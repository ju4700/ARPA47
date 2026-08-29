const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { RouterOSAPI } = require("node-routeros");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const KEY_LENGTH = 32;
// Note: Iterations kept at 10000 because the existing database was encrypted at 10000. 
// Changing this without a DB migration would break authentication.
const ITERATIONS = 10000;

function loadEnv() {
    const files = [".env", ".env.local"];
    for (const file of files) {
        const p = path.join(process.cwd(), "..", file);
        if (!fs.existsSync(p)) continue;
        const lines = fs.readFileSync(p, "utf8").split(/\r?\n/);
        for (const line of lines) {
            const idx = line.indexOf("=");
            if (idx < 0) continue;
            const key = line.slice(0, idx).trim();
            let val = line.slice(idx + 1).trim();
            if (
                (val.startsWith('"') && val.endsWith('"')) ||
                (val.startsWith("'") && val.endsWith("'"))
            ) {
                val = val.slice(1, -1);
            }
            if (!process.env[key]) process.env[key] = val;
        }
    }
}

function decryptPassword(cipheredText) {
    if (!cipheredText) return "";
    try {
        const keyStr = process.env.ENCRYPTION_KEY;
        const data = Buffer.from(cipheredText, "base64");
        const salt = data.subarray(0, SALT_LENGTH);
        const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const tag = data.subarray(
            SALT_LENGTH + IV_LENGTH,
            SALT_LENGTH + IV_LENGTH + TAG_LENGTH,
        );
        const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
        const key = crypto.pbkdf2Sync(
            keyStr,
            salt,
            ITERATIONS,
            KEY_LENGTH,
            "sha256",
        );
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);
        return decipher.update(encrypted) + decipher.final("utf8");
    } catch (e) {
        // FIXED: Loudly throw instead of silently returning ciphertext
        throw new Error("FATAL: Failed to decrypt router password. Check ENCRYPTION_KEY or database integrity. Details: " + e.message);
    }
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
    let api;
    let injectedMangleIds = [];
    try {
        loadEnv();
        if (!process.env.MONGODB_URI) {
            require("dotenv").config({
                path: path.join(__dirname, "..", ".env"),
            });
        }

        await mongoose.connect(process.env.MONGODB_URI);
        const router = await mongoose.connection
            .collection("routers")
            .findOne({ name: "earth" });
            
        // FIXED: Null check for router
        if (!router) {
            throw new Error("FATAL: Router 'earth' not found in database.");
        }

        api = new RouterOSAPI({
            host: router.host,
            user: router.username,
            password: decryptPassword(router.password),
            port: Number(router.port || 8728),
        });

        await api.connect();
        console.log("Connected to MikroTik RouterOS...");

        // CONFIGURATION VARIABLES
        const TARGET_PUBLIC_IP = "103.148.176.43";
        const TARGET_SUBNET = "10.60.1.0/24"; 
        
        // Retaining STEALTH mode comments
        const COMMENT_UP = "System: QoS VoIP Latency Marker (Up)";
        const COMMENT_DOWN = "System: QoS VoIP Latency Marker (Down)";

        // 1. Reset Global Sniffer
        console.log("Stopping and resetting global sniffer...");
        await api.write("/tool/sniffer/stop");
        await api.write("/tool/sniffer/set", [
            "=streaming-enabled=no",
            "=filter-ip-address=",
            "=filter-direction=any",
        ]);

        // 2. Clear old IPFIX targets (FIXED: SURGICAL DELETION ONLY)
        console.log(`Clearing existing Traffic Flow targets pointing to ${TARGET_PUBLIC_IP}...`);
        const targets = await api.write("/ip/traffic-flow/target/print");
        for (const t of targets) {
            if (t[".id"] && t["dst-address"] && t["dst-address"].includes(TARGET_PUBLIC_IP)) {
                console.log(`Removing target ${t['.id']}`);
                await api.write("/ip/traffic-flow/target/remove", [
                    `=.id=${t[".id"]}`,
                ]);
            }
        }

        // 3. Configure Macroscopic IPFIX (All Interfaces)
        console.log(`Setting up IPFIX to ${TARGET_PUBLIC_IP}:2055...`);
        let injectedIpfixId = null;
        const ipfixRes = await api.write("/ip/traffic-flow/target/add", [
            `=dst-address=${TARGET_PUBLIC_IP}`,
            "=port=2055",
            "=version=ipfix",
        ]);
        if (ipfixRes.length > 0 && ipfixRes[0].ret) injectedIpfixId = ipfixRes[0].ret;
        
        await api.write("/ip/traffic-flow/set", [
            "=enabled=yes",
            "=interfaces=all",
            "=active-flow-timeout=1m",
            "=inactive-flow-timeout=15s",
        ]);

        // 4. Clean up old Mangle rules
        console.log("Cleaning up old Mangle sniffing rules...");
        const mangleRules = await api.write("/ip/firewall/mangle/print");
        for (const r of mangleRules) {
            if (r.comment === COMMENT_UP || r.comment === COMMENT_DOWN || r.comment === "System: QoS VoIP Latency Marker") {
                await api.write("/ip/firewall/mangle/remove", [
                    `=.id=${r[".id"]}`,
                ]);
            }
        }

        // 5. Inject BIDIRECTIONAL Mangle Rules
        console.log(`Injecting Bidirectional TZSP Sniff rules for ${TARGET_SUBNET}...`);
        
        // Upload (Client -> WAN)
        const upRes = await api.write("/ip/firewall/mangle/add", [
            "=chain=forward",
            `=src-address=${TARGET_SUBNET}`,
            "=action=sniff-tzsp",
            `=sniff-target=${TARGET_PUBLIC_IP}`,
            "=sniff-target-port=37008",
            `=comment=${COMMENT_UP}`,
        ]);
        if (upRes.length > 0 && upRes[0].ret) injectedMangleIds.push(upRes[0].ret);

        // Download (WAN -> Client)
        const downRes = await api.write("/ip/firewall/mangle/add", [
            "=chain=forward",
            `=dst-address=${TARGET_SUBNET}`,
            "=action=sniff-tzsp",
            `=sniff-target=${TARGET_PUBLIC_IP}`,
            "=sniff-target-port=37008",
            `=comment=${COMMENT_DOWN}`,
        ]);
        if (downRes.length > 0 && downRes[0].ret) injectedMangleIds.push(downRes[0].ret);

        console.log("\nSetup Complete: Bidirectional TZSP + IPFIX active.");
        
        // 6. CPU Circuit Breaker (Safety Check)
        console.log("\n[SAFETY] Monitoring CPU load for 10 seconds...");
        await sleep(10000); // Wait for traffic to spool up
        const resources = await api.write("/system/resource/print");
        if (resources && resources.length > 0) {
            const cpuLoad = parseInt(resources[0]["cpu-load"]);
            console.log(`Current MikroTik CPU Load: ${cpuLoad}%`);
            
            if (cpuLoad > 85) {
                console.error("🚨 CRITICAL: CPU load exceeded 85%! Initiating emergency rollback to protect clients...");
                for (const id of injectedMangleIds) {
                    await api.write("/ip/firewall/mangle/remove", [`=.id=${id}`]);
                }
                if (injectedIpfixId) {
                    await api.write("/ip/traffic-flow/target/remove", [`=.id=${injectedIpfixId}`]);
                }
                throw new Error("Emergency Rollback: Mangle rules and IPFIX deleted due to excessive CPU load.");
            } else {
                console.log("✅ CPU is healthy. The pipeline is running safely.");
            }
        }

    } catch (e) {
        console.error("Error:", e.message);
    } finally {
        if (api) await api.close();
        await mongoose.disconnect();
        process.exit(0);
    }
})();
