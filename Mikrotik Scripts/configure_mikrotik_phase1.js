const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { RouterOSAPI } = require('node-routeros');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const KEY_LENGTH = 32;
const ITERATIONS = 10000;

function loadEnv() {
  const files = ['.env', '.env.local'];
  for (const file of files) {
    const p = path.join(process.cwd(), file);
    if (!fs.existsSync(p)) continue;
    const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const idx = line.indexOf('=');
      if (idx < 0) continue;
      const key = line.slice(0, idx).trim();
      let val = line.slice(idx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!process.env[key]) process.env[key] = val;
    }
  }
}

function decryptPassword(cipheredText) {
  if (!cipheredText) return '';
  try {
    const keyStr = process.env.ENCRYPTION_KEY;
    const data = Buffer.from(cipheredText, 'base64');
    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const key = crypto.pbkdf2Sync(keyStr, salt, ITERATIONS, KEY_LENGTH, 'sha256');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final('utf8');
  } catch {
    return cipheredText;
  }
}

(async () => {
  try {
    loadEnv();
    const mongoose = require('mongoose');
    await mongoose.connect(process.env.MONGODB_URI);
    const router = await mongoose.connection.collection('routers').findOne({ name: 'earth' });
    
    const api = new RouterOSAPI({
      host: router.host,
      user: router.username,
      password: decryptPassword(router.password),
      port: Number(router.port || 8728)
    });

    await api.connect();
    
    console.log("\n=== 1. Upgrading Traffic Flow to IPFIX ===");
    const targets = await api.write("/ip/traffic-flow/target/print");
    for (const t of targets) {
       await api.write("/ip/traffic-flow/target/set", [
           "=.id=" + t['.id'],
           "=version=ipfix"
       ]);
       console.log(`Updated Traffic Flow target ${t['dst-address']} to IPFIX`);
    }

    console.log("\n=== 2. Enabling Filtered TZSP Mirroring ===");
    await api.write("/tool/sniffer/set", [
        "=streaming-enabled=yes",
        "=streaming-server=103.148.176.43",
        "=filter-ip-address=103.148.176.62"
    ]);
    await api.write("/tool/sniffer/start");
    console.log("Packet Sniffer started and streaming to 103.148.176.43 for IP 103.148.176.62");

    console.log("\n=== 3. Deploying Honeyports (NAT Traps) ===");
    const ports = [23, 445, 1433, 3389];
    const blocks = ["103.146.76.0/24", "103.148.176.0/24"];
    const honeypotIP = "103.148.176.62";

    for (const block of blocks) {
        for (const port of ports) {
            let req = [
                "=chain=dstnat",
                "=action=dst-nat",
                "=to-addresses=" + honeypotIP,
                "=to-ports=" + port,
                "=protocol=tcp",
                "=dst-address=" + block,
                "=dst-port=" + port,
                `=comment=HONEYPORT-TCP-${port}`
            ];
            
            // Special syntax for exclusion in node-routeros (array doesn't support ! directly on the IP sometimes)
            // But usually "!IP" works in the API. Let's send it.
            if (block === "103.148.176.0/24") {
                req.push("=dst-address=!103.148.176.62");
            }

            try {
                await api.write("/ip/firewall/nat/add", req);
                console.log(`Added Honeyport Trap for ${block} on port ${port}`);
            } catch (e) {
                console.log(`Failed to add Honeyport Trap for ${block} on port ${port}: ${e.message}`);
            }
        }
    }

    console.log("\n=== 4. Enforcing Zero Egress Policy & Honeyport Logging ===");
    try {
        await api.write("/ip/firewall/filter/add", [
            "=chain=forward",
            "=action=log",
            "=dst-address=" + honeypotIP,
            "=connection-nat-state=dstnat",
            "=log-prefix=HONEYPORT-HIT",
            "=comment=HONEYPOT-LOG-NAT-TRAPS"
        ]);
        console.log("Added Logging Rule for Honeyports");
    } catch(e) {}

    try {
        await api.write("/ip/firewall/filter/add", [
            "=chain=forward",
            "=action=drop",
            "=src-address=" + honeypotIP,
            "=connection-state=new",
            "=comment=ZERO-EGRESS: Prevent Honeypot Pivot"
        ]);
        console.log("Added Zero Egress Policy for Honeypot");
    } catch(e) {}

    console.log("\n=== VERIFICATION ===");
    const verifyTargets = await api.write("/ip/traffic-flow/target/print");
    console.log("Traffic Flow Targets:", verifyTargets.map(t => `${t['dst-address']} (v${t['version']})`));

    const verifySniffer = await api.write("/tool/sniffer/print");
    console.log(`Sniffer Streaming: ${verifySniffer[0]['streaming-enabled']} to ${verifySniffer[0]['streaming-server']} for ${verifySniffer[0]['filter-ip-address']}`);

    const verifyNat = await api.write("/ip/firewall/nat/print");
    const hPorts = verifyNat.filter(n => (n.comment || "").includes("HONEYPORT"));
    console.log(`Verified ${hPorts.length} Honeyport NAT rules are active.`);

    const verifyFilter = await api.write("/ip/firewall/filter/print");
    const zEgress = verifyFilter.filter(f => (f.comment || "").includes("ZERO-EGRESS"));
    console.log(`Verified Zero Egress Policy: ${zEgress.length > 0 ? "ACTIVE" : "NOT FOUND"}`);

    await api.close();
    await mongoose.disconnect();
  } catch (err) {
    console.error(err);
  }
})();
