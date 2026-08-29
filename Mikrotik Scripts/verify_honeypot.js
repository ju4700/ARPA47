// scripts/verify_honeypot_live.js

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { RouterOSAPI } = require('node-routeros');

const HONEYPOT_IP = '103.148.176.62';

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
      const val = line.slice(idx + 1).trim();

      if (!process.env[key]) process.env[key] = val;
    }
  }
}

function decryptPassword(cipheredText) {
  const keyStr = process.env.ENCRYPTION_KEY;

  const data = Buffer.from(cipheredText, 'base64');

  const salt = data.subarray(0, SALT_LENGTH);
  const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = data.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + TAG_LENGTH
  );

  const encrypted = data.subarray(
    SALT_LENGTH + IV_LENGTH + TAG_LENGTH
  );

  const key = crypto.pbkdf2Sync(
    keyStr,
    salt,
    ITERATIONS,
    KEY_LENGTH,
    'sha256'
  );

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    iv
  );

  decipher.setAuthTag(tag);

  return decipher.update(encrypted) + decipher.final('utf8');
}

(async () => {
  try {
    loadEnv();

    const mongoose = require('mongoose');

    await mongoose.connect(process.env.MONGODB_URI);

    const router = await mongoose.connection
      .collection('routers')
      .findOne({ name: 'earth' });

    const api = new RouterOSAPI({
      host: router.host,
      user: router.username,
      password: decryptPassword(router.password),
      port: Number(router.port || 8728)
    });

    await api.connect();

    console.log("\n=== HONEYPOT VERIFICATION ===\n");

        const addresses =
            await api.write("/ip/address/print");

        const hp = addresses.find(
            x => (x.address || "").startsWith(HONEYPOT_IP)
        );

        if (hp) {
            console.log("✅ Honeypot IP exists");
            console.log("   " + hp.address);
        } else {
            console.log("❌ Honeypot IP NOT found");
        }

        const filters =
            await api.write("/ip/firewall/filter/print");

        const honeypotRules = filters.filter(r =>
            (r.comment || "").toLowerCase().includes("honeypot")
        );

        console.log(
            `\nFound ${honeypotRules.length} honeypot rules\n`
        );

        honeypotRules.forEach(r => {
            console.log(
                `Chain=${r.chain} Action=${r.action} Packets=${r.packets || 0} Bytes=${r.bytes || 0}`
            );
        });

        const logRule = honeypotRules.find(
            r => r.action === "log"
        );

        const before =
            Number(logRule?.packets || 0);

        console.log(
            `\nCurrent honeypot packet counter: ${before}`
        );

        try {
            await api.write("/log/warning", [
                "=message=HONEYPOT-WINDOWS-TEST"
            ]);

            console.log(
                "✅ Generated MikroTik test log"
            );
        } catch {
            console.log(
                "⚠ Unable to generate test log"
            );
        }

        console.log("\n================================");
        console.log("NOW GENERATE TRAFFIC");
        console.log("================================\n");

        console.log(`curl http://${HONEYPOT_IP}`);
        console.log(`nc -vz ${HONEYPOT_IP} 22`);
        console.log(`telnet ${HONEYPOT_IP} 22`);

        console.log("\nWaiting 30 seconds...\n");


        await api.close();

        await new Promise(r => setTimeout(r, 30000));

        const api2 = new RouterOSAPI({
            host: router.host,
            user: router.username,
            password: decryptPassword(router.password),
            port: Number(router.port || 8728)
        });
        await api2.connect();

        const afterFilters = await api2.write("/ip/firewall/filter/print");
        const afterRule = afterFilters.find(r => (r.comment || "").toLowerCase().includes("honeypot") && r.action === "log");
        const after = Number(afterRule?.packets || 0);

        console.log(`Before: ${before}`);
        console.log(`After : ${after}`);

        if (after > before) {
            console.log(`\n✅ Honeypot triggered (+${after - before} packets)`);
        } else {
            console.log("\n❌ No new honeypot hits detected");
        }

        await api2.close();

    
    await mongoose.disconnect();

    console.log('\nVerification complete');
  } catch (err) {
    console.error(err);
  }
})();