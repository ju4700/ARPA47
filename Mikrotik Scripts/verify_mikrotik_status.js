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
    
    console.log("\n=== MIKROTIK VERIFICATION REPORT ===");

    console.log("\n[1] IPFIX Export Status:");
    const targets = await api.write("/ip/traffic-flow/target/print");
    targets.forEach(t => console.log(`  -> Target: ${t['dst-address']} | Version: ${t['version']} | Enabled: ${t['disabled'] === 'false' ? 'YES' : 'NO'}`));

    console.log("\n[2] TZSP Sniffer Status:");
    const sniffer = await api.write("/tool/sniffer/print");
    if (sniffer.length > 0) {
        console.log(`  -> Streaming: ${sniffer[0]['streaming-enabled']}`);
        console.log(`  -> Server: ${sniffer[0]['streaming-server']}`);
        console.log(`  -> Filter IP: ${sniffer[0]['filter-ip-address']}`);
    }

    console.log("\n[3] Honeyport NAT Traps:");
    const nat = await api.write("/ip/firewall/nat/print");
    const honeyports = nat.filter(n => (n.comment || "").includes("HONEYPORT"));
    if (honeyports.length > 0) {
        console.log(`  -> SUCCESS: Found ${honeyports.length} active Honeyport NAT rules!`);
        honeyports.forEach(h => console.log(`     Rule: Redirect ${h['dst-address']} port ${h['dst-port']} -> Honeypot port ${h['to-ports']}`));
    } else {
        console.log(`  -> ERROR: No Honeyport NAT rules found.`);
    }

    console.log("\n[4] Honeypot Security Policies:");
    const filter = await api.write("/ip/firewall/filter/print");
    
    const logging = filter.filter(f => (f.comment || "").includes("HONEYPOT-LOG-NAT-TRAPS"));
    console.log(`  -> Logging Rule: ${logging.length > 0 ? 'ACTIVE' : 'MISSING'}`);
    
    const egress = filter.filter(f => (f.comment || "").includes("ZERO-EGRESS"));
    console.log(`  -> Zero Egress Policy: ${egress.length > 0 ? 'ACTIVE' : 'MISSING'} (Safeguards your clients)`);

    await api.close();
    await mongoose.disconnect();
    
    console.log("\n=== VERIFICATION COMPLETE ===");
  } catch (err) {
    console.error("Verification failed:", err);
  }
})();
