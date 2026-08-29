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
    const p = path.join(process.cwd(), '..', file);
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
    if (!process.env.MONGODB_URI) {
        require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
    }
    
    await mongoose.connect(process.env.MONGODB_URI);
    const router = await mongoose.connection.collection('routers').findOne({ name: 'earth' });
    
    const api = new RouterOSAPI({
      host: router.host,
      user: router.username,
      password: decryptPassword(router.password),
      port: Number(router.port || 8728)
    });

    await api.connect();
    
    console.log("Connected to MikroTik. Verifying configuration deeply...");

    const sniffer = await api.write("/tool/sniffer/print");
    console.log("\n--- PACKET SNIFFER CONFIG ---");
    console.log(JSON.stringify(sniffer, null, 2));

    const tf = await api.write("/ip/traffic-flow/target/print");
    console.log("\n--- TRAFFIC FLOW (IPFIX) CONFIG ---");
    console.log(JSON.stringify(tf, null, 2));
    
    const rules = await api.write("/ip/firewall/filter/print");
    const hpRules = rules.filter(r => (r.comment || '').includes("HONEYP"));
    console.log("\n--- HONEYPOT FIREWALL RULES ---");
    hpRules.forEach(r => console.log(`Chain: ${r.chain}, Action: ${r.action}, Dst: ${r['dst-address'] || 'any'}, Comment: ${r.comment}`));

    api.close();
    process.exit(0);
  } catch (e) {
    console.error("Error:", e);
    process.exit(1);
  }
})();
