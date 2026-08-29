const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const mongoose = require('mongoose');
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
  let api;
  try {
    loadEnv();
    if (!process.env.MONGODB_URI) {
        require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
    }
    await mongoose.connect(process.env.MONGODB_URI);
    const router = await mongoose.connection.collection('routers').findOne({ name: 'earth' });
    api = new RouterOSAPI({
      host: router.host,
      user: router.username,
      password: decryptPassword(router.password),
      port: Number(router.port || 8728)
    });
    
    await api.connect();
    
    console.log("=== 1. Active Traffic Flow (NetFlow) Targets ===");
    const targets = await api.write("/ip/traffic-flow/target/print");
    if (targets.length === 0) {
        console.log("No NetFlow targets found.");
    } else {
        targets.forEach(t => console.log(t));
    }
    
    console.log("\n=== 2. Mangle Sniff Rules ===");
    const mangle = await api.write("/ip/firewall/mangle/print");
    const sniffRules = mangle.filter(r => r.action === 'sniff-tzsp' || r.action === 'sniff-pc');
    if (sniffRules.length === 0) {
        console.log("No TZSP Mangle rules found.");
    } else {
        sniffRules.forEach(r => console.log(r));
    }
    
    console.log("\n=== 3. Global Sniffer Status ===");
    const sniffer = await api.write("/tool/sniffer/print");
    console.log(sniffer[0]);
    
    console.log("\n=== 4. CPU Profiling (What is using 52%?) ===");
    // Run profiler for 2 seconds to see what subsystem is using CPU
    const profile = await api.write("/system/profile/print", ["=duration=2"]);
    profile.forEach(p => console.log(`${p.name.padEnd(20)}: ${p.usage}%`));

  } catch (e) {
    console.error("Error:", e);
  } finally {
    if (api) await api.close();
    await mongoose.disconnect();
    process.exit(0);
  }
})();
