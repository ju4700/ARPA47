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
      const val = line.slice(idx + 1).trim();
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
    
    console.log("\n=== ISP IP POOLS ===");
    const pools = await api.write("/ip/pool/print");
    pools.forEach(p => console.log(`${p.name}: ${p.ranges}`));

    console.log("\n=== FIREWALL NAT (To see existing port forwards) ===");
    const nat = await api.write("/ip/firewall/nat/print");
    nat.slice(0, 15).forEach(n => console.log(`${n.chain} ${n.action} - Dst: ${n['dst-address'] || 'any'} Port: ${n['dst-port'] || 'any'}`));

    await api.close();
    await mongoose.disconnect();
  } catch (err) {
    console.error(err);
  }
})();
