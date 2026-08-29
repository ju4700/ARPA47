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
    // Ensure we use the .env from the parent directory if needed
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
    
    console.log("Connected to MikroTik! Checking existing schedulers...");

    // Remove existing scheduler if it exists to avoid duplicates
    try {
        const existing = await api.write("/system/scheduler/print", ["?name=Auto-Start-TZSP"]);
        for (const sched of existing) {
            await api.write("/system/scheduler/remove", ["=.id=" + sched['.id']]);
            console.log(" -> Removed old scheduler");
        }
    } catch(e) {}

    console.log("Injecting Auto-Startup Scheduler...");
    
    await api.write("/system/scheduler/add", [
        "=name=Auto-Start-TZSP",
        "=start-time=startup",
        "=on-event=/tool sniffer set filter-ip-address=103.148.176.62/32 filter-stream=yes filter-direction=any streaming-enabled=yes streaming-server=103.148.176.43\r\n/tool sniffer start",
        "=policy=reboot,read,write,policy,test,sniff,sensitive"
    ]);

    console.log("\n[SUCCESS] MikroTik will now permanently auto-start the sniffer on reboot!");

    api.close();
    process.exit(0);
  } catch (e) {
    console.error("Error connecting or updating Mikrotik:", e);
    process.exit(1);
  }
})();
