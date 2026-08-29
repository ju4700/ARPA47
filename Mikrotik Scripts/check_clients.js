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
    console.log("Checking client health...\n");
    
    // 1. Check active PPPoE connections
    const pppActive = await api.write("/ppp/active/print");
    console.log(`Active PPPoE Clients: ${pppActive.length}`);
    
    // 2. Check recent logs for disconnects
    const logs = await api.write("/log/print");
    // Filter the last 10 log entries
    const recentLogs = logs.slice(-10);
    console.log("\nRecent System Logs (Looking for mass disconnects):");
    recentLogs.forEach(log => {
        console.log(`[${log.time}] ${log.topics} - ${log.message}`);
    });

    // 3. Check overall traffic on a main interface (we'll look at the first running interface)
    const interfaces = await api.write("/interface/print", ["?running=true"]);
    if (interfaces.length > 0) {
        const mainIf = interfaces[0];
        console.log(`\nMonitoring traffic on interface: ${mainIf.name}...`);
        const traffic = await api.write("/interface/monitor-traffic", [`=interface=${mainIf.name}`, "=once="]);
        if (traffic.length > 0) {
            const rxMbps = (parseInt(traffic[0]['rx-bits-per-second']) / 1000000).toFixed(2);
            const txMbps = (parseInt(traffic[0]['tx-bits-per-second']) / 1000000).toFixed(2);
            console.log(`Traffic Flowing -> RX: ${rxMbps} Mbps | TX: ${txMbps} Mbps`);
        }
    }

  } catch (e) {
    console.error("Error:", e);
  } finally {
    if (api) await api.close();
    await mongoose.disconnect();
    process.exit(0);
  }
})();
