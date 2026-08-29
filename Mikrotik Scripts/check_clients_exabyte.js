const mongoose = require('mongoose');
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
  let api;
  try {
    loadEnv();
    await mongoose.connect(process.env.MONGODB_URI);
    const router = await mongoose.connection.collection('routers').findOne({ name: 'exabyte' });
    api = new RouterOSAPI({
      host: router.host,
      user: router.username,
      password: decryptPassword(router.password),
      port: Number(router.port || 8728),
      timeout: 30
    });
    
    // Listen for error events to prevent crash
    api.on('error', (err) => {
      console.error("API Error:", err.message);
    });
    
    await api.connect();
    console.log("Checking exabyte health...\n");
    
    // CPU
    const res = await api.write("/system/resource/print");
    if (res.length > 0) {
      console.log(`CPU Load: ${res[0]['cpu-load']}%`);
      console.log(`Free Memory: ${(parseInt(res[0]['free-memory']) / 1024 / 1024).toFixed(2)} MB`);
      console.log(`Uptime: ${res[0]['uptime']}`);
    }
    
    // Logs for disconnects
    const logs = await api.write("/log/print", ["?topics=pppoe,info,account"]);
    const recentLogs = logs.slice(-5);
    console.log("\nRecent PPPoE Logs (Checking for mass disconnects):");
    recentLogs.forEach(log => {
        console.log(`[${log.time}] ${log.topics} - ${log.message}`);
    });

    // Main interface traffic (WAN or similar)
    const interfaces = await api.write("/interface/print", ["?running=true"]);
    if (interfaces.length > 0) {
        // Just pick one interface that has some traffic, e.g. the first one
        const mainIf = interfaces.find(i => i.name.toLowerCase().includes('vlan') || i.name.toLowerCase().includes('ether')) || interfaces[0];
        console.log(`\nMonitoring traffic on interface: ${mainIf.name}...`);
        const traffic = await api.write("/interface/monitor-traffic", [`=interface=${mainIf.name}`, "=once="]);
        if (traffic.length > 0) {
            const rxMbps = (parseInt(traffic[0]['rx-bits-per-second']) / 1000000).toFixed(2);
            const txMbps = (parseInt(traffic[0]['tx-bits-per-second']) / 1000000).toFixed(2);
            console.log(`Traffic Flowing -> RX: ${rxMbps} Mbps | TX: ${txMbps} Mbps`);
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
