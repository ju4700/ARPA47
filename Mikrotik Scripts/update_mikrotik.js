const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { RouterOSAPI } = require('node-routeros');

function loadEnv() {
  const p = path.join(process.cwd(), '..', '.env');
  if (!fs.existsSync(p)) return;
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

function decryptPassword(cipheredText) {
  if (!cipheredText) return '';
  try {
    const keyStr = process.env.ENCRYPTION_KEY;
    const data = Buffer.from(cipheredText, 'base64');
    const salt = data.subarray(0, 16);
    const iv = data.subarray(16, 28);
    const tag = data.subarray(28, 44);
    const encrypted = data.subarray(44);
    const key = crypto.pbkdf2Sync(keyStr, salt, 10000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
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
    
    console.log('Stopping sniffer...');
    await api.write('/tool/sniffer/stop');
    
    console.log('Updating sniffer streaming server...');
    await api.write('/tool/sniffer/set', [
        '=streaming-server=103.148.176.43'
    ]);
    
    console.log('Starting sniffer...');
    await api.write('/tool/sniffer/start');
    
    console.log('Updating IPFIX target...');
    const targets = await api.write('/ip/traffic-flow/target/print');
    for (const t of targets) {
       if (t['dst-address'] === '192.168.20.136' || t['dst-address'] === '103.148.176.43') {
           await api.write('/ip/traffic-flow/target/set', [
               '=.id=' + t['.id'],
               '=dst-address=103.148.176.43'
           ]);
       }
    }
    
    console.log('Updating Remote Syslog target...');
    const actions = await api.write('/system/logging/action/print');
    for (const a of actions) {
        if (a.name === 'remote') {
            await api.write('/system/logging/action/set', [
                '=.id=' + a['.id'],
                '=remote=103.148.176.43'
            ]);
        }
    }
    
    console.log('Done.');
    api.close();
    process.exit(0);
  } catch(e) {
    console.error(e);
    process.exit(1);
  }
})();
