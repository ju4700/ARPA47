const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const { RouterOSAPI } = require('node-routeros');
const crypto = require('crypto');

function loadEnv() {
  const p = path.join(process.cwd(), '..', '.env');
  const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf('=');
    if (idx < 0) continue;
    process.env[line.slice(0, idx).trim()] = line.slice(idx + 1).replace(/["']/g, '').trim();
  }
}

function decryptPassword(cipheredText) {
  if (!cipheredText) return '';
  try {
    const data = Buffer.from(cipheredText, 'base64');
    const salt = data.subarray(0, 16);
    const iv = data.subarray(16, 28);
    const tag = data.subarray(28, 44);
    const encrypted = data.subarray(44);
    const key = crypto.pbkdf2Sync(process.env.ENCRYPTION_KEY, salt, 10000, 32, 'sha256');
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
    await mongoose.connect(process.env.MONGODB_URI);
    const r = await mongoose.connection.collection('routers').findOne({name: 'exabyte'});
    if (!r) throw new Error("Router not found");
    
    console.log(`Connecting to ${r.host}:${r.port} as ${r.username}...`);
    const api = new RouterOSAPI({host: r.host, user: r.username, password: decryptPassword(r.password), port: Number(r.port)});
    await api.connect();
    
    console.log('Connected! Adding FastTrack bypass rules...');

    try {
        await api.write('/ip/firewall/filter/add', [
            '=chain=forward',
            '=src-address=10.60.1.0/24',
            '=action=accept',
            '=place-before=0',
            '=comment=Internal Traffic Shaping (Upload)'
        ]);
        console.log('Added Upload rule.');

        await api.write('/ip/firewall/filter/add', [
            '=chain=forward',
            '=dst-address=10.60.1.0/24',
            '=action=accept',
            '=place-before=1',
            '=comment=Internal Traffic Shaping (Download)'
        ]);
        console.log('Added Download rule.');

    } catch (e) {
        console.error('Error adding rules:', e);
    }
    
    api.close();
    await mongoose.disconnect();
    process.exit(0);
  } catch(e) {
    console.error(e.message);
    process.exit(1);
  }
})();
