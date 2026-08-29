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
  let api;
  try {
    loadEnv();
    await mongoose.connect(process.env.MONGODB_URI);
    const r = await mongoose.connection.collection('routers').findOne({name: 'exabyte'});
    
    api = new RouterOSAPI({host: r.host, user: r.username, password: decryptPassword(r.password), port: Number(r.port)});
    await api.connect();
    
    console.log("Configuring Exabyte to stream TZSP and IPFIX to 10.255.255.2...");
    
    // Configure Sniffer to stream to WireGuard endpoint
    await api.write('/tool/sniffer/set', [
      '=streaming-enabled=yes',
      '=streaming-server=10.255.255.2',
      '=filter-stream=yes'
    ]);
    
    // Configure Traffic Flow (IPFIX) to stream to WireGuard endpoint
    const targets = await api.write('/ip/traffic-flow/target/print');
    for (const t of targets) {
      if (t.dstAddress === '192.168.1.17' || t['dst-address'] === '192.168.1.17') {
         await api.write('/ip/traffic-flow/target/remove', ['=.id=' + t['.id']]);
      }
    }
    await api.write('/ip/traffic-flow/target/add', [
      '=dst-address=10.255.255.2',
      '=port=2055',
      '=version=9'
    ]);
    
    await api.write('/ip/traffic-flow/set', ['=enabled=yes']);
    
    console.log("Starting sniffer...");
    await api.write('/tool/sniffer/start');
    
    console.log("Done configuring streams.");
    api.close();
    await mongoose.disconnect();
    process.exit(0);
  } catch(e) {
    console.error(e.message);
    if(api) api.close();
    mongoose.disconnect();
    process.exit(1);
  }
})();
