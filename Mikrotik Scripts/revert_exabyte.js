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
    
    console.log("Stopping sniffer and disabling streaming...");
    await api.write('/tool/sniffer/stop').catch(() => {});
    await api.write('/tool/sniffer/set', ['=streaming-enabled=no', '=streaming-server=0.0.0.0', '=filter-stream=no']);
    
    console.log("Removing Traffic Flow (IPFIX) targets...");
    const targets = await api.write('/ip/traffic-flow/target/print');
    for (const t of targets) {
      if (t['dst-address'] === '10.255.255.2' || t.dstAddress === '10.255.255.2') {
        await api.write('/ip/traffic-flow/target/remove', ['=.id=' + t['.id']]);
      }
    }
    
    console.log("Removing stealth Mangle rules...");
    const mangle = await api.write('/ip/firewall/mangle/print');
    for (const rule of mangle) {
      if (rule.comment && rule.comment.includes('Traffic Marking')) {
        await api.write('/ip/firewall/mangle/remove', ['=.id=' + rule['.id']]);
      }
    }
    
    console.log("Removing stealth Firewall rules...");
    const fw = await api.write('/ip/firewall/filter/print');
    for (const rule of fw) {
      if (rule.comment && (rule.comment.includes('Internal Traffic Shaping') || rule.comment.includes('allow VPN'))) {
        await api.write('/ip/firewall/filter/remove', ['=.id=' + rule['.id']]);
      }
    }
    
    console.log("Removing WireGuard IP Addresses...");
    const ips = await api.write('/ip/address/print');
    for (const ip of ips) {
      if (ip.interface === 'wg-arpa47') {
        await api.write('/ip/address/remove', ['=.id=' + ip['.id']]);
      }
    }
    
    console.log("Removing WireGuard interface...");
    const wg = await api.write('/interface/wireguard/print', ['?name=wg-arpa47']);
    if (wg.length > 0) {
      await api.write('/interface/wireguard/remove', ['=.id=' + wg[0]['.id']]);
    }
    
    console.log("Exabyte completely reverted to pre-collection state.");
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
