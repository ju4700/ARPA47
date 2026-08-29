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
    
    let report = [];
    
    // Sniffer
    try {
      const sniffer = await api.write('/tool/sniffer/print');
      if (sniffer[0]['streaming-enabled'] === 'true' || sniffer[0]['streaming-enabled'] === true) {
        await api.write('/tool/sniffer/set', ['=streaming-enabled=no', '=streaming-server=0.0.0.0', '=filter-stream=no']);
        report.push("- Disabled packet sniffer streaming.");
      } else {
        report.push("- Packet sniffer streaming is already disabled.");
      }
    } catch(e) { report.push("- Sniffer check failed: " + e.message); }
    
    // Traffic Flow (IPFIX)
    try {
      const targets = await api.write('/ip/traffic-flow/target/print');
      let removedTF = false;
      for (const t of targets) {
        if (t['dst-address'] === '10.255.255.2' || t.dstAddress === '10.255.255.2') {
          await api.write('/ip/traffic-flow/target/remove', ['=.id=' + t['.id']]);
          removedTF = true;
        }
      }
      if (removedTF) report.push("- Removed NetFlow/IPFIX target for 10.255.255.2.");
      else report.push("- NetFlow/IPFIX targets are clean.");
    } catch(e) { report.push("- Traffic flow check failed: " + e.message); }
    
    // Mangle
    try {
      const mangle = await api.write('/ip/firewall/mangle/print');
      let removedMangle = 0;
      for (const rule of mangle) {
        if (rule.comment && rule.comment.includes('Traffic Marking')) {
          await api.write('/ip/firewall/mangle/remove', ['=.id=' + rule['.id']]);
          removedMangle++;
        }
      }
      if (removedMangle > 0) report.push(`- Removed ${removedMangle} stealth Mangle rules.`);
      else report.push("- Firewall Mangle rules are clean.");
    } catch(e) { report.push("- Mangle check failed: " + e.message); }
    
    // Firewall Filter
    try {
      const fw = await api.write('/ip/firewall/filter/print');
      let removedFw = 0;
      for (const rule of fw) {
        if (rule.comment && (rule.comment.includes('Internal Traffic Shaping') || rule.comment.includes('allow VPN'))) {
          await api.write('/ip/firewall/filter/remove', ['=.id=' + rule['.id']]);
          removedFw++;
        }
      }
      if (removedFw > 0) report.push(`- Removed ${removedFw} stealth Firewall filter rules.`);
      else report.push("- Firewall Filter rules are clean.");
    } catch(e) { report.push("- Firewall check failed: " + e.message); }
    
    // IP Addresses
    try {
      const ips = await api.write('/ip/address/print');
      let removedIp = false;
      for (const ip of ips) {
        if (ip.interface === 'wg-arpa47') {
          await api.write('/ip/address/remove', ['=.id=' + ip['.id']]);
          removedIp = true;
        }
      }
      if (removedIp) report.push("- Removed WireGuard IP address (10.255.255.1/30).");
      else report.push("- IP Addresses are clean.");
    } catch(e) { report.push("- IP check failed: " + e.message); }
    
    // WireGuard Interfaces
    try {
      const wg = await api.write('/interface/wireguard/print');
      let removedWg = false;
      for (const w of wg) {
        if (w.name === 'wg-arpa47') {
          await api.write('/interface/wireguard/remove', ['=.id=' + w['.id']]);
          removedWg = true;
        }
      }
      if (removedWg) report.push("- Removed WireGuard interface (wg-arpa47).");
      else report.push("- WireGuard interfaces are clean.");
    } catch(e) { report.push("- Wireguard check failed: " + e.message); }
    
    console.log("\n=== Exabyte Revert Verification Report ===");
    console.log(report.join("\n"));
    
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
