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
    
    console.log("Updating firewall and mangle comments to be stealthy...");
    
    // Find and update firewall rules
    const fw = await api.write('/ip/firewall/filter/print');
    for (const rule of fw) {
      if (rule.comment && rule.comment.includes('ARPA47')) {
        let newComment = "";
        if (rule.comment.includes('WireGuard')) newComment = "allow VPN";
        else if (rule.comment.includes('Upload')) newComment = "Internal Traffic Shaping (Upload)";
        else if (rule.comment.includes('Download')) newComment = "Internal Traffic Shaping (Download)";
        
        if (newComment) {
          await api.write('/ip/firewall/filter/set', ['=.id=' + rule['.id'], '=comment=' + newComment]);
          console.log(`Updated firewall comment: ${newComment}`);
        }
      }
    }

    // Find and update mangle rules
    const mangle = await api.write('/ip/firewall/mangle/print');
    for (const rule of mangle) {
      if (rule.comment && rule.comment.includes('ARPA47')) {
        let newComment = "";
        if (rule.comment.includes('Upload')) newComment = "Traffic Marking (Upload)";
        else if (rule.comment.includes('Download')) newComment = "Traffic Marking (Download)";
        
        if (newComment) {
          await api.write('/ip/firewall/mangle/set', ['=.id=' + rule['.id'], '=comment=' + newComment]);
          console.log(`Updated mangle comment: ${newComment}`);
        }
      }
    }

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
