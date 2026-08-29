const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function loadEnv() {
  const p = path.join(process.cwd(), '..', '.env');
  if (!fs.existsSync(p)) return;
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
    const r = await mongoose.connection.collection('routers').findOne({name: 'earth'});
    const password = decryptPassword(r.password);
    
    const scriptContent = `const { RouterOSAPI } = require('node-routeros');

(async () => {
  let api;
  try {
    // Hardcoded credentials for earth
    const host = '${r.host}';
    const user = '${r.username}';
    const password = '${password}';
    const port = ${r.port};

    console.log(\`Connecting to Earth at \${host}:\${port} as \${user}...\`);
    
    api = new RouterOSAPI({host, user, password, port});
    await api.connect();
    
    console.log('Connected! Checking FastTrack rules on Earth...');
    
    const fw = await api.write('/ip/firewall/filter/print');
    for (const rule of fw) {
      if (rule.action === 'fasttrack-connection') {
        if (rule.disabled === 'true' || rule.disabled === true) {
          console.log(\`Enabling FastTrack rule ID \${rule['.id']}...\`);
          await api.write('/ip/firewall/filter/enable', ['=.id=' + rule['.id']]);
        }
      }
    }
    
    console.log("Ensuring FastTrack bypass rules for ARPA47 exist...");
    await api.write('/ip/firewall/filter/add', [
        '=chain=forward',
        '=src-address=10.60.1.0/24',
        '=action=accept',
        '=place-before=0',
        '=comment=Internal Traffic Shaping (Upload)'
    ]).catch(() => console.log("Upload rule might already exist"));
    
    await api.write('/ip/firewall/filter/add', [
        '=chain=forward',
        '=dst-address=10.60.1.0/24',
        '=action=accept',
        '=place-before=1',
        '=comment=Internal Traffic Shaping (Download)'
    ]).catch(() => console.log("Download rule might already exist"));
    
    console.log("Successfully fixed FastTrack and added bypass on Earth.");
    api.close();
    process.exit(0);
  } catch(e) {
    console.error(e.message);
    if(api) api.close();
    process.exit(1);
  }
})();
`;
    
    fs.writeFileSync('cpanel_fix_earth.js', scriptContent);
    console.log("Successfully generated cpanel_fix_earth.js with hardcoded credentials.");
    
    await mongoose.disconnect();
    process.exit(0);
  } catch(e) {
    console.error(e.message);
    mongoose.disconnect();
    process.exit(1);
  }
})();
