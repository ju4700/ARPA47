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
    
    console.log("=== Investigating Global Sniffer ===");
    
    console.log("\n1. Looking for 192.168.20.136 in Active Connections...");
    const conns = await api.write("/ip/firewall/connection/print");
    const targetConns = conns.filter(c => c['dst-address'] && c['dst-address'].includes('192.168.20.136'));
    if (targetConns.length > 0) {
        console.log(`Found ${targetConns.length} active connection(s) streaming to 192.168.20.136.`);
        console.log(targetConns[0]);
    } else {
        console.log("No active firewall connections to 192.168.20.136 right now.");
    }
    
    console.log("\n2. ARP Table for 192.168.20.136...");
    const arpAll = await api.write("/ip/arp/print");
    const arp = arpAll.filter(a => a.address === '192.168.20.136');
    if (arp.length > 0) {
        console.log(`MAC Address: ${arp[0]['mac-address']} on Interface: ${arp[0]['interface']}`);
    } else {
        console.log("IP not in ARP table (likely routed through another gateway).");
    }

    console.log("\n3. Route to 192.168.20.136...");
    const routeAll = await api.write("/ip/route/print");
    const route = routeAll.filter(r => r['dst-address'] && r['dst-address'].includes('192.168.20.136'));
    console.log(route.length > 0 ? route[0] : "No specific route found.");

    console.log("\n4. Active PPPoE/DHCP Client with 103.148.176.62...");
    const pppAll = await api.write("/ppp/active/print");
    const ppp = pppAll.filter(p => p.address === '103.148.176.62');
    if (ppp.length > 0) {
        console.log(`Target IP 103.148.176.62 belongs to active PPPoE client: ${ppp[0]['name']} (Uptime: ${ppp[0]['uptime']})`);
    } else {
        const dhcpAll = await api.write("/ip/dhcp-server/lease/print");
        const dhcp = dhcpAll.filter(d => d.address === '103.148.176.62');
        if (dhcp.length > 0) {
            console.log(`Target IP 103.148.176.62 belongs to DHCP lease with MAC: ${dhcp[0]['mac-address']}`);
        } else {
            console.log("Target IP 103.148.176.62 not found in active PPPoE or DHCP leases.");
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
