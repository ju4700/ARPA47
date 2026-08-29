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

const LINUX_PUB_KEY = "SmzzOsl5Tvbv3PnMMTfRUaaa2A8xedlOoF7WJa5wLHg=";

(async () => {
  let api;
  try {
    loadEnv();
    await mongoose.connect(process.env.MONGODB_URI);
    const r = await mongoose.connection.collection('routers').findOne({name: 'exabyte'});
    if (!r) throw new Error("Router not found");
    
    api = new RouterOSAPI({host: r.host, user: r.username, password: decryptPassword(r.password), port: Number(r.port)});
    await api.connect();
    
    console.log("Setting up WireGuard Interface...");
    await api.write('/interface/wireguard/add', [
      '=name=wg-arpa47',
      '=listen-port=51820',
      '=mtu=1420'
    ]).catch(e => { if(!e.message.includes("already")) throw e; });
    
    console.log("Adding IP Address to WireGuard...");
    await api.write('/ip/address/add', [
      '=address=10.255.255.1/30',
      '=interface=wg-arpa47'
    ]).catch(e => { if(!e.message.includes("already")) throw e; });
    
    console.log("Adding WireGuard Peer...");
    await api.write('/interface/wireguard/peers/add', [
      '=interface=wg-arpa47',
      '=public-key=' + LINUX_PUB_KEY,
      '=allowed-address=10.255.255.2/32'
    ]).catch(e => { if(!e.message.includes("already")) throw e; });
    
    console.log("Adding Firewall Rule for WireGuard...");
    await api.write('/ip/firewall/filter/add', [
      '=chain=input',
      '=action=accept',
      '=protocol=udp',
      '=dst-port=51820',
      '=place-before=0',
      '=comment=Allow WireGuard for ARPA47'
    ]);
    
    console.log("Configuring Traffic Flow (IPFIX)...");
    await api.write('/ip/traffic-flow/set', [
      '=enabled=yes',
      '=interfaces=all',
      '=cache-entries=4k',
      '=active-flow-timeout=30m',
      '=inactive-flow-timeout=15s'
    ]);
    
    await api.write('/ip/traffic-flow/target/add', [
      '=dst-address=10.255.255.2',
      '=port=2055',
      '=version=9'
    ]).catch(e => { if(!e.message.includes("already")) throw e; });
    
    console.log("Adding TZSP Sniffer Rules...");
    await api.write('/ip/firewall/mangle/add', [
      '=chain=forward',
      '=src-address=10.50.1.0/24',
      '=action=sniff-tzsp',
      '=sniff-target=10.255.255.2',
      '=sniff-target-port=37008',
      '=place-before=0',
      '=comment=ARPA47 TZSP Upload'
    ]);
    
    await api.write('/ip/firewall/mangle/add', [
      '=chain=forward',
      '=dst-address=10.50.1.0/24',
      '=action=sniff-tzsp',
      '=sniff-target=10.255.255.2',
      '=sniff-target-port=37008',
      '=place-before=1',
      '=comment=ARPA47 TZSP Download'
    ]);
    
    console.log("Adding FastTrack Bypass Rules...");
    await api.write('/ip/firewall/filter/add', [
      '=chain=forward',
      '=src-address=10.50.1.0/24',
      '=action=accept',
      '=place-before=0',
      '=comment=ARPA47 FastTrack Bypass Upload'
    ]);
    
    await api.write('/ip/firewall/filter/add', [
      '=chain=forward',
      '=dst-address=10.50.1.0/24',
      '=action=accept',
      '=place-before=1',
      '=comment=ARPA47 FastTrack Bypass Download'
    ]);

    console.log("Setup complete on exabyte!");
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
