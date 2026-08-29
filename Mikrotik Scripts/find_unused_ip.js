// find_unused_ip.js
/**
 * Script to discover unused IP addresses on a MikroTik router.
 * Useful for allocating a free IP for a honeypot or other services.
 *
 * It connects to the router via the RouterOS API, gathers IPs from:
 *   - /ip/arp (ARP table)
 *   - /ip/dhcp-server/lease (DHCP leases)
 *   - /ip/address (static IP addresses on interfaces)
 * Then it computes the free IPs within a given CIDR subnet.
 *
 * Usage: `node find_unused_ip.js`
 */

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { RouterOSAPI } = require("node-routeros");

// ─── CONFIG ────────────────────────────────────────────────────────────────
// Adjust these constants for your environment.
const ROUTER_NAME = "earth"; // name as stored in the MongoDB routers collection
const SUBNET = "192.168.1.0/24"; // subnet to scan for free IPs

// ─── ENCRYPTION SETTINGS (same as other scripts) ────────────────────────
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const KEY_LENGTH = 32;
const ITERATIONS = 10000;

// ─── ENV LOADER ────────────────────────────────────────────────────────────
function loadEnv() {
  const files = [".env", ".env.local"];
  for (const file of files) {
    const envPath = path.join(process.cwd(), file);
    if (!fs.existsSync(envPath)) continue;
    const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const idx = trimmed.indexOf("=");
      if (idx < 0) continue;
      const key = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (!process.env[key]) process.env[key] = value;
    }
  }
}

// ─── DECRYPT PASSWORD ─────────────────────────────────────────────────────
function decryptPassword(cipheredText) {
  if (!cipheredText) return "";
  try {
    const keyStr = process.env.ENCRYPTION_KEY;
    const data = Buffer.from(cipheredText, "base64");
    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const key = crypto.pbkdf2Sync(keyStr, salt, ITERATIONS, KEY_LENGTH, "sha256");
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final("utf8");
  } catch {
    return cipheredText;
  }
}

// ─── LOGGING HELPERS ─────────────────────────────────────────────────────
function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}
function logSection(title) {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${"─".repeat(60)}`);
}

// ─── IP UTILITIES ───────────────────────────────────────────────────────
function ipToInt(ip) {
  return ip.split('.').reduce((int, oct) => (int << 8) + parseInt(oct, 10), 0) >>> 0;
}
function intToIp(int) {
  return [
    (int >>> 24) & 0xff,
    (int >>> 16) & 0xff,
    (int >>> 8) & 0xff,
    int & 0xff,
  ].join('.');
}
function* cidrRange(cidr) {
  const [base, maskStr] = cidr.split('/');
  const mask = parseInt(maskStr, 10);
  const baseInt = ipToInt(base);
  const hostBits = 32 - mask;
  const start = baseInt & (~((1 << hostBits) - 1));
  const end = start + (1 << hostBits) - 1;
  for (let i = start + 1; i < end; i++) { // skip network and broadcast
    yield intToIp(i);
  }
}

// ─── MAIN ────────────────────────────────────────────────────────────────
async function main() {
  loadEnv();

  // 1️⃣ Connect to MongoDB to fetch router credentials (same pattern as other scripts)
  const mongoose = require('mongoose');
  await mongoose.connect(process.env.MONGODB_URI);
  const Router = mongoose.connection.collection('routers');
  const router = await Router.findOne({ name: ROUTER_NAME });
  if (!router) throw new Error(`Router '${ROUTER_NAME}' not found in database`);
  const password = decryptPassword(router.password);

  // 2️⃣ Connect to MikroTik via API
  const api = new RouterOSAPI({
    host: router.host,
    user: router.username,
    password,
    port: Number(router.port || 8728),
    timeout: 10,
  });
  await api.connect();

  logSection('Gathering used IP addresses');
  const usedSet = new Set();

  // ARP table
  const arp = await api.write('/ip/arp/print');
  arp.forEach(entry => {
    if (entry.address) usedSet.add(entry.address);
  });

  // DHCP leases
  const leases = await api.write('/ip/dhcp-server/lease/print');
  leases.forEach(entry => {
    if (entry.address) usedSet.add(entry.address);
  });

  // Static IP addresses on interfaces
  const addresses = await api.write('/ip/address/print');
  addresses.forEach(entry => {
    if (entry.address) {
      // entry.address may include CIDR, e.g., "192.168.1.1/24"
      const ip = entry.address.split('/')[0];
      usedSet.add(ip);
    }
  });

  log(`Collected ${usedSet.size} used IPs`);

  // 3️⃣ Compute free IPs in the target subnet
  logSection(`Scanning subnet ${SUBNET}`);
  const freeIps = [];
  for (const ip of cidrRange(SUBNET)) {
    if (!usedSet.has(ip)) freeIps.push(ip);
    if (freeIps.length >= 20) break; // limit output to first 20 free IPs
  }

  if (freeIps.length === 0) {
    log('⚠️ No free IPs found in the specified subnet');
  } else {
    log(`✅ Found ${freeIps.length} free IP(s) (showing up to 20):`);
    freeIps.forEach(ip => console.log('  -', ip));
  }

  // Cleanup
  api.close();
  await mongoose.disconnect();
}

main()
  .then(() => process.exit(0))
  .catch(async err => {
    console.error('\n❌ FAILED:', err.message);
    try { await mongoose.disconnect(); } catch {}
    process.exit(1);
  });
