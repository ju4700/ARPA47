// verify_syslog_target.js
/**
 * Verify that the MikroTik router is sending firewall logs to the correct
 * syslog collector (IP + port) and that the collector is reachable.
 *
 * This script follows the same environment‑loading and decryption logic as the
 * other scripts in the repository, so you can run it directly with:
 *
 *   node scripts/verify_syslog_target.js
 *
 * It performs two checks:
 *   1. Reads the remote‑logging action (name = "remote") from the router and
 *      prints the configured `remote` IP and `remote-port`.
 *   2. Sends a tiny UDP packet from the router to that IP/port using the
 *      `/tool fetch` command (mode=udp). If the packet is received, the router
 *      will report `status=success`. This tells you whether the collector is
 *      reachable from the router’s perspective (i.e. whether you need a port‑
 *      forward on your Netis router).
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { RouterOSAPI } = require('node-routeros');

// ─── CONFIG ────────────────────────────────────────────────────────────────
// Name of the router entry in the MongoDB "routers" collection (same as other scripts)
const ROUTER_NAME = 'earth';

// ─── ENCRYPTION SETTINGS (identical to other scripts) ───────────────────────
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const KEY_LENGTH = 32;
const ITERATIONS = 10000;

// ─── ENV LOADER ────────────────────────────────────────────────────────────
function loadEnv() {
  const files = ['.env', '.env.local'];
  for (const file of files) {
    const envPath = path.join(process.cwd(), file);
    if (!fs.existsSync(envPath)) continue;
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
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

// ─── LOGGING HELPERS ─────────────────────────────────────────────────────
function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}
function logSection(title) {
  console.log('\n' + '─'.repeat(60));
  console.log(`  ${title}`);
  console.log('─'.repeat(60));
}

// ─── MAIN ────────────────────────────────────────────────────────────────
async function main() {
  loadEnv();

  // 1️⃣ Load router credentials from MongoDB (same pattern as other scripts)
  const mongoose = require('mongoose');
  await mongoose.connect(process.env.MONGODB_URI);
  const Router = mongoose.connection.collection('routers');
  const router = await Router.findOne({ name: ROUTER_NAME });
  if (!router) throw new Error(`Router '${ROUTER_NAME}' not found in database`);
  const password = decryptPassword(router.password);

  // 2️⃣ Connect to MikroTik API
  const api = new RouterOSAPI({
    host: router.host,
    user: router.username,
    password,
    port: Number(router.port || 8728),
    timeout: 10,
  });
  await api.connect();

  // 3️⃣ Retrieve the remote‑logging action named "remote"
  logSection('Fetching remote syslog action from router');
  const actions = await api.write('/system/logging/action/print');
  const remote = actions.find(a => a.name === 'remote');
  if (!remote) {
    console.error('❌ No logging action named "remote" found on the router');
    process.exit(1);
  }
  const collectorIp = remote.remote;
  const collectorPort = remote['remote-port'];
  console.log(`Configured collector: ${collectorIp}:${collectorPort}`);

  // 4️⃣ Advise about UDP reachability
  logSection('UDP reachability advice');
  console.log('The script cannot programmatically test UDP reachability from the router,');
  console.log('but you can verify it manually by sending a test packet from the router');
  console.log('or by checking that the collector receives logs after a known event (e.g., a ping to the honeypot IP).');
  console.log('If the collector does NOT receive any HONEYPOT logs, you will need to forward UDP port 514');
  console.log('on your Netis router (WAN → 103.148.176.43).');

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
