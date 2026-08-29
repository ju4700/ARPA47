/**
 * setup_netflow.js
 * 
 * Configures NetFlow v9 on MikroTik router for research data collection.
 * - Removes stale/wrong targets
 * - Sets correct flow export timeouts
 * - Adds correct collector target
 * - Verifies connectivity
 * - Prints final config summary
 */

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { RouterOSAPI } = require("node-routeros");

// ─── CONFIG ──────────────────────────────────────────────────────────────────

const ROUTER_NAME       = "earth";
const COLLECTOR_IP      = "103.148.176.43";   // Netis WAN IP (port-forwards to 192.168.1.17:2055)
const COLLECTOR_PORT    = "2055";
const NETFLOW_VERSION   = "9";

// Flow timeout settings — critical for research data quality
// active: export long-running flows every 1 min (not 30 min default)
// inactive: export idle flows after 15s
const ACTIVE_TIMEOUT    = "1m";
const INACTIVE_TIMEOUT  = "15s";
const CACHE_ENTRIES     = "4M";               // keep default, handles 2500 clients fine

// ─── ENCRYPTION (unchanged from your original) ───────────────────────────────

const ALGORITHM   = "aes-256-gcm";
const IV_LENGTH   = 12;
const TAG_LENGTH  = 16;
const SALT_LENGTH = 16;
const KEY_LENGTH  = 32;
const ITERATIONS  = 10000;

// ─── ENV LOADER ──────────────────────────────────────────────────────────────

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
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (!process.env[key]) process.env[key] = value;
    }
  }
}

// ─── DECRYPT ─────────────────────────────────────────────────────────────────

function decryptPassword(cipheredText) {
  if (!cipheredText) return "";
  try {
    const keyStr = process.env.ENCRYPTION_KEY;
    const data   = Buffer.from(cipheredText, "base64");
    const salt   = data.subarray(0, SALT_LENGTH);
    const iv     = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag    = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const key    = crypto.pbkdf2Sync(keyStr, salt, ITERATIONS, KEY_LENGTH, "sha256");
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final("utf8");
  } catch {
    return cipheredText;
  }
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function logSection(title) {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${"─".repeat(60)}`);
}

// ─── MAIN ────────────────────────────────────────────────────────────────────

async function main() {
  loadEnv();

  // ── 1. Connect to MongoDB and get router credentials ────────────────────
  logSection("Connecting to database");
  await mongoose.connect(process.env.MONGODB_URI);
  log("MongoDB connected");

  const Router = mongoose.connection.collection("routers");
  const router = await Router.findOne({ name: ROUTER_NAME });
  if (!router) throw new Error(`Router '${ROUTER_NAME}' not found in database`);

  log(`Router found: ${router.name} (${router.host})`);
  const password = decryptPassword(router.password);

  // ── 2. Connect to MikroTik via API ───────────────────────────────────────
  logSection("Connecting to MikroTik");
  const api = new RouterOSAPI({
    host: router.host,
    user: router.username,
    password,
    port: Number(router.port || 8728),
    timeout: 10,
  });

  await api.connect();
  log(`Connected to MikroTik at ${router.host}`);

  // ── 3. Verify collector is reachable from MikroTik ───────────────────────
  logSection("Testing connectivity to collector");
  log(`Pinging collector ${COLLECTOR_IP} from MikroTik...`);

  const pingResults = await api.write("/ping", [
    `=address=${COLLECTOR_IP}`,
    "=count=4",
    "=interval=500ms",
  ]);

  const received = pingResults.filter(p => p.status !== "timeout" && p.received === "1");
  const lost     = pingResults.filter(p => p.status === "timeout");

  if (received.length === 0) {
    log("❌ ERROR: MikroTik cannot reach collector IP " + COLLECTOR_IP);
    log("   NetFlow packets will not arrive. Fix routing first.");
    log("   Ping results:");
    console.dir(pingResults, { depth: null });
    throw new Error("Collector unreachable from MikroTik");
  }

  log(`✓ Collector reachable — ${received.length}/4 packets received, ${lost.length} lost`);

  // ── 4. Configure traffic-flow global settings ────────────────────────────
  logSection("Configuring traffic-flow global settings");

  await api.write("/ip/traffic-flow/set", [
    "=enabled=true",
    "=interfaces=all",
    `=active-flow-timeout=${ACTIVE_TIMEOUT}`,
    `=inactive-flow-timeout=${INACTIVE_TIMEOUT}`,
    `=cache-entries=${CACHE_ENTRIES}`,
  ]);

  log(`✓ Traffic flow enabled`);
  log(`✓ Active timeout  : ${ACTIVE_TIMEOUT}`);
  log(`✓ Inactive timeout: ${INACTIVE_TIMEOUT}`);
  log(`✓ Cache entries   : ${CACHE_ENTRIES}`);

  // ── 5. Clean up all existing targets ────────────────────────────────────
  logSection("Cleaning up existing NetFlow targets");

  const existingTargets = await api.write("/ip/traffic-flow/target/print");
  log(`Found ${existingTargets.length} existing target(s)`);

  for (const target of existingTargets) {
    const isCorrect = 
      target["dst-address"] === COLLECTOR_IP &&
      target.port === COLLECTOR_PORT &&
      target.version === NETFLOW_VERSION &&
      target.disabled === "false";

    if (isCorrect) {
      log(`✓ Keeping correct target: ${target["dst-address"]}:${target.port} v${target.version}`);
    } else {
      log(`✗ Removing stale/wrong target: ${target["dst-address"]}:${target.port} v${target.version || "?"} disabled=${target.disabled}`);
      await api.write("/ip/traffic-flow/target/remove", [
        `=.id=${target[".id"]}`,
      ]);
    }
  }

  // ── 6. Add correct target if not already present ────────────────────────
  logSection("Ensuring correct NetFlow target exists");

  const remainingTargets = await api.write("/ip/traffic-flow/target/print");
  const correctExists = remainingTargets.some(
    t => t["dst-address"] === COLLECTOR_IP && t.port === COLLECTOR_PORT
  );

  if (!correctExists) {
    log(`Adding target → ${COLLECTOR_IP}:${COLLECTOR_PORT} v${NETFLOW_VERSION}`);
    await api.write("/ip/traffic-flow/target/add", [
      `=dst-address=${COLLECTOR_IP}`,
      `=port=${COLLECTOR_PORT}`,
      `=version=${NETFLOW_VERSION}`,
      `=v9-template-refresh=20`,
      `=v9-template-timeout=30m`,
    ]);
    log("✓ Target created");
  } else {
    log("✓ Correct target already exists — no change needed");
  }

  // ── 7. Print final verified configuration ────────────────────────────────
  logSection("Final Configuration");

  const finalFlow    = await api.write("/ip/traffic-flow/print");
  const finalTargets = await api.write("/ip/traffic-flow/target/print");

  console.log("\nGlobal Traffic Flow Settings:");
  console.dir(finalFlow, { depth: null });

  console.log("\nNetFlow Targets:");
  console.dir(finalTargets, { depth: null });

  // ── 8. Summary ───────────────────────────────────────────────────────────
  logSection("Setup Summary");

  const flowEnabled = finalFlow[0]?.enabled === "true";
  const targetCount = finalTargets.length;
  const correctTarget = finalTargets.find(
    t => t["dst-address"] === COLLECTOR_IP && t.port === COLLECTOR_PORT
  );

  console.log(`
  Router          : ${router.name} (${router.host})
  Traffic Flow    : ${flowEnabled ? "✓ ENABLED" : "❌ DISABLED"}
  Active Timeout  : ${finalFlow[0]?.["active-flow-timeout"] || "unknown"}
  Inactive Timeout: ${finalFlow[0]?.["inactive-flow-timeout"] || "unknown"}
  Total Targets   : ${targetCount}
  Collector Target: ${correctTarget ? `✓ ${COLLECTOR_IP}:${COLLECTOR_PORT} v${correctTarget.version}` : "❌ NOT FOUND"}

  Next Steps on Fedora Server:
  1. Run: nfdump -r /data/flows/raw/nfcapd.current -q | wc -l
  2. Wait 2-3 minutes, count should increase
  3. Run: nfdump -r /data/flows/raw/nfcapd.current -o line | head -20
`);

  if (!flowEnabled || !correctTarget) {
    throw new Error("Configuration incomplete — check errors above");
  }

  log("✅ NetFlow configuration complete and verified");

  // ── 9. Cleanup ───────────────────────────────────────────────────────────
  api.close();
  await mongoose.disconnect();
}

// ─── RUN ─────────────────────────────────────────────────────────────────────

main()
  .then(() => process.exit(0))
  .catch(async (err) => {
    console.error(`\n❌ FAILED: ${err.message}`);
    try { await mongoose.disconnect(); } catch {}
    process.exit(1);
  });