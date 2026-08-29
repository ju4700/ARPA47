/**
 * setup_honeypot_syslog.js
 *
 * Configures two research monitoring systems on MikroTik:
 *
 * 1. HONEYPOT
 *    Assigns an unused IP in the client range to the router.
 *    Any traffic hitting this IP is guaranteed malicious (no real client uses it).
 *    Firewall rules LOG then DROP all traffic to this IP.
 *    Provides ground-truth attack labels for the NIDS dataset.
 *
 * 2. SYSLOG FORWARDING
 *    Sends MikroTik firewall logs (including honeypot hits) to Fedora server.
 *    Fedora rsyslog receives on UDP 514 and writes to /var/log/mikrotik/
 *    parse_honeypot.py processes hits into structured CSV every 5 minutes.
 *
 * Usage: node setup_honeypot_syslog.js
 *        node setup_honeypot_syslog.js --dry-run   (print changes without applying)
 *        node setup_honeypot_syslog.js --remove     (undo all changes)
 */

const path   = require("path");
const fs     = require("fs");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { RouterOSAPI } = require("node-routeros");

// ─── RESEARCH CONFIG ─────────────────────────────────────────────────────────
//
// HONEYPOT_IP: Must be an IP in your client range that is NEVER assigned
//              to any real device. Check your MikroTik DHCP leases and
//              static IPs before choosing.
//
//              Your client range is 103.148.176.x
//              .253 and .254 are typically safe choices
//              .1 is your router — do NOT use that
//
const ROUTER_NAME     = "earth";
const HONEYPOT_IP     = "103.148.176.62";    // ← VERIFY this IP is unused
const SYSLOG_SERVER   = "103.148.176.43";    // Netis WAN IP (port-forwards to Fedora)
const SYSLOG_PORT     = 514;
const LOG_PREFIX      = "HONEYPOT:";

// Comment tags used to identify our rules — never change these after deployment
// Changing them means the script can no longer detect existing rules
const TAG_HP_CHAIN_LOG     = "RESEARCH:honeypot-chain-log";
const TAG_HP_CHAIN_DROP    = "RESEARCH:honeypot-chain-drop";
const TAG_HP_INPUT_JUMP    = "RESEARCH:honeypot-input-jump";
const TAG_HP_FORWARD_JUMP  = "RESEARCH:honeypot-forward-jump";
const TAG_HP_ADDRESS       = "RESEARCH:honeypot-ip";

// ─── ENCRYPTION (identical to setup_netflow.js) ───────────────────────────────

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
      ) value = value.slice(1, -1);
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
    const enc    = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
    const key    = crypto.pbkdf2Sync(keyStr, salt, ITERATIONS, KEY_LENGTH, "sha256");
    const dec    = crypto.createDecipheriv(ALGORITHM, key, iv);
    dec.setAuthTag(tag);
    return dec.update(enc) + dec.final("utf8");
  } catch {
    return cipheredText;
  }
}

// ─── LOGGING ─────────────────────────────────────────────────────────────────

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
  const dryRun = process.argv.includes("--dry-run");
  const remove = process.argv.includes("--remove");

  if (dryRun)  log("⚠️  DRY RUN MODE — no changes will be applied");
  if (remove)  log("⚠️  REMOVE MODE — will undo all honeypot/syslog changes");

  loadEnv();

  // ── 1. Connect to database ────────────────────────────────────────────────
  logSection("Connecting to database");
  await mongoose.connect(process.env.MONGODB_URI);
  log("MongoDB connected");

  const Router = mongoose.connection.collection("routers");
  const router = await Router.findOne({ name: ROUTER_NAME });
  if (!router) throw new Error(`Router '${ROUTER_NAME}' not found`);
  log(`Router: ${router.name} (${router.host})`);

  const password = decryptPassword(router.password);

  // ── 2. Connect to MikroTik ────────────────────────────────────────────────
  logSection("Connecting to MikroTik");
  const api = new RouterOSAPI({
    host:     router.host,
    user:     router.username,
    password,
    port:     Number(router.port || 8728),
    timeout:  15,
  });

  await api.connect();
  log(`Connected to MikroTik at ${router.host}`);

  // ── 3. Discover network interfaces ───────────────────────────────────────
  logSection("Discovering network interfaces");

  const addresses = await api.write("/ip/address/print");
  log("Current IP addresses:");

  let honeypotInterface = null;

  // ─── SUBNET UTILITIES ────────────────────────────────────────────────────────

  function ipToNum(ip) {
    return ip.split(".").reduce((acc, oct) => ((acc << 8) + parseInt(oct, 10)) >>> 0, 0);
  }

  /**
   * Returns true if `ip` falls within the subnet described by `cidr`
   * e.g. isInSubnet("103.148.176.62", "103.148.176.33/27") → true
   */
  function isInSubnet(ip, cidr) {
    const [base, prefixStr] = cidr.split("/");
    const prefix = parseInt(prefixStr ?? "32", 10);
    const mask   = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipToNum(ip) & mask) === (ipToNum(base) & mask);
  }
  // AFTER
for (const addr of addresses) {
  const flag = addr.disabled === "true" ? "[disabled]" : "";
  log(`  ${addr.address.padEnd(22)} on ${addr.interface.padEnd(12)} ${flag} ${addr.comment || ""}`);

  // Use proper CIDR containment — not naive /24 prefix matching.
  // Skip loopback: a honeypot must live on a client-facing interface.
  if (addr.address && addr.disabled !== "true" && addr.interface !== "loopback") {
    if (isInSubnet(HONEYPOT_IP, addr.address)) {
      honeypotInterface = addr.interface;
      log(`  → Honeypot IP ${HONEYPOT_IP} is within ${addr.address} on ${honeypotInterface}`);
    }
  }
}

  if (!honeypotInterface) {
    throw new Error(
      `Could not auto-detect interface for honeypot IP ${HONEYPOT_IP}.\n` +
      `No existing IP in the same /24 subnet was found.\n` +
      `Check your interface names above and set honeypotInterface manually.`
    );
  }

  // ── 4. Verify honeypot IP is not already in use ───────────────────────────
  logSection(`Verifying honeypot IP: ${HONEYPOT_IP}`);

  const alreadyAssigned = addresses.find(
    a => a.address && a.address.split("/")[0] === HONEYPOT_IP && !a.comment?.includes("RESEARCH:")
  );

  if (alreadyAssigned) {
    throw new Error(
      `HONEYPOT_IP ${HONEYPOT_IP} is already assigned to interface ${alreadyAssigned.interface}.\n` +
      `Choose a different IP that is genuinely unused by any client.`
    );
  }

  const leases = await api.write("/ip/dhcp-server/lease/print");
  const leaseConflict = leases.find(l => l.address === HONEYPOT_IP && l.status === "bound");
  if (leaseConflict) {
    throw new Error(
      `HONEYPOT_IP ${HONEYPOT_IP} has an active DHCP lease (MAC: ${leaseConflict["mac-address"]}).\n` +
      `Choose a different IP that no client is using.`
    );
  }

  log(`✓ ${HONEYPOT_IP} is free — no existing assignment or DHCP lease`);

  // ── 5. REMOVE MODE — undo everything ─────────────────────────────────────
  if (remove) {
    logSection("Removing all honeypot and syslog configuration");

    // Remove firewall rules by comment tag
    const rules = await api.write("/ip/firewall/filter/print");
    const ourTags = [TAG_HP_CHAIN_LOG, TAG_HP_CHAIN_DROP, TAG_HP_INPUT_JUMP, TAG_HP_FORWARD_JUMP];
    for (const rule of rules) {
      if (ourTags.includes(rule.comment)) {
        log(`  Removing rule: ${rule.comment} (chain=${rule.chain})`);
        if (!dryRun) {
          await api.write("/ip/firewall/filter/remove", [`=.id=${rule[".id"]}`]);
        }
      }
    }

    // Remove honeypot IP address
    const ourAddresses = addresses.filter(a => a.comment === TAG_HP_ADDRESS);
    for (const addr of ourAddresses) {
      log(`  Removing IP: ${addr.address}`);
      if (!dryRun) {
        await api.write("/ip/address/remove", [`=.id=${addr[".id"]}`]);
      }
    }

    // Remove firewall logging topic for remote
    const loggingRules = await api.write("/system/logging/print");
    const fwRemote = loggingRules.find(
      r => r.topics === "firewall" && r.action === "remote" && r.prefix === "FW"
    );
    if (fwRemote) {
      log(`  Removing firewall remote logging rule`);
      if (!dryRun) {
        await api.write("/system/logging/remove", [`=.id=${fwRemote[".id"]}`]);
      }
    }

    log("✓ Removal complete");
    api.close();
    await mongoose.disconnect();
    return;
  }

  // ── 6. Add honeypot IP address ────────────────────────────────────────────
  logSection(`Adding honeypot IP: ${HONEYPOT_IP}`);

  const existingHoneypot = addresses.find(a => a.comment === TAG_HP_ADDRESS);

  if (existingHoneypot) {
    log(`✓ Honeypot IP already configured: ${existingHoneypot.address} on ${existingHoneypot.interface}`);
  } else {
    log(`  Adding ${HONEYPOT_IP}/32 to interface ${honeypotInterface}...`);
    if (!dryRun) {
      await api.write("/ip/address/add", [
        `=address=${HONEYPOT_IP}/32`,
        `=interface=${honeypotInterface}`,
        `=comment=${TAG_HP_ADDRESS}`,
      ]);
    }
    log(`✓ Honeypot IP ${HONEYPOT_IP}/32 added to ${honeypotInterface}`);
  }

  // ── 7. Configure firewall rules ───────────────────────────────────────────
  //
  // Architecture: Custom "honeypot" chain (cleaner than inline rules)
  //
  //  input chain:   ... → [JUMP to honeypot if dst=HONEYPOT_IP] → ...
  //  forward chain: ... → [JUMP to honeypot if dst=HONEYPOT_IP] → ...
  //
  //  honeypot chain: LOG (logs to syslog) → DROP (kills packet)
  //
  // The JUMP rules are placed at position 0 (top) of their chains so they
  // fire before any established/related rules.
  //
  logSection("Configuring firewall rules");

  const existingRules = await api.write("/ip/firewall/filter/print");

  // ── 7a. Honeypot chain: LOG rule ──────────────────────────────────────────
  // ── 7a. Honeypot chain: LOG rule ──────────────────────────
const chainLogExists = existingRules.find(
  r => r.comment === TAG_HP_CHAIN_LOG
);

if (chainLogExists) {
  log(`✓ Honeypot chain LOG rule already exists`);
} else {
  log(`  Adding honeypot chain LOG rule...`);

  if (!dryRun) {
    await api.write("/ip/firewall/filter/add", [
      "=chain=honeypot",
      "=action=log",
      `=log-prefix=${LOG_PREFIX}`,
      `=comment=${TAG_HP_CHAIN_LOG}`,
    ]);
  }

  log(`✓ Honeypot chain LOG rule added`);
}

  // ── 7b. Honeypot chain: DROP rule ─────────────────────────────────────────
  const chainDropExists = existingRules.find(r => r.comment === TAG_HP_CHAIN_DROP);
  if (chainDropExists) {
    log(`✓ Honeypot chain DROP rule already exists`);
  } else {
    log(`  Adding honeypot chain DROP rule...`);
    if (!dryRun) {
      await api.write("/ip/firewall/filter/add", [
        "=chain=honeypot",
        "=action=drop",
        `=comment=${TAG_HP_CHAIN_DROP}`,
      ]);
    }
    log(`✓ Honeypot chain DROP rule added`);
  }

  // ── 7c. INPUT chain: JUMP to honeypot ────────────────────────────────────
  const inputJumpExists = existingRules.find(r => r.comment === TAG_HP_INPUT_JUMP);
  if (inputJumpExists) {
    log(`✓ Input chain JUMP rule already exists`);
  } else {
    log(`  Adding input chain JUMP rule (place-before=0)...`);
    if (!dryRun) {
      await api.write("/ip/firewall/filter/add", [
        "=chain=input",
        `=dst-address=${HONEYPOT_IP}`,
        "=action=jump",
        "=jump-target=honeypot",
        "=place-before=0",
        `=comment=${TAG_HP_INPUT_JUMP}`,
      ]);
    }
    log(`✓ Input chain JUMP rule added at top`);
  }

  // ── 7d. FORWARD chain: JUMP to honeypot ──────────────────────────────────
  const forwardJumpExists = existingRules.find(r => r.comment === TAG_HP_FORWARD_JUMP);
  if (forwardJumpExists) {
    log(`✓ Forward chain JUMP rule already exists`);
  } else {
    log(`  Adding forward chain JUMP rule (place-before=0)...`);
    if (!dryRun) {
      await api.write("/ip/firewall/filter/add", [
        "=chain=forward",
        `=dst-address=${HONEYPOT_IP}`,
        "=action=jump",
        "=jump-target=honeypot",
        "=place-before=0",
        `=comment=${TAG_HP_FORWARD_JUMP}`,
      ]);
    }
    log(`✓ Forward chain JUMP rule added at top`);
  }

  // ── 8. Configure syslog forwarding ───────────────────────────────────────
  logSection(`Configuring syslog → ${SYSLOG_SERVER}:${SYSLOG_PORT}`);

  // MikroTik has a built-in "remote" logging action
  const loggingActions = await api.write("/system/logging/action/print");
  const remoteAction   = loggingActions.find(a => a.name === "remote");

  if (!remoteAction) {
    throw new Error(
      "Remote logging action not found on this router.\n" +
      "MikroTik RouterOS should have a built-in 'remote' action.\n" +
      "Check: /system logging action print"
    );
  }

  const currentRemote = remoteAction.remote || "";
  const currentPort   = remoteAction["remote-port"] || "";

  if (currentRemote === SYSLOG_SERVER && currentPort === String(SYSLOG_PORT)) {
    log(`✓ Remote syslog already configured: ${SYSLOG_SERVER}:${SYSLOG_PORT}`);
  } else {
    log(`  Current: remote=${currentRemote || "(not set)"} port=${currentPort || "(not set)"}`);
    log(`  Setting: remote=${SYSLOG_SERVER} port=${SYSLOG_PORT}`);
    if (!dryRun) {
      await api.write("/system/logging/action/set", [
        `=.id=${remoteAction[".id"]}`,
        `=remote=${SYSLOG_SERVER}`,
        `=remote-port=${SYSLOG_PORT}`,
        "=src-address=0.0.0.0",
        "=bsd-syslog=no",
        "=syslog-facility=daemon",
        "=syslog-severity=auto",
      ]);
    }
    log(`✓ Remote syslog configured → ${SYSLOG_SERVER}:${SYSLOG_PORT}`);
  }

  // ── 9. Add firewall logging topic to remote action ────────────────────────
  logSection("Enabling firewall log topic for remote syslog");

  const loggingRules  = await api.write("/system/logging/print");

  // Check for firewall topic on remote action
  const fwRemoteExists = loggingRules.find(
    r => r.topics === "firewall" && r.action === "remote"
  );

  if (fwRemoteExists) {
    log(`✓ Firewall topic already forwarded to remote syslog`);
  } else {
    log(`  Adding firewall topic → remote action...`);
    if (!dryRun) {
      await api.write("/system/logging/add", [
        "=topics=firewall",
        "=action=remote",
        "=prefix=FW",
      ]);
    }
    log(`✓ Firewall logs will now be forwarded to ${SYSLOG_SERVER}`);
  }

  // Also add system+info topics so we get general router events
  const systemRemoteExists = loggingRules.find(
    r => r.topics === "system" && r.action === "remote"
  );
  if (!systemRemoteExists) {
    log(`  Adding system topic → remote action...`);
    if (!dryRun) {
      await api.write("/system/logging/add", [
        "=topics=system,info",
        "=action=remote",
        "=prefix=SYS",
      ]);
    }
    log(`✓ System logs will also be forwarded`);
  }

  // ── 10. Send a test syslog message ────────────────────────────────────────
  logSection("Sending test syslog message");

  if (!dryRun) {
    await api.write("/log/print", ["=follow=", "=count=1"]);

    // Log a test message using /log/info
    await api.write("/log/info", [
      "=message=RESEARCH-SYSLOG-TEST: Honeypot and syslog setup complete",
    ]);
    log(`✓ Test message sent to syslog`);
    log(`  Check Fedora: tail -f /var/log/mikrotik/$(date +%Y-%m-%d).log`);
  }

  // ── 11. Print final verification ─────────────────────────────────────────
  logSection("Final Verification");

  const finalRules    = await api.write("/ip/firewall/filter/print");
  const finalAddrs    = await api.write("/ip/address/print");
  const finalLogging  = await api.write("/system/logging/print");
  const finalActions  = await api.write("/system/logging/action/print");
  const finalRemote   = finalActions.find(a => a.name === "remote");

  const hpAddr      = finalAddrs.find(a => a.comment === TAG_HP_ADDRESS);
  const hpChainLog  = finalRules.find(r => r.comment === TAG_HP_CHAIN_LOG);
  const hpChainDrop = finalRules.find(r => r.comment === TAG_HP_CHAIN_DROP);
  const hpInJump    = finalRules.find(r => r.comment === TAG_HP_INPUT_JUMP);
  const hpFwdJump   = finalRules.find(r => r.comment === TAG_HP_FORWARD_JUMP);
  const fwLogging   = finalLogging.find(r => r.topics === "firewall" && r.action === "remote");

  console.log(`
  ┌─────────────────────────────────────────────────────┐
  │             Setup Verification Summary               │
  ├─────────────────────────────────────────────────────┤
  │  HONEYPOT                                           │
  │  IP Address  : ${(hpAddr     ? `✓ ${hpAddr.address} on ${hpAddr.interface}` : "❌ Not configured").padEnd(37)}│
  │  Chain LOG   : ${(hpChainLog  ? "✓ Configured"                               : "❌ Missing").padEnd(37)}│
  │  Chain DROP  : ${(hpChainDrop ? "✓ Configured"                               : "❌ Missing").padEnd(37)}│
  │  Input JUMP  : ${(hpInJump    ? "✓ Configured (at top of input chain)"       : "❌ Missing").padEnd(37)}│
  │  Forward JUMP: ${(hpFwdJump   ? "✓ Configured (at top of forward chain)"     : "❌ Missing").padEnd(37)}│
  ├─────────────────────────────────────────────────────┤
  │  SYSLOG FORWARDING                                  │
  │  Destination : ${(finalRemote  ? `✓ ${finalRemote.remote}:${finalRemote["remote-port"]}` : "❌ Not set").padEnd(37)}│
  │  FW Logging  : ${(fwLogging    ? "✓ Firewall logs → remote"                  : "❌ Not enabled").padEnd(37)}│
  └─────────────────────────────────────────────────────┘

  What happens next:
  ─────────────────────────────────────────────────────
  Any scan/probe hitting ${HONEYPOT_IP} will:
  1. Be logged by MikroTik as "HONEYPOT:" prefix
  2. Sent via syslog to ${SYSLOG_SERVER}:${SYSLOG_PORT}
  3. Forwarded by Netis to your Fedora server :514
  4. Written to /var/log/mikrotik/YYYY-MM-DD.log
  5. Written to /data/flows/metadata/honeypot_raw.log
  6. Parsed by parse_honeypot.py every 5 minutes
  7. Structured into /data/flows/metadata/honeypot_hits.csv

  To verify on Fedora:
  ─────────────────────────────────────────────────────
  tail -f /var/log/mikrotik/$(date +%Y-%m-%d).log
  tail -f /data/flows/metadata/honeypot_raw.log
  cat /data/flows/metadata/honeypot_hits.csv
`);

  const allOk = hpAddr && hpChainLog && hpChainDrop && hpInJump && hpFwdJump && fwLogging;
  if (allOk) {
    log("✅ All components configured successfully");
  } else {
    log("⚠️  Some components are missing — check errors above");
  }

  // ── 12. Cleanup ──────────────────────────────────────────────────────────
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