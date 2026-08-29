#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const { Telnet } = require("telnet-client");

const PROMPT_WAIT = /(?:Switch|[A-Za-z0-9_.-]+)[>#]\s*$/m;

function loadEnv() {
  const envCandidates = [
    path.join(process.cwd(), ".env"),
    path.join(process.cwd(), ".env.local"),
  ];

  for (const envPath of envCandidates) {
    if (!fs.existsSync(envPath)) continue;
    const raw = fs.readFileSync(envPath, "utf8");
    const lines = raw.split(/\r?\n/);

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      const idx = line.indexOf("=");
      if (idx <= 0) continue;

      const key = line.slice(0, idx).trim();
      let value = line.slice(idx + 1).trim();
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

function normalizeMac(value) {
  return String(value || "").toLowerCase().replace(/[^0-9a-f]/g, "");
}

function formatMac(normalizedMac) {
  if (normalizedMac.length !== 12) return normalizedMac;
  const chunks = normalizedMac.match(/.{1,2}/g) || [];
  return chunks.join(":");
}

function parseMacEntries(output) {
  const lines = String(output || "").split(/\r?\n/);
  const seen = new Set();
  const entries = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const macMatch = line.match(/(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|(?:[0-9a-f]{2}[-:.]){5}[0-9a-f]{2}|\b[0-9a-f]{12}\b/i);
    if (!macMatch) continue;

    const normalized = normalizeMac(macMatch[0]);
    if (normalized.length !== 12) continue;

    const interfaceMatch =
      line.match(/\b(?:epon|gpon)\d+\/\d+(?::\d+)?\b/i) ||
      line.match(/\bonu\d+\/\d+:\d+\b/i) ||
      line.match(/\b(?:g\d+\/\d+|tg\d+\/\d+)\b/i);

    const interfaceName = interfaceMatch ? interfaceMatch[0] : null;
    const dedupeKey = `${normalized}|${interfaceName || ""}|${line}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    entries.push({
      mac: formatMac(normalized),
      normalizedMac: normalized,
      interface: interfaceName,
      raw: line,
    });
  }

  return entries;
}

function parseMacTotal(output) {
  const match = String(output || "").match(/Total\s+MAC\s+address\s*:\s*(\d+)/i);
  if (!match) return null;
  const value = Number(match[1]);
  return Number.isFinite(value) ? value : null;
}

async function sendCommand(telnet, command, timeout = 30000) {
  return String(await telnet.send(command, { waitFor: PROMPT_WAIT, timeout }));
}

async function connectAndLogin(host, username, password, port = 23) {
  const telnet = new Telnet();

  await telnet.connect({
    host,
    port,
    timeout: 10000,
    disableLogon: true,
    negotiationMandatory: true,
    shellPrompt: null,
    irs: "\r\n",
    ors: "\r\n",
    stripControls: true,
    echoLines: 0,
    sendTimeout: 10000,
    pageSeparator: /--More--/,
  });

  await telnet.nextData();
  const afterUser = await telnet.send(username, {
    waitFor: /Username[: ]*|Password[: ]*$/i,
    timeout: 10000,
  });

  if (/Password[: ]*$/i.test(String(afterUser))) {
    await telnet.send(password, { waitFor: PROMPT_WAIT, timeout: 12000 });
  } else {
    await telnet.send(username, { waitFor: /Password[: ]*$/i, timeout: 10000 });
    await telnet.send(password, { waitFor: PROMPT_WAIT, timeout: 12000 });
  }

  await sendCommand(telnet, "enable", 10000);
  await sendCommand(telnet, "terminal length 0", 10000);

  return telnet;
}

async function getOltTargets() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is missing. Ensure .env is present.");
  }

  const RouterSchema = new mongoose.Schema(
    {
      name: String,
      host: String,
      port: Number,
      username: String,
      isActive: Boolean,
      brand: String,
      deviceType: String,
    },
    { strict: false },
  );

  const Router =
    mongoose.models.DumpOltRouter ||
    mongoose.model("DumpOltRouter", RouterSchema, "routers");

  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });

  const rows = await Router.find({
    $or: [{ deviceType: "olt" }, { brand: /olt|bdcom|vsol/i }, { name: /olt/i }],
    isActive: true,
  })
    .select("name host port username deviceType brand")
    .lean();

  const byHost = new Map();
  for (const row of rows) {
    const host = String(row.host || "").trim();
    if (!host) continue;
    if (byHost.has(host)) continue;

    byHost.set(host, {
      name: row.name || host,
      host,
      port: Number(row.port || 23),
      username: String(row.username || "admin") || "admin",
      password: "admin",
    });
  }

  await mongoose.disconnect();
  return [...byHost.values()];
}

async function main() {
  loadEnv();
  const targets = await getOltTargets();

  if (targets.length === 0) {
    throw new Error("No active OLT targets found in router records.");
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outDir = path.join(process.cwd(), "scripts", "backups", "olt-mac-dumps", stamp);
  fs.mkdirSync(outDir, { recursive: true });

  const report = [];

  for (const target of targets) {
    const item = {
      host: target.host,
      name: target.name,
      success: false,
      macTotal: null,
      parsedEntries: 0,
      rawFile: null,
      parsedFile: null,
      error: null,
      sampleMacs: [],
    };

    let telnet;
    try {
      telnet = await connectAndLogin(target.host, target.username, target.password, target.port);
      const totalOutput = await sendCommand(telnet, "show mac address-table brief | include Total", 25000);
      const rawOutput = await sendCommand(telnet, "show mac address-table", 60000);

      const entries = parseMacEntries(rawOutput);
      const uniqueByMac = new Map();
      for (const entry of entries) {
        if (!uniqueByMac.has(entry.normalizedMac)) {
          uniqueByMac.set(entry.normalizedMac, entry);
        }
      }
      const uniqueEntries = [...uniqueByMac.values()];

      const safeHost = target.host.replace(/[^0-9a-zA-Z.-]/g, "_");
      const rawFile = path.join(outDir, `${safeHost}-raw.txt`);
      const parsedFile = path.join(outDir, `${safeHost}-parsed.json`);

      fs.writeFileSync(rawFile, `${totalOutput}\n\n${rawOutput}\n`, "utf8");
      fs.writeFileSync(parsedFile, `${JSON.stringify(uniqueEntries, null, 2)}\n`, "utf8");

      item.success = true;
      item.macTotal = parseMacTotal(totalOutput);
      item.parsedEntries = uniqueEntries.length;
      item.rawFile = rawFile;
      item.parsedFile = parsedFile;
      item.sampleMacs = uniqueEntries.slice(0, 20).map((entry) => entry.mac);
    } catch (error) {
      item.error = error && error.message ? error.message : String(error);
    } finally {
      if (telnet) {
        try { await telnet.end(); } catch {}
      }
    }

    report.push(item);
  }

  const reportFile = path.join(outDir, "report.json");
  fs.writeFileSync(reportFile, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  console.log(JSON.stringify({ outDir, reportFile, report }, null, 2));
}

main().catch(async (error) => {
  console.error(error && error.message ? error.message : error);
  try { await mongoose.disconnect(); } catch {}
  process.exit(1);
});
