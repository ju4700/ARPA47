const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { RouterOSAPI } = require("node-routeros");

const TARGET_CLIENT = {
  name: "JAHANGIR CON S/N 21.06.2020",
  ipAddress: "103.148.176.43",
  macAddress: "BC:62:CE:09:DB:CE",
  type: "Static",
};

const BACKUP_FILE = path.join(__dirname, "backups", "client-speed-backups.json");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const KEY_LENGTH = 32;
const ITERATIONS = 10000;

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

      if (!process.env[key]) {
        process.env[key] = value;
      }
    }
  }
}

function decryptPassword(cipheredText) {
  if (!cipheredText || typeof cipheredText !== "string") return "";
  const keyStr = process.env.ENCRYPTION_KEY;
  if (!keyStr) return cipheredText;

  try {
    const data = Buffer.from(cipheredText, "base64");
    const minLength = SALT_LENGTH + IV_LENGTH + TAG_LENGTH + 1;
    if (data.length < minLength) return cipheredText;

    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const tag = data.subarray(
      SALT_LENGTH + IV_LENGTH,
      SALT_LENGTH + IV_LENGTH + TAG_LENGTH,
    );
    const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

    const key = crypto.pbkdf2Sync(keyStr, salt, ITERATIONS, KEY_LENGTH, "sha256");
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    return decipher.update(encrypted) + decipher.final("utf8");
  } catch {
    return cipheredText;
  }
}

function getModels() {
  const ClientSchema = new mongoose.Schema(
    {
      routerId: mongoose.Schema.Types.ObjectId,
      name: String,
      type: String,
      ipAddress: String,
      macAddress: String,
      status: String,
      comment: String,
      updatedAt: Date,
    },
    { strict: false },
  );

  const RouterSchema = new mongoose.Schema(
    {
      name: String,
      host: String,
      port: Number,
      username: String,
      password: String,
      isActive: Boolean,
      deviceType: String,
      brand: String,
    },
    { strict: false },
  );

  const Client =
    mongoose.models.SpeedScriptClient ||
    mongoose.model("SpeedScriptClient", ClientSchema, "clients");
  const Router =
    mongoose.models.SpeedScriptRouter ||
    mongoose.model("SpeedScriptRouter", RouterSchema, "routers");

  return { Client, Router };
}

async function resolveClientAndRouter() {
  if (!process.env.MONGODB_URI) {
    throw new Error("MONGODB_URI is missing. Ensure .env is present.");
  }

  const { Client, Router } = getModels();

  await mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
  });

  const client = await Client.findOne({
    ipAddress: TARGET_CLIENT.ipAddress,
    type: TARGET_CLIENT.type,
  }).lean();

  if (!client) {
    throw new Error(
      `Client not found for IP ${TARGET_CLIENT.ipAddress}. Run pulse and try again.`,
    );
  }

  const router = await Router.findById(client.routerId).lean();
  if (!router) {
    throw new Error(`Router not found for client ${client.name || client._id}.`);
  }

  const password = decryptPassword(router.password || "");
  if (!router.username || !password) {
    throw new Error("Router credentials are missing or invalid.");
  }

  return {
    client,
    router: {
      ...router,
      port: Number(router.port || 8728),
      username: String(router.username),
      password,
    },
  };
}

function parseTargetIps(target) {
  return String(target || "")
    .split(",")
    .map((token) => token.trim())
    .filter(Boolean)
    .map((token) => token.split("/")[0]?.trim() || "")
    .filter(Boolean);
}

function queueMatchScore(queue, ipAddress) {
  const target = String(queue?.target || "");
  const tokens = target.split(",").map((token) => token.trim()).filter(Boolean);

  let score = 0;
  for (const token of tokens) {
    if (token === ipAddress) score = Math.max(score, 100);
    if (token === `${ipAddress}/32`) score = Math.max(score, 95);
    if (token.startsWith(`${ipAddress}/`)) score = Math.max(score, 80);
    if (token.split("/")[0] === ipAddress) score = Math.max(score, 60);
  }

  return score;
}

async function findQueueForClient(api, client) {
  const queues = await api.write("/queue/simple/print", [
    "=.proplist=.id,name,target,max-limit,limit-at,burst-limit,burst-threshold,burst-time,priority,queue,comment,disabled",
  ]);

  const byTarget = (queues || [])
    .filter((queue) => parseTargetIps(queue.target).includes(String(client.ipAddress || "")))
    .map((queue) => ({ queue, score: queueMatchScore(queue, String(client.ipAddress || "")) }))
    .sort((a, b) => b.score - a.score)
    .map((item) => item.queue);

  if (byTarget.length > 0) return byTarget[0];

  const byName = (queues || []).find((queue) => {
    const queueName = String(queue.name || "").toLowerCase();
    const clientName = String(client.name || "").toLowerCase();
    const ipAddress = String(client.ipAddress || "");
    return (
      queueName === clientName ||
      (clientName && queueName.includes(clientName)) ||
      (ipAddress && queueName.includes(ipAddress))
    );
  });

  if (byName) return byName;

  throw new Error(
    `No simple queue found for client ${client.name || "Unknown"} (${client.ipAddress || "no IP"}).`,
  );
}

function ensureBackupFile() {
  const dir = path.dirname(BACKUP_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  if (!fs.existsSync(BACKUP_FILE)) {
    fs.writeFileSync(BACKUP_FILE, "{}\n", "utf8");
  }
}

function readBackupStore() {
  ensureBackupFile();
  try {
    const raw = fs.readFileSync(BACKUP_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed;
    return {};
  } catch {
    return {};
  }
}

function writeBackupStore(store) {
  ensureBackupFile();
  fs.writeFileSync(BACKUP_FILE, `${JSON.stringify(store, null, 2)}\n`, "utf8");
}

function makeBackupKey(router, client) {
  const routerKey = router._id ? String(router._id) : String(router.host || "unknown-router");
  return `${routerKey}::${String(client.ipAddress || "unknown-ip")}`;
}

function makeQueueSnapshot(queue) {
  return {
    id: queue[".id"] || "",
    name: queue.name || "",
    target: queue.target || "",
    maxLimit: queue["max-limit"] || "",
    limitAt: queue["limit-at"] || "",
    burstLimit: queue["burst-limit"] || "",
    burstThreshold: queue["burst-threshold"] || "",
    burstTime: queue["burst-time"] || "",
    priority: queue.priority || "",
    queueType: queue.queue || "",
    disabled: queue.disabled || "false",
  };
}

async function withRouterConnection(router, handler) {
  const api = new RouterOSAPI({
    host: String(router.host || "").trim(),
    user: String(router.username || "").trim(),
    password: String(router.password || ""),
    port: Number(router.port || 8728),
    timeout: 10,
  });

  await api.connect();
  try {
    return await handler(api);
  } finally {
    api.close();
  }
}

function printContext(client, router, queue) {
  console.log("Target Client:");
  console.log(`  Name: ${client.name || TARGET_CLIENT.name}`);
  console.log(`  Type: ${client.type || "Unknown"}`);
  console.log(`  IP: ${client.ipAddress || TARGET_CLIENT.ipAddress}`);
  console.log(`  MAC: ${client.macAddress || TARGET_CLIENT.macAddress}`);
  console.log("Router:");
  console.log(`  Name: ${router.name || "Unknown"}`);
  console.log(`  Host: ${router.host || "Unknown"}:${router.port || 8728}`);
  console.log("Queue:");
  console.log(`  ID: ${queue[".id"] || "Unknown"}`);
  console.log(`  Name: ${queue.name || "Unknown"}`);
  console.log(`  Target: ${queue.target || "Unknown"}`);
  console.log(`  Current max-limit: ${queue["max-limit"] || "(empty)"}`);
}

async function setClientSpeedForTarget(mbps, options = {}) {
  const dryRun = Boolean(options.dryRun);

  if (!Number.isFinite(mbps) || mbps <= 0) {
    throw new Error("Invalid Mbps value.");
  }

  loadEnv();

  let ctx;
  try {
    ctx = await resolveClientAndRouter();
    const { client, router } = ctx;

    const result = await withRouterConnection(router, async (api) => {
      const queue = await findQueueForClient(api, client);
      printContext(client, router, queue);

      const backupStore = readBackupStore();
      const backupKey = makeBackupKey(router, client);

      if (!backupStore[backupKey]) {
        backupStore[backupKey] = {
          createdAt: new Date().toISOString(),
          client: {
            name: client.name || "",
            ipAddress: client.ipAddress || "",
            macAddress: client.macAddress || "",
            type: client.type || "",
          },
          router: {
            id: router._id ? String(router._id) : "",
            name: router.name || "",
            host: router.host || "",
            port: Number(router.port || 8728),
          },
          original: makeQueueSnapshot(queue),
          history: [],
        };
        console.log(`Backup created at ${BACKUP_FILE}`);
      } else {
        console.log("Backup already exists. Original baseline preserved.");
      }

      const nextMaxLimit = `${mbps}M/${mbps}M`;
      if (dryRun) {
        console.log(`[DRY RUN] Would set max-limit to ${nextMaxLimit}`);
      } else {
        await api.write("/queue/simple/set", [
          `=.id=${queue[".id"]}`,
          `=max-limit=${nextMaxLimit}`,
        ]);
        console.log(`Applied max-limit: ${nextMaxLimit}`);
      }

      backupStore[backupKey].history.push({
        at: new Date().toISOString(),
        action: "set",
        maxLimit: nextMaxLimit,
        dryRun,
      });
      writeBackupStore(backupStore);

      const refreshedQueue = await findQueueForClient(api, client);
      return {
        queueId: refreshedQueue[".id"],
        maxLimit: refreshedQueue["max-limit"] || "",
      };
    });

    console.log("Final queue state:");
    console.log(`  ID: ${result.queueId || "Unknown"}`);
    console.log(`  max-limit: ${result.maxLimit || "(empty)"}`);
  } finally {
    await mongoose.disconnect().catch(() => undefined);
  }
}

async function revertClientSpeedForTarget(options = {}) {
  const dryRun = Boolean(options.dryRun);

  loadEnv();

  let ctx;
  try {
    ctx = await resolveClientAndRouter();
    const { client, router } = ctx;

    const backupStore = readBackupStore();
    const backupKey = makeBackupKey(router, client);
    const backup = backupStore[backupKey];

    if (!backup || !backup.original || !backup.original.maxLimit) {
      throw new Error(
        `No backup found for ${client.ipAddress}. Run a set-speed script first.`,
      );
    }

    const originalMaxLimit = String(backup.original.maxLimit);

    const result = await withRouterConnection(router, async (api) => {
      const queue = await findQueueForClient(api, client);
      printContext(client, router, queue);

      if (dryRun) {
        console.log(`[DRY RUN] Would revert max-limit to ${originalMaxLimit}`);
      } else {
        await api.write("/queue/simple/set", [
          `=.id=${queue[".id"]}`,
          `=max-limit=${originalMaxLimit}`,
        ]);
        console.log(`Reverted max-limit to: ${originalMaxLimit}`);
      }

      backupStore[backupKey].history.push({
        at: new Date().toISOString(),
        action: "revert",
        maxLimit: originalMaxLimit,
        dryRun,
      });
      backupStore[backupKey].lastRevertedAt = new Date().toISOString();
      writeBackupStore(backupStore);

      const refreshedQueue = await findQueueForClient(api, client);
      return {
        queueId: refreshedQueue[".id"],
        maxLimit: refreshedQueue["max-limit"] || "",
      };
    });

    console.log("Final queue state:");
    console.log(`  ID: ${result.queueId || "Unknown"}`);
    console.log(`  max-limit: ${result.maxLimit || "(empty)"}`);
  } finally {
    await mongoose.disconnect().catch(() => undefined);
  }
}

module.exports = {
  TARGET_CLIENT,
  setClientSpeedForTarget,
  revertClientSpeedForTarget,
};
