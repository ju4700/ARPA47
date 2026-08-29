const { Telnet } = require('telnet-client');

const BASE_URL = 'http://localhost:3000';
const AUTH_EMAIL = 'admin@linkup.online';
const AUTH_PASSWORD = 'luc4700';

const PROMPT_WAIT = /(?:Switch|[A-Za-z0-9_.-]+)[>#]\s*$/m;

function normalizeMac(value) {
  return String(value || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

function formatMacColon(normalized) {
  return normalized.match(/.{1,2}/g)?.join(':') || normalized;
}

async function loginAndGetCookie() {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: AUTH_EMAIL, password: AUTH_PASSWORD }),
  });

  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) {
    throw new Error('Login did not return session cookie');
  }

  return setCookie.split(';')[0];
}

async function apiGet(path, cookie) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'GET',
    headers: { Cookie: cookie },
    cache: 'no-store',
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Non-JSON response for ${path}: ${text.slice(0, 200)}`);
  }

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for ${path}: ${JSON.stringify(json)}`);
  }

  return json;
}

async function connectTelnet(host) {
  const telnet = new Telnet();
  await telnet.connect({
    host,
    port: 23,
    timeout: 10000,
    disableLogon: true,
    negotiationMandatory: true,
    shellPrompt: null,
    irs: '\r\n',
    ors: '\r\n',
    stripControls: true,
    echoLines: 0,
    sendTimeout: 10000,
    pageSeparator: /--More--/,
  });

  await telnet.nextData();
  const afterUser = String(await telnet.send('admin', {
    waitFor: /Username[: ]*|Password[: ]*$/i,
    timeout: 10000,
  }));

  if (/Password[: ]*$/i.test(afterUser)) {
    await telnet.send('admin', { waitFor: PROMPT_WAIT, timeout: 12000 });
  } else {
    await telnet.send('admin', { waitFor: /Password[: ]*$/i, timeout: 10000 });
    await telnet.send('admin', { waitFor: PROMPT_WAIT, timeout: 12000 });
  }

  await telnet.send('enable', { waitFor: PROMPT_WAIT, timeout: 8000 });
  await telnet.send('terminal length 0', { waitFor: PROMPT_WAIT, timeout: 8000 });

  return telnet;
}

async function runCommand(telnet, command, timeout = 25000) {
  return String(await telnet.send(command, { waitFor: PROMPT_WAIT, timeout }));
}

function parseMacTotal(text) {
  const m = String(text || '').match(/Total\s+MAC\s+address\s*:\s*(\d+)/i);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

function parseMacEntries(text) {
  const lines = String(text || '').split(/\r?\n/);
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

    let onuPort = null;
    let onuId = null;
    if (interfaceName) {
      const eponMatch = interfaceName.toLowerCase().match(/(?:epon|gpon)(\d+)\/(\d+)(?::(\d+))?/);
      if (eponMatch) {
        onuPort = `${Number(eponMatch[1])}/${Number(eponMatch[2])}`;
        onuId = eponMatch[3] ? String(Number(eponMatch[3])) : null;
      }
    }

    entries.push({
      mac: formatMacColon(normalized),
      normalized,
      interface: interfaceName,
      onuPort,
      onuId,
      raw: line,
    });
  }

  return entries;
}

function chooseEponMac(entries) {
  return entries.find((item) => item.onuPort && item.onuId) || null;
}

function uniqueByNormalized(entries) {
  const map = new Map();
  for (const entry of entries) {
    if (!map.has(entry.normalized)) map.set(entry.normalized, entry);
  }
  return [...map.values()];
}

async function validateHost(host, routerId, cookie) {
  const telnet = await connectTelnet(host);
  try {
    const cpuOut = await runCommand(telnet, 'show cpu', 12000);
    const statusOut = await runCommand(telnet, 'show epon onu-status-count', 18000);
    const macBrief = await runCommand(telnet, 'show mac address-table brief | include Total', 18000);
    const macTable = await runCommand(telnet, 'show mac address-table', 30000);

    const directCpu = (() => {
      const m = cpuOut.match(/CPU\s+utilization\s+for\s+one\s+second:\s*(\d+(?:\.\d+)?)%/i);
      if (!m) return null;
      const n = Number(m[1]);
      return Number.isFinite(n) ? n : null;
    })();

    const directRegistered = (() => {
      const m = statusOut.match(/Registered:\s*(\d+)/i);
      const n = m ? Number(m[1]) : 0;
      return Number.isFinite(n) ? n : 0;
    })();
    const directAutoConfigured = (() => {
      const m = statusOut.match(/Auto-configured:\s*(\d+)/i);
      const n = m ? Number(m[1]) : 0;
      return Number.isFinite(n) ? n : 0;
    })();
    const directDeregistered = (() => {
      const m = statusOut.match(/Deregistered:\s*(\d+)/i);
      const n = m ? Number(m[1]) : 0;
      return Number.isFinite(n) ? n : 0;
    })();

    const directMacTotal = parseMacTotal(macBrief);
    const allEntries = uniqueByNormalized(parseMacEntries(macTable));
    const eponEntries = allEntries.filter((item) => item.onuPort && item.onuId);
    const sample = chooseEponMac(allEntries);

    const apiBase = await apiGet(`/api/olt-details?routerId=${encodeURIComponent(routerId)}&onuPort=0/9&onuId=1`, cookie);
    if (!apiBase.success) {
      throw new Error(`API base failed for ${host}: ${JSON.stringify(apiBase)}`);
    }

    const sampleChecks = [];
    if (sample) {
      const fullColon = sample.mac;
      const dotted = `${sample.normalized.slice(0,4)}.${sample.normalized.slice(4,8)}.${sample.normalized.slice(8)}`;
      const compact = sample.normalized;
      const partial = sample.normalized.slice(0, 8);
      const wildcard = `${sample.normalized.slice(0,2)}:${sample.normalized.slice(2,4)}:${sample.normalized.slice(4,6)}:as`;

      const queries = [
        { label: 'full-colon', value: fullColon },
        { label: 'dotted', value: dotted },
        { label: 'compact', value: compact },
        { label: 'partial', value: partial },
        { label: 'wildcard-style', value: wildcard },
      ];

      for (const query of queries) {
        const apiSearch = await apiGet(
          `/api/olt-details?routerId=${encodeURIComponent(routerId)}&onuPort=0/9&onuId=1&searchMac=${encodeURIComponent(query.value)}`,
          cookie,
        );

        const result = apiSearch?.data?.macSearch;
        const matches = Array.isArray(result?.matches) ? result.matches : [];
        const hasTarget = matches.some((item) => normalizeMac(item?.mac) === sample.normalized);

        sampleChecks.push({
          query: query.label,
          value: query.value,
          matchesCount: Number(result?.matchesCount || 0),
          hasTarget,
        });
      }
    }

    return {
      host,
      direct: {
        cpu: directCpu,
        registered: directRegistered,
        autoConfigured: directAutoConfigured,
        deregistered: directDeregistered,
        macTotal: directMacTotal,
        parsedMacEntries: allEntries.length,
        parsedEponMacEntries: eponEntries.length,
        sampleMac: sample ? sample.mac : null,
      },
      api: {
        cpu: apiBase.data.cpuLoadPercent,
        status: apiBase.data.oltStatus,
        registered: apiBase.data.registeredOnuTotal,
        active: apiBase.data.activeOnuTotal,
        inactive: apiBase.data.inactiveOnuTotal,
        macTotal: apiBase.data.macTableTotal,
      },
      searchChecks: sampleChecks,
    };
  } finally {
    try { await telnet.end(); } catch {}
  }
}

(async () => {
  const cookie = await loginAndGetCookie();
  const routers = await apiGet('/api/routers', cookie);
  const olts = (routers.data || []).filter((item) => String(item.deviceType || '').toLowerCase() === 'olt');

  const uniqueHostRouter = new Map();
  for (const olt of olts) {
    if (!uniqueHostRouter.has(olt.host)) uniqueHostRouter.set(olt.host, olt._id);
  }

  const reports = [];
  for (const [host, routerId] of uniqueHostRouter.entries()) {
    const report = await validateHost(host, String(routerId), cookie);
    reports.push(report);
  }

  console.log(JSON.stringify(reports, null, 2));
})();
