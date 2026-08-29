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
['.env', '.env.local'].forEach(file => {
const p = path.join(process.cwd(), file);


if (!fs.existsSync(p)) return;

fs.readFileSync(p, 'utf8')
  .split(/\r?\n/)
  .forEach(line => {
    const idx = line.indexOf('=');

    if (idx < 0) return;

    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();

    if (!process.env[key]) {
      process.env[key] = value;
    }
  });

});
}

function decryptPassword(cipheredText) {
const keyStr = process.env.ENCRYPTION_KEY;

const data = Buffer.from(cipheredText, 'base64');

const salt = data.subarray(0, SALT_LENGTH);

const iv = data.subarray(
SALT_LENGTH,
SALT_LENGTH + IV_LENGTH
);

const tag = data.subarray(
SALT_LENGTH + IV_LENGTH,
SALT_LENGTH + IV_LENGTH + TAG_LENGTH
);

const encrypted = data.subarray(
SALT_LENGTH + IV_LENGTH + TAG_LENGTH
);

const key = crypto.pbkdf2Sync(
keyStr,
salt,
ITERATIONS,
KEY_LENGTH,
'sha256'
);

const decipher = crypto.createDecipheriv(
ALGORITHM,
key,
iv
);

decipher.setAuthTag(tag);

return (
decipher.update(encrypted) +
decipher.final('utf8')
);
}

(async () => {
let api;

try {
loadEnv();

await mongoose.connect(
  process.env.MONGODB_URI
);

const router =
  await mongoose.connection
    .collection('routers')
    .findOne({ name: 'earth' });

api = new RouterOSAPI({
  host: router.host,
  user: router.username,
  password: decryptPassword(router.password),
  port: Number(router.port || 8728)
});

await api.connect();

console.log('\n====================================');
console.log('MIKROTIK FLOW + HONEYPOT DIAGNOSTICS');
console.log('====================================\n');

console.log('\n=== TRAFFIC FLOW ===\n');

const trafficFlow =
  await api.write('/ip/traffic-flow/print');

console.log(
  JSON.stringify(trafficFlow, null, 2)
);

console.log('\n=== TRAFFIC FLOW TARGETS ===\n');

const targets =
  await api.write('/ip/traffic-flow/target/print');

console.log(
  JSON.stringify(targets, null, 2)
);

try {
  console.log('\n=== TRAFFIC FLOW INTERFACES ===\n');

  const interfaces =
    await api.write('/ip/traffic-flow/interface/print');

  console.log(
    JSON.stringify(interfaces, null, 2)
  );
} catch (e) {
  console.log(
    'Traffic-flow interface menu not available on this RouterOS version'
  );
}

console.log('\n=== HONEYPOT ADDRESS ===\n');

const addresses =
  await api.write('/ip/address/print');

const hpAddresses =
  addresses.filter(a =>
    (a.address || '').includes('103.148.176.62')
  );

console.log(
  JSON.stringify(hpAddresses, null, 2)
);

console.log('\n=== HONEYPOT FIREWALL RULES ===\n');

const filters =
  await api.write('/ip/firewall/filter/print');

const hpRules =
  filters.filter(r =>
    (r.comment || '')
      .toLowerCase()
      .includes('honeypot')
  );

console.log(
  JSON.stringify(hpRules, null, 2)
);

console.log('\n=== HONEYPOT RULE DETAILS ===\n');

const hpRule = filters.find(
  r =>
    r.chain === 'input' &&
    r['dst-address'] === '103.148.176.62'
);

console.log(
  JSON.stringify(hpRule, null, 2)
);

console.log('\n=== RECENT HONEYPOT LOGS ===\n');

const logs =
  await api.write('/log/print');

const hpLogs =
  logs.filter(l =>
    JSON.stringify(l)
      .toLowerCase()
      .includes('honeypot')
  );

console.log(
  JSON.stringify(
    hpLogs.slice(-20),
    null,
    2
  )
);

console.log('\n=== GENERATING TEST LOG ===\n');

const testId = Date.now();

await api.write('/log/warning', [
  `=message=FLOW_DEBUG_${testId}`
]);

console.log(
  `Generated test log FLOW_DEBUG_${testId}`
);

console.log(
  '\nNow check Fedora collector:\n'
);

console.log(
  'sudo tcpdump -ni any udp port 2055'
);

console.log(
  'sudo tcpdump -ni any udp port 514'
);

console.log(
  '\nAlso test from Windows:\n'
);

console.log(
  'curl http://103.148.176.62'
);

console.log(
  'telnet 103.148.176.62 22'
);

console.log(
  'curl http://103.148.176.62:8080'
);

await api.close();
await mongoose.disconnect();


} catch (err) {
console.error(err);


try {
  if (api) await api.close();
} catch {}

try {
  await mongoose.disconnect();
} catch {}

}
})();
