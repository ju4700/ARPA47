const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');

function loadEnv() {
  const p = path.join(process.cwd(), '..', '.env');
  const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf('=');
    if (idx < 0) continue;
    process.env[line.slice(0, idx).trim()] = line.slice(idx + 1).replace(/["']/g, '').trim();
  }
}

(async () => {
  try {
    loadEnv();
    await mongoose.connect(process.env.MONGODB_URI);
    const collections = await mongoose.connection.db.listCollections().toArray();
    console.log(collections.map(c => c.name));
    process.exit(0);
  } catch(e) {
    console.error(e.message);
    process.exit(1);
  }
})();
