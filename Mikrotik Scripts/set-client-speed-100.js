#!/usr/bin/env node

const { setClientSpeedForTarget } = require("./_client-speed-common");

const dryRun = process.argv.includes("--dry-run");

setClientSpeedForTarget(100, { dryRun })
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("Failed to set client speed to 100Mbps:", error.message || error);
    process.exit(1);
  });
