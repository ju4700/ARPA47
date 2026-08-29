#!/usr/bin/env node

const { revertClientSpeedForTarget } = require("./_client-speed-common");

const dryRun = process.argv.includes("--dry-run");

revertClientSpeedForTarget({ dryRun })
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("Failed to revert client speed:", error.message || error);
    process.exit(1);
  });
