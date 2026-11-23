#!/usr/bin/env node
/**
 * CLI Entrypoint: `uor-verify-offline` (`host/verifier-offline/src/cli.mjs`)
 *
 * Verifies a DSSE v1.0 / in-toto v1 Blind Notary receipt bundle completely offline
 * (zero network access, WT-04, TC-05, TC-06).
 */

import fs from 'node:fs';
import { verifyOfflineReceiptBundle } from './index.mjs';

function printUsage() {
  console.error(
    'Usage: uor-verify-offline --bundle <receipt-bundle.json> [--holo <Notary.holo>]'
  );
}

function main() {
  const args = process.argv.slice(2);
  let bundlePath = null;
  let holoPath = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--bundle' && i + 1 < args.length) {
      bundlePath = args[++i];
    } else if (args[i] === '--holo' && i + 1 < args.length) {
      holoPath = args[++i];
    } else if (args[i] === '--help' || args[i] === '-h') {
      printUsage();
      process.exit(0);
    }
  }

  if (!bundlePath) {
    printUsage();
    process.exit(2);
  }

  const rawBundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
  if (holoPath) {
    rawBundle.holoBase64 = fs.readFileSync(holoPath).toString('base64');
  }

  const report = verifyOfflineReceiptBundle(rawBundle);
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.verified ? 0 : 1);
}

main();
