#!/usr/bin/env node
/**
 * Print relay TLS SPKI SHA-256 for out-of-band verification (**M4.21**).
 *
 *   node demo/proxy/relay-tls-spki.mjs --cert ./relay-fullchain.pem
 *   node demo/proxy/relay-tls-spki.mjs --host relay.example.com --port 443
 */

import {
  spkiSha256HexFromCertFile,
  spkiSha256HexFromTlsHost,
} from "./relay-spki.mjs";

function usage() {
  console.error(
    "usage:\n" +
      "  node demo/proxy/relay-tls-spki.mjs --cert PATH\n" +
      "  node demo/proxy/relay-tls-spki.mjs --host HOST [--port 443]\n",
  );
  process.exit(2);
}

const args = process.argv.slice(2);
let cert;
let host;
let port = 443;

for (let i = 0; i < args.length; i += 1) {
  const a = args[i];
  if (a === "--cert" && args[i + 1]) {
    cert = args[++i];
  } else if (a === "--host" && args[i + 1]) {
    host = args[++i];
  } else if (a === "--port" && args[i + 1]) {
    port = Number(args[++i]);
  } else if (a === "-h" || a === "--help") {
    usage();
  } else {
    console.error(`unknown argument: ${a}`);
    usage();
  }
}

async function main() {
  let hex;
  if (cert) {
    hex = spkiSha256HexFromCertFile(cert);
    console.log(`spki_sha256=${hex}`);
    console.log(`source=cert file ${cert}`);
    return;
  }
  if (host) {
    hex = await spkiSha256HexFromTlsHost(host, port);
    console.log(`spki_sha256=${hex}`);
    console.log(`source=tls://${host}:${port}`);
    return;
  }
  usage();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
