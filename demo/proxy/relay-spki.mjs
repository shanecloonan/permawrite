/**
 * TLS certificate SPKI SHA-256 helpers for light-relay operators (**M4.21**).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import tls from "node:tls";

/**
 * @param {crypto.KeyObject | import("node:crypto").X509Certificate} keyOrCert
 * @returns {string} lowercase hex SHA-256 of SPKI DER
 */
export function spkiSha256HexFromPublicKey(keyOrCert) {
  const key =
    keyOrCert instanceof crypto.X509Certificate
      ? keyOrCert.publicKey
      : keyOrCert;
  const spkiDer = key.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(spkiDer).digest("hex");
}

/**
 * @param {string} pem
 * @returns {string}
 */
export function spkiSha256HexFromCertPem(pem) {
  const cert = new crypto.X509Certificate(pem);
  return spkiSha256HexFromPublicKey(cert);
}

/**
 * @param {string} host
 * @param {number} [port]
 * @param {number} [timeoutMs]
 * @returns {Promise<string>}
 */
export function spkiSha256HexFromTlsHost(host, port = 443, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const x509 = socket.getPeerX509Certificate?.();
          if (!x509) {
            reject(new Error(`no peer certificate from ${host}:${port}`));
            return;
          }
          resolve(spkiSha256HexFromPublicKey(x509));
        } catch (e) {
          reject(e);
        } finally {
          socket.end();
        }
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error(`TLS connect to ${host}:${port} timed out`));
    });
    socket.on("error", reject);
  });
}

/**
 * @param {string} certPath
 * @returns {string}
 */
export function spkiSha256HexFromCertFile(certPath) {
  const pem = fs.readFileSync(certPath, "utf8");
  return spkiSha256HexFromCertPem(pem);
}
