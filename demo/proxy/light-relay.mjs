#!/usr/bin/env node
/**
 * Dedicated light-client relay (**M4.16**).
 *
 * Browsers POST evolution batches here; the relay calls `get_light_follow_quorum_p2p`
 * on a backend `mfnd` (which dials P2P peers). The wallet's balance-scanning RPC node
 * can differ from `RELAY_RPC`.
 *
 *   RELAY_RPC=127.0.0.1:18731 node demo/proxy/light-relay.mjs
 *   # POST http://127.0.0.1:8790/light-follow
 *   # {"peers":["127.0.0.1:18732","127.0.0.1:18733"],"from_height":1,"to_height":10}
 */

import http from "node:http";
import net from "node:net";

const RELAY_RPC = process.env.RELAY_RPC ?? "127.0.0.1:18731";
const LISTEN_HOST = process.env.RELAY_HOST ?? "127.0.0.1";
const LISTEN_PORT = Number(process.env.RELAY_PORT ?? "8790");

const [mfndHost, mfndPortStr] = RELAY_RPC.split(":");
const mfndPort = Number(mfndPortStr ?? "18731");

function tcpLineRpc(line) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: mfndHost, port: mfndPort }, () => {
      socket.write(line.endsWith("\n") ? line : `${line}\n`);
    });
    let buf = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buf += chunk;
      if (buf.includes("\n")) {
        socket.end();
        resolve(buf.trim());
      }
    });
    socket.on("error", reject);
    socket.on("end", () => {
      if (buf) resolve(buf.trim());
    });
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url !== "/light-follow" || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("POST /light-follow with {peers,from_height,to_height}\n");
    return;
  }

  try {
    const body = await readBody(req);
    const params = JSON.parse(body);
    const rpcLine = JSON.stringify({
      jsonrpc: "2.0",
      method: "get_light_follow_quorum_p2p",
      params,
      id: 1,
    });
    const line = await tcpLineRpc(rpcLine);
    const msg = JSON.parse(line);
    if (msg.error) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(`${line}\n`);
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(`${JSON.stringify(msg.result)}\n`);
  } catch (e) {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(String(e));
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `light relay http://${LISTEN_HOST}:${LISTEN_PORT}/light-follow -> quorum via tcp://${RELAY_RPC}`,
  );
});
