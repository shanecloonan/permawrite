#!/usr/bin/env node
/**
 * Dev-only HTTP → TCP bridge for `mfnd serve` newline JSON-RPC (M4.1).
 *
 *   MFND_RPC=127.0.0.1:18731 node demo/proxy/rpc-proxy.mjs
 *   # listens on http://127.0.0.1:8787/rpc
 */

import http from "node:http";
import net from "node:net";

const MFND_RPC = process.env.MFND_RPC ?? "127.0.0.1:18731";
const LISTEN_HOST = process.env.PROXY_HOST ?? "127.0.0.1";
const LISTEN_PORT = Number(process.env.PROXY_PORT ?? "8787");

const [mfndHost, mfndPortStr] = MFND_RPC.split(":");
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

  if (req.url === "/p2p/light-follow" && req.method === "POST") {
    try {
      const body = await readBody(req);
      const params = JSON.parse(body);
      const rpcLine = JSON.stringify({
        jsonrpc: "2.0",
        method: "get_light_follow_p2p",
        params,
        id: 1,
      });
      const line = await tcpLineRpc(rpcLine);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(`${line}\n`);
    } catch (e) {
      res.writeHead(502, { "Content-Type": "text/plain" });
      res.end(String(e));
    }
    return;
  }

  if (req.url !== "/rpc" || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end(
      "POST /rpc with JSON-RPC body\nPOST /p2p/light-follow with {peer,from_height,to_height}\n",
    );
    return;
  }

  try {
    const body = await readBody(req);
    const line = await tcpLineRpc(body);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(`${line}\n`);
  } catch (e) {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(String(e));
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `mfnd rpc proxy http://${LISTEN_HOST}:${LISTEN_PORT}/rpc (+ /p2p/light-follow) -> tcp://${MFND_RPC}`,
  );
});
