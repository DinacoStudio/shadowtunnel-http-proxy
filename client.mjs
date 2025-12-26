import net from "node:net";
import fs from "node:fs";
import crypto from "node:crypto";

import {
  generateEphemeralKeys,
  computeSharedSecret,
  deriveKey,
  encrypt,
  decrypt,
  verifyData,
  PacketParser,
  MSG_HANDSHAKE,
  MSG_DATA,
} from "./crypto.mjs";

const HOST = "0.0.0.0";
const PORT = 1234;

const LOCAL_PROXY_PORT = 8081;

const OP_OPEN = 0x01;
const OP_DATA = 0x02;
const OP_CLOSE = 0x03;
const OP_OPEN_OK = 0x04;
const OP_OPEN_ERR = 0x05;

const serverPubKey = crypto.createPublicKey(
  fs.readFileSync("./server_identity.pub")
);

function makeFrame(op, connId, payload = Buffer.alloc(0)) {
  const b = Buffer.alloc(1 + 4);
  b.writeUInt8(op, 0);
  b.writeUInt32BE(connId >>> 0, 1);
  return Buffer.concat([b, payload]);
}

const tunnelSocket = new net.Socket();
const { publicKey: cPub, privateKey: cPriv } = generateEphemeralKeys();

let sharedKey = null;
let sSeq = 0n;
let rSeq = 0n;
let handshakeDone = false;

const pendingSend = [];

const clientSockets = new Map();
const pendingOpen = new Map();

function sendEncrypted(plainBuf) {
  if (!handshakeDone) {
    pendingSend.push(plainBuf);
    return;
  }
  const enc = encrypt(plainBuf, sharedKey, sSeq++);
  const h = Buffer.alloc(5);
  h.writeUInt32BE(enc.length, 0);
  h.writeUInt8(MSG_DATA, 4);
  tunnelSocket.write(Buffer.concat([h, enc]));
}

function sendOp(op, connId, payload = Buffer.alloc(0)) {
  sendEncrypted(makeFrame(op, connId, payload));
}

function genConnId() {
  return crypto.randomBytes(4).readUInt32BE(0) >>> 0;
}

function readHeadersOnce(socket) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);

    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf("\r\n\r\n");
      if (idx === -1) return;
      socket.off("data", onData);
      const head = buf.subarray(0, idx + 4);
      const rest = buf.subarray(idx + 4);
      resolve({ head, rest });
    }

    socket.on("data", onData);
    socket.once("error", reject);
    socket.once("end", () => reject(new Error("Client closed before headers")));
  });
}

function parseHeaders(headBuf) {
  const s = headBuf.toString("latin1");
  const lines = s.split("\r\n");

  const requestLine = lines[0] || "";
  const [method, rawUrl, version] = requestLine.split(" ");

  const headers = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const j = line.indexOf(":");
    if (j === -1) continue;
    const name = line.slice(0, j).trim();
    const value = line.slice(j + 1).trim();
    headers.push([name, value]);
  }

  return { method, rawUrl, version, headers };
}

function getHeader(headers, nameLower) {
  for (const [k, v] of headers) {
    if (k.toLowerCase() === nameLower) return v;
  }
  return null;
}

function buildHttpForwardRequest(method, rawUrl, version, headers) {
  let targetHost = null;
  let targetPort = 80;
  let path = rawUrl;

  if (rawUrl && rawUrl.startsWith("http://")) {
    const u = new URL(rawUrl);
    targetHost = u.hostname;
    targetPort = u.port ? Number(u.port) : 80;
    path = (u.pathname || "/") + (u.search || "");
  } else {
    const hostHeader = getHeader(headers, "host");
    if (!hostHeader) throw new Error("No Host header");
    const hh = hostHeader.trim();
    const idx = hh.lastIndexOf(":");
    if (idx > 0 && /^\d+$/.test(hh.slice(idx + 1))) {
      targetHost = hh.slice(0, idx);
      targetPort = Number(hh.slice(idx + 1));
    } else {
      targetHost = hh;
      targetPort = 80;
    }
    path = rawUrl || "/";
  }

  const outHeaders = [];
  let hasHost = false;

  for (const [k, v] of headers) {
    const kl = k.toLowerCase();
    if (kl === "proxy-connection") continue;
    if (kl === "connection") continue;
    if (kl === "keep-alive") continue;
    if (kl === "host") hasHost = true;
    outHeaders.push([k, v]);
  }

  if (!hasHost) {
    outHeaders.push([
      "Host",
      targetPort === 80 ? targetHost : `${targetHost}:${targetPort}`,
    ]);
  }

  outHeaders.push(["Connection", "close"]);

  const reqLine = `${method} ${path} ${version || "HTTP/1.1"}`;
  const headerStr = outHeaders.map(([k, v]) => `${k}: ${v}`).join("\r\n");
  const full = `${reqLine}\r\n${headerStr}\r\n\r\n`;

  return {
    targetHost,
    targetPort,
    bytes: Buffer.from(full, "latin1"),
  };
}

function parseConnectTarget(headBuf) {
  const head = headBuf.toString("latin1");
  const firstLine = head.split("\r\n")[0] || "";
  const [method, target] = firstLine.split(" ");
  if (method !== "CONNECT" || !target) return null;
  return target.trim();
}

const parser = new PacketParser((type, data) => {
  if (type === MSG_HANDSHAKE && !handshakeDone) {
    const pubLen = data.readUInt16BE(0);
    const sPubDer = data.subarray(2, 2 + pubLen);
    const sig = data.subarray(2 + pubLen);

    if (!verifyData(sPubDer, sig, serverPubKey)) {
      tunnelSocket.destroy();
      return;
    }

    const sKeyObj = crypto.createPublicKey({
      key: sPubDer,
      type: "spki",
      format: "der",
    });

    sharedKey = deriveKey(computeSharedSecret(cPriv, sKeyObj));

    const myPubDer = cPub.export({ type: "spki", format: "der" });
    const h = Buffer.alloc(5);
    h.writeUInt32BE(myPubDer.length, 0);
    h.writeUInt8(MSG_HANDSHAKE, 4);
    tunnelSocket.write(Buffer.concat([h, myPubDer]));

    handshakeDone = true;
    console.error("Личность подтверждена.");

    while (pendingSend.length) sendEncrypted(pendingSend.shift());
    return;
  }

  if (type !== MSG_DATA || !handshakeDone) return;

  let msg;
  try {
    msg = decrypt(data, sharedKey, rSeq++);
  } catch (e) {
    console.error("Error decrypting data:", e);
    tunnelSocket.destroy();
    return;
  }

  if (msg.length < 5) return;
  const op = msg.readUInt8(0);
  const connId = msg.readUInt32BE(1);
  const payload = msg.subarray(5);

  if (op === OP_OPEN_OK) {
    const p = pendingOpen.get(connId);
    if (p) {
      pendingOpen.delete(connId);
      p.resolve();
    }
    return;
  }

  if (op === OP_OPEN_ERR) {
    const p = pendingOpen.get(connId);
    if (p) {
      pendingOpen.delete(connId);
      p.reject(new Error(payload.toString("utf8") || "Open failed"));
    }
    const s = clientSockets.get(connId);
    if (s) s.destroy();
    clientSockets.delete(connId);
    return;
  }

  if (op === OP_DATA) {
    const s = clientSockets.get(connId);
    if (!s) return;
    s.write(payload);
    return;
  }

  if (op === OP_CLOSE) {
    const s = clientSockets.get(connId);
    if (s) s.end();
    clientSockets.delete(connId);
    return;
  }
});

tunnelSocket.on("data", (d) => parser.add(d));
tunnelSocket.on("error", (e) => console.error("Tunnel error:", e));
tunnelSocket.on("close", () => {
  for (const [, s] of clientSockets) {
    try {
      s.destroy();
    } catch {}
  }
  clientSockets.clear();
});

tunnelSocket.connect(PORT, HOST, () => {
  console.error("Подключение к туннелю...");
});

const proxyServer = net.createServer(async (clientSocket) => {
  clientSocket.setNoDelay(true);

  const connId = genConnId();
  clientSockets.set(connId, clientSocket);

  const kill = () => {
    if (clientSockets.has(connId)) {
      clientSockets.delete(connId);
      try {
        sendOp(OP_CLOSE, connId);
      } catch {}
    }
    try {
      clientSocket.destroy();
    } catch {}
  };

  try {
    const { head, rest } = await readHeadersOnce(clientSocket);

    const connectTarget = parseConnectTarget(head);
    if (connectTarget) {
      await new Promise((resolve, reject) => {
        pendingOpen.set(connId, { resolve, reject });
        sendOp(OP_OPEN, connId, Buffer.from(connectTarget, "utf8"));
      });

      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

      if (rest.length) sendOp(OP_DATA, connId, rest);

      clientSocket.on("data", (chunk) => sendOp(OP_DATA, connId, chunk));
      clientSocket.on("close", () => {
        if (clientSockets.has(connId)) {
          clientSockets.delete(connId);
          sendOp(OP_CLOSE, connId);
        }
      });
      clientSocket.on("error", kill);
      return;
    }

    const { method, rawUrl, version, headers } = parseHeaders(head);

    if (!method || !rawUrl) {
      clientSocket.write(
        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
      );
      clientSocket.end();
      return;
    }

    const fwd = buildHttpForwardRequest(method, rawUrl, version, headers);
    const target = `${fwd.targetHost}:${fwd.targetPort}`;

    await new Promise((resolve, reject) => {
      pendingOpen.set(connId, { resolve, reject });
      sendOp(OP_OPEN, connId, Buffer.from(target, "utf8"));
    });

    sendOp(OP_DATA, connId, fwd.bytes);
    if (rest.length) sendOp(OP_DATA, connId, rest);

    clientSocket.on("data", (chunk) => sendOp(OP_DATA, connId, chunk));

    clientSocket.on("close", () => {
      if (clientSockets.has(connId)) {
        clientSockets.delete(connId);
        sendOp(OP_CLOSE, connId);
      }
    });
    clientSocket.on("error", kill);
  } catch (e) {
    try {
      clientSocket.write(
        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
      );
    } catch {}
    kill();
  }
});

proxyServer.listen(LOCAL_PROXY_PORT, () => {
  console.error(`Local proxy запущен на порту ${LOCAL_PROXY_PORT}`);
  console.error(`Configure browser proxy: 127.0.0.1:${LOCAL_PROXY_PORT}`);
});
