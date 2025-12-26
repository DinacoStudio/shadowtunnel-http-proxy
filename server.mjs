import net from "node:net";
import http from "node:http";
import fs from "node:fs";
import crypto from "node:crypto";

import {
  generateEphemeralKeys,
  computeSharedSecret,
  deriveKey,
  encrypt,
  decrypt,
  signData,
  PacketParser,
  MSG_HANDSHAKE,
  MSG_DATA,
} from "./crypto.mjs";

const PORT = 1234;
const HTTP_PROXY_PORT = 8080;

const OP_OPEN = 0x01;
const OP_DATA = 0x02;
const OP_CLOSE = 0x03;
const OP_OPEN_OK = 0x04;
const OP_OPEN_ERR = 0x05;

const serverPrivKey = crypto.createPrivateKey(
  fs.readFileSync("./server_identity")
);

function makeFrame(op, connId, payload = Buffer.alloc(0)) {
  const b = Buffer.alloc(1 + 4);
  b.writeUInt8(op, 0);
  b.writeUInt32BE(connId >>> 0, 1);
  return Buffer.concat([b, payload]);
}

const tunnelServer = net.createServer((socket) => {
  const { publicKey: sPub, privateKey: sPriv } = generateEphemeralKeys();

  let sharedKey = null;
  let sSeq = 0n;
  let rSeq = 0n;
  let handshakeDone = false;

  const conns = new Map();

  function sendEncrypted(plainBuf) {
    const enc = encrypt(plainBuf, sharedKey, sSeq++);
    const h = Buffer.alloc(5);
    h.writeUInt32BE(enc.length, 0);
    h.writeUInt8(MSG_DATA, 4);
    socket.write(Buffer.concat([h, enc]));
  }

  function sendOp(op, connId, payload = Buffer.alloc(0)) {
    sendEncrypted(makeFrame(op, connId, payload));
  }

  function closeConn(connId) {
    const t = conns.get(connId);
    if (t) {
      conns.delete(connId);
      try {
        t.destroy();
      } catch {}
    }
  }

  const rawPub = sPub.export({ type: "spki", format: "der" });
  const pubLenBuf = Buffer.alloc(2);
  pubLenBuf.writeUInt16BE(rawPub.length, 0);
  const sig = signData(rawPub, serverPrivKey);
  const payload = Buffer.concat([pubLenBuf, rawPub, sig]);

  const header = Buffer.alloc(5);
  header.writeUInt32BE(payload.length, 0);
  header.writeUInt8(MSG_HANDSHAKE, 4);
  socket.write(Buffer.concat([header, payload]));

  const parser = new PacketParser((type, data) => {
    if (type === MSG_HANDSHAKE && !handshakeDone) {
      const cPub = crypto.createPublicKey({
        key: data,
        type: "spki",
        format: "der",
      });
      sharedKey = deriveKey(computeSharedSecret(sPriv, cPub));
      handshakeDone = true;
      console.error("Канал защищен.");
      return;
    }

    if (type !== MSG_DATA || !handshakeDone) return;

    let msg;
    try {
      msg = decrypt(data, sharedKey, rSeq++);
    } catch (e) {
      console.error("Decrypt failed:", e);
      socket.destroy();
      return;
    }

    if (msg.length < 5) return;
    const op = msg.readUInt8(0);
    const connId = msg.readUInt32BE(1);
    const payload = msg.subarray(5);

    if (op === OP_OPEN) {
      const target = payload.toString("utf8").trim();
      const idx = target.lastIndexOf(":");
      if (idx <= 0) {
        sendOp(OP_OPEN_ERR, connId, Buffer.from("Bad target format"));
        return;
      }

      const host = target.slice(0, idx);
      const port = Number(target.slice(idx + 1));
      if (!Number.isFinite(port) || port <= 0 || port > 65535) {
        sendOp(OP_OPEN_ERR, connId, Buffer.from("Bad port"));
        return;
      }

      if (conns.has(connId)) {
        sendOp(OP_OPEN_ERR, connId, Buffer.from("ConnId already exists"));
        return;
      }

      const targetSocket = net.createConnection(port, host, () => {
        conns.set(connId, targetSocket);
        sendOp(OP_OPEN_OK, connId);
      });

      targetSocket.on("data", (chunk) => {
        sendOp(OP_DATA, connId, chunk);
      });

      targetSocket.on("error", (err) => {
        if (!conns.has(connId)) {
          sendOp(OP_OPEN_ERR, connId, Buffer.from(String(err?.message || err)));
        } else {
          sendOp(OP_CLOSE, connId);
        }
        closeConn(connId);
      });

      targetSocket.on("close", () => {
        if (conns.has(connId)) {
          sendOp(OP_CLOSE, connId);
          closeConn(connId);
        }
      });

      return;
    }

    if (op === OP_DATA) {
      const targetSocket = conns.get(connId);
      if (!targetSocket) return;
      targetSocket.write(payload);
      return;
    }

    if (op === OP_CLOSE) {
      closeConn(connId);
      return;
    }
  });

  socket.on("data", (d) => parser.add(d));
  socket.on("error", (err) => console.error("Tunnel socket error:", err));
  socket.on("close", () => {
    for (const [connId] of conns) closeConn(connId);
  });
});

const httpProxyServer = http.createServer((req, res) => {
  res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Method not allowed - This is a tunnel endpoint");
});

httpProxyServer.on("connect", (req, clientSocket) => {
  clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n", "utf8", () => {
    clientSocket.end();
  });
});

tunnelServer.listen(PORT, () =>
  console.error(`Tunnel server запущен на ${PORT} порту`)
);
httpProxyServer.listen(HTTP_PROXY_PORT, () =>
  console.error(`HTTP proxy запущен на ${HTTP_PROXY_PORT} порту`)
);
