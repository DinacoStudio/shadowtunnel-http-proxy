import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {
  generateEphemeralKeys, computeSharedSecret, deriveKey, encrypt, decrypt,
  signData, PacketParser, MSG_HANDSHAKE, MSG_DATA
} from './crypto.mjs';

const PORT = 1234;
const serverPrivKey = crypto.createPrivateKey(fs.readFileSync('./server_identity'));

const server = net.createServer((socket) => {
  const { publicKey: sPub, privateKey: sPriv } = generateEphemeralKeys();
  let sharedKey, sSeq = 0n, rSeq = 0n, handshakeDone = false;

  const rawPub = sPub.export({ type: 'spki', format: 'der' });
  const pubLenBuf = Buffer.alloc(2);
  pubLenBuf.writeUInt16BE(rawPub.length);
  const sig = signData(rawPub, serverPrivKey);
  const payload = Buffer.concat([pubLenBuf, rawPub, sig]);

  const header = Buffer.alloc(5);
  header.writeUInt32BE(payload.length, 0);
  header.writeUInt8(MSG_HANDSHAKE, 4);
  socket.write(Buffer.concat([header, payload]));

  const parser = new PacketParser((type, data) => {
    if (type === MSG_HANDSHAKE && !handshakeDone) {
      const cPub = crypto.createPublicKey({ key: data, type: 'spki', format: 'der' });
      sharedKey = deriveKey(computeSharedSecret(sPriv, cPub));
      handshakeDone = true;
      console.error('Канал защищен.');
    } else if (type === MSG_DATA && handshakeDone) {
      try {
        const msg = decrypt(data, sharedKey, rSeq++);
        process.stdout.write(msg.toString());
      } catch (e) { socket.destroy(); }
    }
  });

  socket.on('data', (d) => parser.add(d, socket));
  socket.on('error', (err) => console.error(`Socker error: ${err}`))
  process.stdin.on('data', (d) => {
    if (handshakeDone) {
      const enc = encrypt(d, sharedKey, sSeq++);
      const h = Buffer.alloc(5);
      h.writeUInt32BE(enc.length, 0);
      h.writeUInt8(MSG_DATA, 4);
      socket.write(Buffer.concat([h, enc]));
    }
  });
});

server.listen(PORT, () => console.error(`Сервер запущен на ${PORT} порту`));