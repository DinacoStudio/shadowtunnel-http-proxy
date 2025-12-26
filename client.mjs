import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { 
  generateEphemeralKeys, computeSharedSecret, deriveKey, encrypt, decrypt, 
  verifyData, PacketParser, MSG_HANDSHAKE, MSG_DATA 
} from './crypto.mjs';

const HOST = 'localhost'; // Убедись, что это IP сервера
const PORT = 1234;
const serverPubKey = crypto.createPublicKey(fs.readFileSync('./server_identity.pub'));

const client = new net.Socket();
const { publicKey: cPub, privateKey: cPriv } = generateEphemeralKeys();
let sharedKey, sSeq = 0n, rSeq = 0n, handshakeDone = false;

const parser = new PacketParser((type, data) => {
  if (type === MSG_HANDSHAKE && !handshakeDone) {
    const pubLen = data.readUInt16BE(0);
    const sPubDer = data.subarray(2, 2 + pubLen);
    const sig = data.subarray(2 + pubLen);

    if (!verifyData(sPubDer, sig, serverPubKey)) return client.destroy();

    const sKeyObj = crypto.createPublicKey({ key: sPubDer, type: 'spki', format: 'der' });
    sharedKey = deriveKey(computeSharedSecret(cPriv, sKeyObj));

    const myPubDer = cPub.export({ type: 'spki', format: 'der' });
    const h = Buffer.alloc(5);
    h.writeUInt32BE(myPubDer.length, 0);
    h.writeUInt8(MSG_HANDSHAKE, 4);
    client.write(Buffer.concat([h, myPubDer]));
    handshakeDone = true;
    console.error('Личность подтверждена.');
  } else if (type === MSG_DATA && handshakeDone) {
    try {
      const msg = decrypt(data, sharedKey, rSeq++);
      process.stdout.write(msg.toString());
    } catch (e) { client.destroy(); }
  }
});

client.connect(PORT, HOST, () => console.error('Подключение...'));
client.on('data', (d) => parser.add(d, client));
process.stdin.on('data', (d) => {
  if (handshakeDone) {
    const enc = encrypt(d, sharedKey, sSeq++);
    const h = Buffer.alloc(5);
    h.writeUInt32BE(enc.length, 0);
    h.writeUInt8(MSG_DATA, 4);
    client.write(Buffer.concat([h, enc]));
  }
});