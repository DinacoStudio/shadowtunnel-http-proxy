import crypto from "node:crypto";

export const MSG_HANDSHAKE = 0x01;
export const MSG_DATA = 0x02;

export function generateEphemeralKeys() {
  return crypto.generateKeyPairSync("x25519");
}

export function computeSharedSecret(priv, pub) {
  return crypto.diffieHellman({ privateKey: priv, publicKey: pub });
}

export function deriveKey(secret) {
  return crypto.hkdfSync(
    "sha256",
    secret,
    Buffer.alloc(0),
    "shadowtunnel-v1",
    32
  );
}

export function encrypt(messageBuffer, key, sequenceNumber) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(BigInt(sequenceNumber), 0);

  cipher.setAAD(seqBuf);

  const msg = Buffer.isBuffer(messageBuffer)
    ? messageBuffer
    : Buffer.from(messageBuffer);

  const payloadWithSeq = Buffer.concat([seqBuf, msg]);

  const encrypted = Buffer.concat([
    cipher.update(payloadWithSeq),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]);
}

export function decrypt(payload, key, expectedSeq) {
  if (payload.length < 12 + 16 + 8) throw new Error("Packet too short");

  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const ciphertext = payload.subarray(28);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);

  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(BigInt(expectedSeq), 0);

  decipher.setAAD(seqBuf);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  const gotSeq = decrypted.subarray(0, 8).readBigUInt64BE(0);
  if (gotSeq !== BigInt(expectedSeq)) throw new Error("Sequence mismatch");

  return decrypted.subarray(8);
}

export function signData(data, priv) {
  return crypto.sign(null, data, priv);
}

export function verifyData(data, sig, pub) {
  try {
    return crypto.verify(null, data, pub, sig);
  } catch {
    return false;
  }
}

export class PacketParser {
  constructor(onPacket) {
    this.buffer = Buffer.alloc(0);
    this.onPacket = onPacket;
  }

  add(data) {
    this.buffer = Buffer.concat([this.buffer, data]);

    while (true) {
      if (this.buffer.length < 5) return;

      const len = this.buffer.readUInt32BE(0);
      const type = this.buffer.readUInt8(4);

      if (this.buffer.length < 5 + len) return;

      const payload = this.buffer.subarray(5, 5 + len);
      this.buffer = this.buffer.subarray(5 + len);

      this.onPacket(type, payload);
    }
  }
}
