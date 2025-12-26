import crypto from 'node:crypto';
import fs from 'node:fs';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' }
});

fs.writeFileSync('./server_identity', privateKey);
fs.writeFileSync('./server_identity.pub', publicKey);

console.log('Ключи успешно сгенерированы в правильном формате!');