/**
 * Pruebas del cifrado AES-256-GCM de los secretos 2FA.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.TOTP_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
const { encrypt, decrypt } = require('../src/services/cryptoService');

test('cifra y descifra el secreto TOTP', () => {
  const secreto = 'JBSWY3DPEHPK3PXP';
  const cifrado = encrypt(secreto);
  assert.notEqual(cifrado, secreto);
  assert.equal(decrypt(cifrado), secreto);
});

test('cada cifrado usa un IV distinto', () => {
  assert.notEqual(encrypt('mismo'), encrypt('mismo'));
});

test('detecta datos alterados en la base de datos', () => {
  const [iv, tag, datos] = encrypt('JBSWY3DPEHPK3PXP').split('.');
  const alterado = Buffer.from(datos, 'base64');
  alterado[0] ^= 0xff;
  assert.throws(() => decrypt([iv, tag, alterado.toString('base64')].join('.')));
});
