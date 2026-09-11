/**
 * Cifrado simétrico AES-256-GCM para datos sensibles en reposo (secretos TOTP del 2FA).
 * Si la base de datos se filtra, los secretos no sirven sin la clave TOTP_ENCRYPTION_KEY,
 * que vive solo en las variables de entorno del servidor (OWASP A02: Cryptographic Failures).
 *
 * Formato almacenado: base64(iv).base64(authTag).base64(cifrado)
 */
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;

function getKey() {
  const hex = process.env.TOTP_ENCRYPTION_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('TOTP_ENCRYPTION_KEY debe tener 64 caracteres hexadecimales (32 bytes).');
  }
  return Buffer.from(hex, 'hex');
}

function encrypt(plainText) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv, authTag, encrypted].map((b) => b.toString('base64')).join('.');
}

function decrypt(payload) {
  const parts = String(payload).split('.');
  if (parts.length !== 3) throw new Error('Formato de dato cifrado inválido.');

  const [iv, authTag, encrypted] = parts.map((p) => Buffer.from(p, 'base64'));
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  decipher.setAuthTag(authTag); // si alguien alteró el dato, final() lanza error
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
