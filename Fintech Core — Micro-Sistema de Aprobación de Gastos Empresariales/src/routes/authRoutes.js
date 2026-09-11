/**
 * Endpoints de autenticación: registro, login, logout, sesión, 2FA y OAuth 2.0.
 * Cada ruta pasa por: rate limit (si aplica) → validación → controlador.
 */
const express = require('express');
const { body } = require('express-validator');
const auth = require('../controllers/authController');
const { requireAuth, requirePreAuth } = require('../middlewares/authMiddleware');
const { authLimiter, validate, PATTERNS } = require('../middlewares/security');

const router = express.Router();

/* Reglas de validación (lista blanca) ------------------------------ */

const emailRule = body('email')
  .isString().withMessage('El correo es obligatorio.')
  .bail()
  .trim()
  .toLowerCase()
  .isLength({ max: 254 }).withMessage('El correo es demasiado largo.')
  .matches(PATTERNS.email).withMessage('Escribe un correo válido, por ejemplo nombre@empresa.com.');

const codeRule = body('code')
  .isString().withMessage('Escribe el código de 6 dígitos.')
  .bail()
  .trim()
  .matches(PATTERNS.codigoTotp).withMessage('El código debe tener exactamente 6 dígitos.');

const registerRules = [
  body('nombre')
    .isString().withMessage('El nombre es obligatorio.')
    .bail()
    .trim()
    .matches(PATTERNS.nombre).withMessage('El nombre solo puede tener letras, espacios, apóstrofos y guiones (2 a 80).'),
  emailRule,
  body('password')
    .isString().withMessage('La contraseña es obligatoria.')
    .bail()
    .matches(PATTERNS.password)
    .withMessage('La contraseña necesita de 8 a 72 caracteres con mayúscula, minúscula, número y símbolo.')
    .bail()
    .custom((value) => Buffer.byteLength(value, 'utf8') <= 72) // límite real de bcrypt
    .withMessage('La contraseña es demasiado larga.'),
  body('passwordConfirm')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Las contraseñas no coinciden.'),
];

const loginRules = [
  emailRule,
  body('password')
    .isString().withMessage('La contraseña es obligatoria.')
    .bail()
    .isLength({ min: 1, max: 128 }).withMessage('La contraseña es obligatoria.'),
];

/* Rutas ------------------------------------------------------------ */

router.post('/register', authLimiter, registerRules, validate, auth.register);
router.post('/login', authLimiter, loginRules, validate, auth.login);
router.post('/logout', auth.logout);
router.get('/me', requireAuth, auth.me);
router.get('/providers', auth.providers);

// 2FA
router.post('/2fa/setup', requireAuth, auth.setupTwoFactor);
router.post('/2fa/enable', requireAuth, authLimiter, [codeRule], validate, auth.enableTwoFactor);
router.post('/2fa/disable', requireAuth, authLimiter, [codeRule], validate, auth.disableTwoFactor);
router.post('/2fa/verify', authLimiter, requirePreAuth, [codeRule], validate, auth.verifyTwoFactorLogin);

// OAuth 2.0
for (const provider of ['google', 'github']) {
  router.get(`/${provider}`, auth.requireProvider(provider), auth.oauthStart(provider));
  router.get(`/${provider}/callback`, auth.requireProvider(provider), auth.oauthCallback(provider));
}

module.exports = router;
