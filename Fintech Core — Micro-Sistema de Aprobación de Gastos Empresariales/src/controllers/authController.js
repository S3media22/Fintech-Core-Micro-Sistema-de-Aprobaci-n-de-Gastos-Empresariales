/**
 * Controlador de autenticación (Sprints Martes y Miércoles).
 * Registro con bcrypt, login con JWT en cookie HttpOnly, 2FA con TOTP y OAuth 2.0.
 */
const crypto = require('crypto');
const bcrypt = require('bcryptjs'); // implementación JS pura: instala sin compiladores en Windows
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const User = require('../models/User');
const { encrypt, decrypt } = require('../services/cryptoService');
const { passport, enabledProviders, OAUTH_SCOPES } = require('../config/passport');
const { AppError, asyncHandler } = require('../middlewares/errorHandler');
const {
  COOKIES,
  TOKEN_TYPES,
  cookieOptions,
  issueAccessToken,
  issuePreAuthToken,
  clearAuthCookies,
  resolveUserFromCookie,
} = require('../middlewares/authMiddleware');

const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 12;
const APP_NAME = process.env.APP_NAME || 'Fintech Core';
const TOTP_STEP_SECONDS = 30;

// Acepta el código anterior y el siguiente (±30 s) para tolerar relojes desfasados.
authenticator.options = { step: TOTP_STEP_SECONDS, window: 1 };

// Hash ficticio: si el correo no existe se compara igual, para que el tiempo de respuesta
// no revele qué correos están registrados (enumeración de usuarios por timing).
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_ROUNDS);

/**
 * Verifica un código TOTP y registra su paso para que no pueda reutilizarse.
 * @returns {number|null} paso consumido, o null si el código no es válido.
 */
function verifyTotp(code, secret) {
  const delta = authenticator.checkDelta(code, secret);
  if (delta === null) return null;
  return Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS) + delta;
}

/* ------------------------------------------------------------------ */
/* Registro, login y sesión                                           */
/* ------------------------------------------------------------------ */

const register = asyncHandler(async (req, res) => {
  const { nombre, email, password } = req.body;

  if (await User.findByEmail(email)) {
    throw new AppError('No se pudo crear la cuenta con ese correo. Si ya tienes una, inicia sesión.', 409);
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const user = await User.create({ nombre, email, passwordHash });

  issueAccessToken(res, user);
  res.status(201).json({
    status: 'success',
    message: 'Cuenta creada correctamente.',
    data: { usuario: User.toPublic(user) },
  });
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findByEmail(email);

  const passwordOk = await bcrypt.compare(password, user?.password_hash || DUMMY_HASH);
  if (!user || !user.password_hash || !passwordOk) {
    throw new AppError('Correo o contraseña incorrectos.', 401);
  }

  if (user.two_factor_enabled) {
    issuePreAuthToken(res, user);
    return res.json({
      status: 'success',
      message: 'Contraseña correcta. Falta el código de verificación.',
      data: { requiere2FA: true },
    });
  }

  issueAccessToken(res, user);
  res.json({ status: 'success', message: 'Sesión iniciada.', data: { requiere2FA: false, usuario: User.toPublic(user) } });
});

const logout = asyncHandler(async (req, res) => {
  const user = await resolveUserFromCookie(req, COOKIES.access, TOKEN_TYPES.access);
  if (user) await User.incrementTokenVersion(user.id); // revoca el JWT aunque alguien lo haya copiado
  clearAuthCookies(res);
  res.json({ status: 'success', message: 'Sesión cerrada.' });
});

const me = asyncHandler(async (req, res) => {
  res.json({ status: 'success', data: { usuario: User.toPublic(req.user) } });
});

const providers = (req, res) => {
  res.json({ status: 'success', data: { proveedores: { ...enabledProviders } } });
};

/* ------------------------------------------------------------------ */
/* Autenticación en dos pasos (TOTP)                                  */
/* ------------------------------------------------------------------ */

/** Paso 1: genera un secreto temporal y su QR para escanear con Google Authenticator. */
const setupTwoFactor = asyncHandler(async (req, res) => {
  const user = req.user;
  if (user.two_factor_enabled) {
    throw new AppError('La verificación en dos pasos ya está activa.', 409);
  }

  const secret = authenticator.generateSecret(20);
  await User.setTempTwoFactorSecret(user.id, encrypt(secret));

  const otpauthUrl = authenticator.keyuri(user.email, APP_NAME, secret);
  const qr = await QRCode.toDataURL(otpauthUrl, { errorCorrectionLevel: 'M', margin: 1, width: 232 });

  res.json({ status: 'success', data: { qr, claveManual: secret } });
});

/** Paso 2: el usuario confirma con un código que escaneó correctamente el QR. */
const enableTwoFactor = asyncHandler(async (req, res) => {
  const user = req.user;
  if (user.two_factor_enabled) throw new AppError('La verificación en dos pasos ya está activa.', 409);
  if (!user.two_factor_temp_secret) throw new AppError('Primero genera el código QR.', 400);

  const step = verifyTotp(req.body.code, decrypt(user.two_factor_temp_secret));
  // 400 y no 401: la sesión es válida, lo incorrecto es el código (401 cerraría la sesión en el cliente).
  if (step === null) throw new AppError('El código no coincide. Revisa la hora de tu teléfono e inténtalo de nuevo.', 400);

  const updated = await User.enableTwoFactor(user.id, step);
  if (!updated) throw new AppError('No se pudo activar la verificación en dos pasos.', 409);

  issueAccessToken(res, updated); // la token_version cambió: se emite una sesión nueva
  res.json({
    status: 'success',
    message: 'Verificación en dos pasos activada.',
    data: { usuario: User.toPublic(updated) },
  });
});

const disableTwoFactor = asyncHandler(async (req, res) => {
  const user = req.user;
  if (!user.two_factor_enabled) throw new AppError('La verificación en dos pasos no está activa.', 400);

  const step = verifyTotp(req.body.code, decrypt(user.two_factor_secret));
  if (step === null || !(await User.consumeTotpStep(user.id, step))) {
    throw new AppError('Código incorrecto o ya utilizado.', 400);
  }

  const updated = await User.disableTwoFactor(user.id);
  issueAccessToken(res, updated);
  res.json({
    status: 'success',
    message: 'Verificación en dos pasos desactivada.',
    data: { usuario: User.toPublic(updated) },
  });
});

/** Segundo factor del login: requiere la cookie pre-auth emitida tras la contraseña u OAuth. */
const verifyTwoFactorLogin = asyncHandler(async (req, res) => {
  const user = req.preAuthUser;

  const step = verifyTotp(req.body.code, decrypt(user.two_factor_secret));
  if (step === null || !(await User.consumeTotpStep(user.id, step))) {
    throw new AppError('Código incorrecto o ya utilizado.', 401);
  }

  issueAccessToken(res, user);
  res.json({ status: 'success', message: 'Sesión iniciada.', data: { usuario: User.toPublic(user) } });
});

/* ------------------------------------------------------------------ */
/* OAuth 2.0                                                          */
/* ------------------------------------------------------------------ */

const OAUTH_STATE_COOKIE = 'oauth_state';

// SameSite=Lax es necesario aquí: la vuelta desde Google/GitHub es una navegación entre sitios.
function oauthStateCookieOptions() {
  return { ...cookieOptions(10 * 60), sameSite: 'lax', path: '/api/auth' };
}

function requireProvider(provider) {
  return (req, res, next) => {
    if (enabledProviders[provider]) return next();
    next(new AppError(`El inicio de sesión con ${provider} no está configurado en este servidor.`, 503));
  };
}

/** Redirige al proveedor con un "state" aleatorio que protege el flujo contra CSRF. */
function oauthStart(provider) {
  return (req, res, next) => {
    const state = crypto.randomBytes(32).toString('hex');
    res.cookie(OAUTH_STATE_COOKIE, state, oauthStateCookieOptions());
    passport.authenticate(provider, { scope: OAUTH_SCOPES[provider], session: false, state })(req, res, next);
  };
}

function oauthCallback(provider) {
  return (req, res, next) => {
    const expected = req.cookies?.[OAUTH_STATE_COOKIE];
    const received = typeof req.query.state === 'string' ? req.query.state : '';
    const { maxAge, ...clearOptions } = oauthStateCookieOptions(); // eslint-disable-line no-unused-vars
    res.clearCookie(OAUTH_STATE_COOKIE, clearOptions);

    const stateOk =
      typeof expected === 'string' &&
      expected.length === received.length &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));

    if (!stateOk) return res.redirect('/?aviso=oauth_estado#login');

    passport.authenticate(provider, { session: false }, (err, user) => {
      if (err || !user) {
        if (err) console.warn(`[oauth:${provider}]`, err.message);
        return res.redirect('/?aviso=oauth_error#login');
      }
      if (user.two_factor_enabled) {
        issuePreAuthToken(res, user);
        return res.redirect('/#verificar');
      }
      issueAccessToken(res, user);
      return res.redirect('/#panel');
    })(req, res, next);
  };
}

module.exports = {
  register,
  login,
  logout,
  me,
  providers,
  setupTwoFactor,
  enableTwoFactor,
  disableTwoFactor,
  verifyTwoFactorLogin,
  requireProvider,
  oauthStart,
  oauthCallback,
};
