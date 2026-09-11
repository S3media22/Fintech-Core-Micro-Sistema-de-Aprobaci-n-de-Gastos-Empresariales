/**
 * Generador y validador de JWT almacenado en cookies HttpOnly.
 *
 * Mantiene los nombres del material del Lunes (TokenService):
 *   - generarToken(user)          → firma el JWT
 *   - verificarTokenMiddleware    → protege rutas leyendo la cookie "auth_token"
 *
 * Diferencias importantes frente a la versión inicial:
 *   - NO existe clave secreta por defecto. Si JWT_SECRET falta, el servidor no arranca
 *     (una clave "por defecto" permitiría a cualquiera falsificar tokens).
 *   - jwt.verify fija el algoritmo HS256, el emisor y la audiencia (bloquea "alg: none").
 *   - Cada token se valida también contra la BD (usuario existente + token_version).
 *
 * - HttpOnly: JavaScript del navegador no puede leer el token (mitiga robo por XSS).
 * - Secure:   la cookie solo viaja por HTTPS (obligatorio en producción).
 * - SameSite=Strict: el navegador no la envía en peticiones iniciadas por otros sitios (anti-CSRF).
 *
 * Hay dos tipos de token:
 *  - "access": sesión completa (1 hora).
 *  - "pre2fa": credenciales correctas pero falta el código 2FA (5 minutos, solo sirve para verificarlo).
 *
 * Revocación: cada JWT lleva la "token_version" del usuario. Al cerrar sesión o cambiar
 * el 2FA se incrementa en BD y todos los tokens anteriores dejan de ser válidos.
 */
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError, asyncHandler } = require('./errorHandler');

const COOKIES = Object.freeze({ access: 'auth_token', preAuth: 'pre_auth_token' });
const TOKEN_TYPES = Object.freeze({ access: 'access', preAuth: 'pre2fa' });

const JWT_OPTIONS = Object.freeze({
  algorithm: 'HS256',
  issuer: 'fintech-core',
  audience: 'fintech-core-web',
});

const ACCESS_TTL_SECONDS = 60 * 60;
const PRE_AUTH_TTL_SECONDS = 5 * 60;

function isSecureCookie() {
  if (process.env.NODE_ENV === 'production') return true;
  return process.env.COOKIE_SECURE !== 'false';
}

function cookieOptions(maxAgeSeconds) {
  return {
    httpOnly: true,
    secure: isSecureCookie(),
    sameSite: 'strict',
    path: '/',
    ...(maxAgeSeconds ? { maxAge: maxAgeSeconds * 1000 } : {}),
  };
}

function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET no está configurado o es demasiado corto (mínimo 32 caracteres).');
  }
  return secret;
}

function signToken(user, typ, ttlSeconds) {
  // Solo datos no sensibles: id, rol, versión del token y tipo. Nunca correo ni contraseña.
  return jwt.sign(
    { id: user.id, rol: user.rol, tv: user.token_version, typ },
    getSecret(),
    { ...JWT_OPTIONS, expiresIn: ttlSeconds }
  );
}

function issueAccessToken(res, user) {
  res.clearCookie(COOKIES.preAuth, cookieOptions());
  res.cookie(COOKIES.access, generarToken(user), cookieOptions(ACCESS_TTL_SECONDS));
}

function issuePreAuthToken(res, user) {
  res.clearCookie(COOKIES.access, cookieOptions());
  res.cookie(COOKIES.preAuth, signToken(user, TOKEN_TYPES.preAuth, PRE_AUTH_TTL_SECONDS), cookieOptions(PRE_AUTH_TTL_SECONDS));
}

function clearAuthCookies(res) {
  res.clearCookie(COOKIES.access, cookieOptions());
  res.clearCookie(COOKIES.preAuth, cookieOptions());
}

/** Genera el JWT de sesión (1 hora). Nombre compatible con el material del Lunes. */
function generarToken(user) {
  return signToken(user, TOKEN_TYPES.access, ACCESS_TTL_SECONDS);
}

/** Verifica firma, algoritmo, emisor, audiencia, expiración y tipo. Lanza si algo no cuadra. */
function decodeToken(token, expectedType) {
  const payload = jwt.verify(token, getSecret(), {
    algorithms: [JWT_OPTIONS.algorithm], // impide ataques "alg: none" o confusión de algoritmo
    issuer: JWT_OPTIONS.issuer,
    audience: JWT_OPTIONS.audience,
  });
  if (payload.typ !== expectedType) throw new Error('Tipo de token incorrecto');
  return payload;
}

/** Carga al usuario a partir de la cookie indicada, o devuelve null si no es válida. */
async function resolveUserFromCookie(req, cookieName, expectedType) {
  const token = req.cookies?.[cookieName];
  if (!token || typeof token !== 'string') return null;

  let payload;
  try {
    payload = decodeToken(token, expectedType);
  } catch {
    return null;
  }

  const userId = Number(payload.id);
  if (!Number.isSafeInteger(userId)) return null;

  const user = await User.findById(userId);
  if (!user || user.token_version !== payload.tv) return null;
  return user;
}

const requireAuth = asyncHandler(async (req, res, next) => {
  const user = await resolveUserFromCookie(req, COOKIES.access, TOKEN_TYPES.access);
  if (!user) {
    // Solo se borra la cookie de sesión: la pre-auth debe sobrevivir mientras el usuario escribe su código 2FA.
    res.clearCookie(COOKIES.access, cookieOptions());
    throw new AppError('Tu sesión no es válida o expiró. Inicia sesión de nuevo.', 401);
  }
  req.user = user;
  next();
});

const requirePreAuth = asyncHandler(async (req, res, next) => {
  const user = await resolveUserFromCookie(req, COOKIES.preAuth, TOKEN_TYPES.preAuth);
  if (!user || !user.two_factor_enabled) {
    res.clearCookie(COOKIES.preAuth, cookieOptions());
    throw new AppError('La verificación expiró. Inicia sesión de nuevo.', 401);
  }
  req.preAuthUser = user;
  next();
});

const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (req.user && roles.includes(req.user.rol)) return next();
    next(new AppError('No tienes permisos para realizar esta acción.', 403));
  };

module.exports = {
  COOKIES,
  TOKEN_TYPES,
  cookieOptions,
  generarToken,
  verificarTokenMiddleware: requireAuth,
  issueAccessToken,
  issuePreAuthToken,
  clearAuthCookies,
  resolveUserFromCookie,
  requireAuth,
  requirePreAuth,
  requireRole,
};
