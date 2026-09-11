/**
 * Barreras de seguridad transversales (OWASP Top 10).
 *
 * Capas implementadas en este archivo:
 *  1. Cabeceras HTTP seguras con Helmet (CSP estricta, anti-Clickjacking, nosniff, HSTS).
 *  2. Rate limiting general y reforzado para autenticación (fuerza bruta / credential stuffing).
 *  3. Sanitización recursiva de la entrada (XSS almacenado, inyección JS, prototype pollution).
 *  4. Validación por lista blanca (Regex) con express-validator.
 *  5. Verificación de origen en peticiones que modifican estado (defensa extra anti-CSRF).
 */
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const { validationResult } = require('express-validator');
const { AppError } = require('./errorHandler');

const isProduction = process.env.NODE_ENV === 'production';

/* ------------------------------------------------------------------ */
/* 1. Cabeceras seguras                                               */
/* ------------------------------------------------------------------ */
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], // sin 'unsafe-inline': un <script> inyectado no se ejecuta
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], // data: solo para el QR del 2FA
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"], // anti-Clickjacking (moderno)
      ...(isProduction ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  frameguard: { action: 'deny' }, // anti-Clickjacking (X-Frame-Options para navegadores antiguos)
  crossOriginEmbedderPolicy: true, // del app.js base: bloquea recursos de otros orígenes sin permiso explícito
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: isProduction ? { maxAge: 31_536_000, includeSubDomains: true, preload: true } : false,
});

/* ------------------------------------------------------------------ */
/* 2. Rate limiting                                                   */
/* ------------------------------------------------------------------ */
const rateLimitHandler = (req, res) => {
  res.status(429).json({
    status: 'error',
    statusCode: 429,
    message: 'Demasiadas peticiones desde esta conexión. Espera unos minutos e inténtalo de nuevo.',
  });
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.API_RATE_LIMIT_MAX) || 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: rateLimitHandler,
});

// Solo cuenta intentos fallidos: un usuario legítimo no se bloquea al iniciar sesión bien.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT_MAX) || 10,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: rateLimitHandler,
});

/* ------------------------------------------------------------------ */
/* 3. Sanitización de entrada                                         */
/* ------------------------------------------------------------------ */

// Campos que no deben alterarse (una contraseña puede contener "<" legítimamente).
const RAW_FIELDS = new Set(['password', 'passwordConfirm', 'code']);
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH = 5;

/**
 * Elimina marcado HTML y vectores de inyección JS de un string.
 * Se repite hasta que el resultado no cambie, para neutralizar anidamientos
 * como "<scr<script>ipt>".
 */
function sanitizeString(value) {
  let current = value
    .normalize('NFKC') // convierte variantes Unicode (＜script＞) a su forma ASCII
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ''); // caracteres de control

  let previous;
  do {
    previous = current;
    current = current
      .replace(/<\s*(script|style|iframe|object|embed|svg|math)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, '')
      .replace(/<\/?\s*[a-z!?][^>]*>/gi, '')
      .replace(/(?:java|vb)script\s*:/gi, '')
      .replace(/data\s*:\s*text\/html/gi, '')
      .replace(/\bon[a-z]+\s*=/gi, '');
  } while (current !== previous);

  return current.trim();
}

function sanitizeValue(value, depth = 0) {
  if (depth > MAX_DEPTH) return undefined;
  if (typeof value === 'string') return sanitizeString(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, depth + 1));
  if (value && typeof value === 'object') {
    const clean = Object.create(null);
    for (const [key, val] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(key)) continue; // bloquea prototype pollution
      clean[key] = RAW_FIELDS.has(key) ? val : sanitizeValue(val, depth + 1);
    }
    return { ...clean };
  }
  return value;
}

function sanitizeInput(req, res, next) {
  if (req.body && typeof req.body === 'object') req.body = sanitizeValue(req.body);
  if (req.query && typeof req.query === 'object') req.query = sanitizeValue(req.query);
  next();
}

/* ------------------------------------------------------------------ */
/* 4. Validación por lista blanca                                     */
/* ------------------------------------------------------------------ */

// Patrones compartidos (el frontend replica los mismos en validators.js).
const PATTERNS = Object.freeze({
  nombre: /^[\p{L}][\p{L}' .-]{1,79}$/u,
  email: /^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,24}$/i,
  // 8 a 72 caracteres con minúscula, mayúscula, número y CUALQUIER símbolo (72 = límite de bcrypt).
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9\s]).{8,72}$/,
  // Texto libre sin < > ` { } para que no pueda transportar marcado ni plantillas.
  textoSeguro: /^[\p{L}\p{N} .,;:()#/&%$'"!?¿¡+_-]{3,100}$/u,
  montoUsd: /^\d{1,6}(\.\d{1,2})?$/,
  fechaIso: /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/,
  codigoTotp: /^\d{6}$/,
});

/** Responde 422 con el detalle si alguna regla de express-validator falló. */
function validate(req, res, next) {
  const result = validationResult(req);
  if (result.isEmpty()) return next();

  const detalles = result.array({ onlyFirstError: true }).map((e) => ({
    campo: e.path,
    mensaje: e.msg,
  }));
  next(new AppError('Revisa los datos enviados.', 422, detalles));
}

/* ------------------------------------------------------------------ */
/* 5. Verificación de origen (anti-CSRF complementario a SameSite)    */
/* ------------------------------------------------------------------ */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function allowedOrigins() {
  return (process.env.CORS_ORIGINS || process.env.APP_BASE_URL || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
}

function verifyOrigin(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const origin = req.get('origin');
  if (!origin) return next(); // clientes no-navegador (curl, pruebas); la cookie SameSite sigue protegiendo

  let sameHost = false;
  try {
    sameHost = new URL(origin).host === req.get('host');
  } catch {
    sameHost = false;
  }

  if (sameHost || allowedOrigins().includes(origin)) return next();
  next(new AppError('Origen de la solicitud no permitido.', 403));
}

/** Evita que proxies o el navegador guarden respuestas de la API con datos sensibles. */
function noStore(req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}

module.exports = {
  helmetMiddleware,
  apiLimiter,
  authLimiter,
  hppMiddleware: hpp(),
  sanitizeInput,
  sanitizeString,
  sanitizeValue,
  PATTERNS,
  validate,
  verifyOrigin,
  allowedOrigins,
  noStore,
};
