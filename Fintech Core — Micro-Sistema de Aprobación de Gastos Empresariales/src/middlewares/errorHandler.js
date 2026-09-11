/**
 * Middleware centralizado para captura de errores (Capa de Seguridad OWASP).
 *
 * Mantiene el contrato del material del Lunes:
 *   const errorHandler = require('./middlewares/errorHandler');
 *   app.use(errorHandler);
 *   Respuesta: { status: 'error', statusCode, message }
 *
 * Y añade utilidades para el resto del proyecto:
 *   - AppError:     errores "esperados" cuyo mensaje sí puede ver el cliente.
 *   - asyncHandler: envuelve controladores async en try-catch y reenvía el error.
 *   - notFound:     404 uniforme en JSON.
 */

class AppError extends Error {
  /**
   * @param {string} message    Mensaje seguro para el cliente.
   * @param {number} statusCode Código HTTP.
   * @param {Array}  [detalles] Errores de validación por campo (opcional).
   */
  constructor(message, statusCode = 500, detalles) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.detalles = detalles;
    this.isOperational = true;
  }
}

const asyncHandler = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (error) {
    next(error); // cualquier fallo termina en errorHandler
  }
};

const notFound = (req, res, next) => {
  next(new AppError('El recurso solicitado no existe.', 404));
};

// Códigos de PostgreSQL traducidos a mensajes genéricos (evita SQL Leakage).
const PG_ERRORS = {
  23505: { statusCode: 409, message: 'Los datos enviados entran en conflicto con registros existentes.' },
  23503: { statusCode: 400, message: 'El registro relacionado no existe.' },
  23514: { statusCode: 400, message: 'Los datos no cumplen las reglas del sistema.' },
  '22P02': { statusCode: 400, message: 'Formato de dato inválido.' },
  22001: { statusCode: 400, message: 'Uno de los textos supera la longitud permitida.' },
  22003: { statusCode: 400, message: 'Un valor numérico está fuera de rango.' },
};

// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  if (res.headersSent) return next(err);

  // 1. Valores por defecto: nunca se expone err.message de errores inesperados.
  let statusCode = Number(err.statusCode) || 500;
  let message = err.isOperational ? err.message : 'Ocurrió un error interno en el servidor. Intenta más tarde.';

  // 2. Errores de base de datos (códigos SQLSTATE de PostgreSQL)
  const pgCode = typeof err.code === 'string' ? err.code : '';
  if (PG_ERRORS[pgCode]) {
    ({ statusCode, message } = PG_ERRORS[pgCode]);
  } else if (pgCode.startsWith('23')) {
    statusCode = 400;
    message = 'Los datos enviados entran en conflicto con registros existentes.';
  }

  // 3. Errores de JWT
  if (err.name === 'JsonWebTokenError') {
    statusCode = 401;
    message = 'Token de autenticación inválido o alterado.';
  } else if (err.name === 'TokenExpiredError') {
    statusCode = 401;
    message = 'Tu sesión expiró. Inicia sesión nuevamente.';
  }

  // 4. Errores del parser de Express
  if (err.type === 'entity.parse.failed') {
    statusCode = 400;
    message = 'El cuerpo de la solicitud no es un JSON válido.';
  } else if (err.type === 'entity.too.large') {
    statusCode = 413;
    message = 'La solicitud supera el tamaño permitido.';
  }

  // 5. Registro interno para auditoría: el stack solo queda en el servidor.
  if (statusCode >= 500) {
    console.error(`[ERROR] [${new Date().toISOString()}] ${req.method} ${req.originalUrl}\n${err.stack}`);
  }

  const body = { status: 'error', statusCode, message };
  if (Array.isArray(err.detalles) && err.detalles.length) body.detalles = err.detalles;

  res.status(statusCode).json(body);
};

module.exports = errorHandler;
module.exports.errorHandler = errorHandler;
module.exports.AppError = AppError;
module.exports.asyncHandler = asyncHandler;
module.exports.notFound = notFound;
