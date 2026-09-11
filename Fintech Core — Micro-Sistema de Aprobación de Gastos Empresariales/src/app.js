/**
 * Punto de entrada del servidor — Micro-Sistema de Aprobación de Gastos (Fintech Core).
 *
 * Parte del "Código de Arranque Seguro" del Lunes y lo completa:
 *  - dotenv se carga PRIMERO para que todos los módulos lean el .env.
 *  - Las rutas estáticas usan path absoluto (el original fallaba si se ejecutaba fuera de la raíz).
 *  - JSON y formularios con límite de tamaño (evita DoS por cuerpos gigantes).
 *  - CSP estricta propia en security.js (la de Helmet por defecto permite estilos 'unsafe-inline').
 *  - 404 en JSON antes del errorHandler (el original no tenía).
 *  - Validación de variables críticas al arrancar: sin JWT_SECRET el servidor no inicia.
 */
require('dotenv').config({ quiet: true });

const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const { configurePassport } = require('./config/passport');
const { testConnection } = require('./config/db');
const {
  helmetMiddleware,
  apiLimiter,
  hppMiddleware,
  sanitizeInput,
  verifyOrigin,
  allowedOrigins,
  noStore,
} = require('./middlewares/security');
const errorHandler = require('./middlewares/errorHandler');
const { notFound, AppError } = errorHandler;
const authRoutes = require('./routes/authRoutes');
const gastoRoutes = require('./routes/gastoRoutes');

// --- VALIDACIÓN DE CONFIGURACIÓN (falla rápido y con mensaje claro) ---
function validarEntorno() {
  const problemas = [];
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    problemas.push('JWT_SECRET debe existir y tener al menos 32 caracteres.');
  }
  if (!/^[0-9a-fA-F]{64}$/.test(process.env.TOTP_ENCRYPTION_KEY || '')) {
    problemas.push('TOTP_ENCRYPTION_KEY debe tener 64 caracteres hexadecimales.');
  }
  if (problemas.length) {
    throw new Error(`Configuración inválida:\n - ${problemas.join('\n - ')}\nRevisa tu archivo .env (ver .env.example).`);
  }
}
validarEntorno();

const app = express();
const passport = configurePassport();
const isProduction = process.env.NODE_ENV === 'production';

app.disable('x-powered-by'); // no revelar que el servidor usa Express
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);

// --- CAPA DE SEGURIDAD GLOBAL (OWASP) ---
app.use(helmetMiddleware); // CSP anti JS Injection, X-Frame-Options DENY anti Clickjacking, nosniff, HSTS en producción
app.use(
  cors({
    // Control estricto de accesos: solo los orígenes de CORS_ORIGINS reciben cabeceras CORS.
    origin(origin, callback) {
      callback(null, !origin || allowedOrigins().includes(origin));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH'],
  })
);
app.use(cookieParser()); // Habilita lectura de cookies seguras
app.use(express.json({ limit: '10kb' })); // Parsing seguro de JSON
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(hppMiddleware); // HTTP Parameter Pollution (?estado=a&estado=b)
app.use(sanitizeInput); // Sanitización XSS / prototype pollution de body y query
app.use(passport.initialize());

// Rate Limiting para mitigar fuerza bruta o scraping masivo (el login tiene uno más estricto)
app.use('/api/', apiLimiter, noStore, verifyOrigin);

// --- RUTAS DE LA API ---
app.get('/api/health', (req, res) => {
  res.json({ status: 'success', data: { servicio: 'fintech-core', hora: new Date().toISOString() } });
});

if (!isProduction) {
  // Recomendación del Lunes: ruta que falla a propósito para comprobar el errorHandler.
  // Debe responder 500 con un mensaje genérico, sin stack trace, y el servidor debe seguir vivo.
  app.get('/api/test/error', () => {
    throw new Error('Test: error intencional con datos internos que NO deben llegar al cliente');
  });
  app.get('/api/test/error-controlado', () => {
    throw new AppError('Error operacional de prueba: este mensaje sí es seguro para el cliente.', 418);
  });
}

app.use('/api/auth', authRoutes);
app.use('/api/gastos', gastoRoutes);
app.use('/api', notFound);

// Servir el Frontend dinámico desde la carpeta pública
app.use(
  express.static(path.join(__dirname, 'public'), {
    index: 'index.html',
    dotfiles: 'ignore',
    maxAge: isProduction ? '1h' : 0,
  })
);

// --- MANEJO DE ERRORES GLOBAL (Try-Catch Middleware) ---
app.use(notFound);
app.use(errorHandler);

// --- ARRANQUE ---
async function start() {
  const PORT = Number(process.env.PORT) || 3000;
  const ahora = await testConnection();
  console.log(`✔ Base de datos conectada (${new Date(ahora).toISOString()})`);

  app.listen(PORT, () => {
    console.log(`🔒 Servidor robusto corriendo en http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  start().catch((err) => {
    console.error('✖ No fue posible iniciar el servidor:', err.message);
    process.exit(1);
  });
}

module.exports = app;
