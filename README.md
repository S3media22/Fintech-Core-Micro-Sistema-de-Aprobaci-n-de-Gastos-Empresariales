# Fintech-Core-Micro-Sistema-de-Aprobaci-n-de-Gastos-Empresariales
Aplicación web en JavaScript (Node.js + Express + PostgreSQL) bajo patrón MVC, donde los empleados registran gastos en dólares, el sistema los convierte a pesos colombianos con una API externa de tasas de cambio y un aprobador los aprueba o rechaza

# Fintech Core — Micro-Sistema de Aprobación de Gastos Empresariales

Aplicación web en JavaScript (Node.js + Express + PostgreSQL) bajo patrón MVC, donde los empleados registran gastos en dólares, el sistema los convierte a pesos colombianos con una API externa de tasas de cambio y un aprobador los aprueba o rechaza. Está construida como proyecto formativo de una semana para equipos de Frontend y Backend, con seguridad alineada al OWASP Top 10.

## Funcionalidades

El **empleado** crea su cuenta (o entra con Google/GitHub), registra gastos en USD, ve la conversión aproximada a COP antes de enviar, consulta su libro de gastos filtrado por estado con totales, y puede activar la verificación en dos pasos con Google Authenticator.

El **aprobador** (definido en `ADMIN_EMAILS`) tiene además una bandeja con los gastos pendientes de su equipo. Puede aprobarlos o rechazarlos (el rechazo exige motivo). El sistema impide que alguien apruebe sus propios gastos y que dos aprobadores decidan el mismo gasto.

## Stack

| Capa | Tecnología |
| --- | --- |
| Servidor | Node.js 20+, Express 4 |
| Base de datos | PostgreSQL 14+ con `pg` (consultas parametrizadas) |
| Autenticación | JWT en cookie HttpOnly, `bcryptjs`, Passport.js (Google y GitHub), `otplib` + `qrcode` (2FA) |
| Seguridad | Helmet (CSP), express-rate-limit, express-validator, hpp, sanitización propia, AES-256-GCM |
| Frontend | HTML único (SPA), CSS Grid, Vanilla JS sin bundler |
| Pruebas | `node:test` (unitarias) y script de ataques QA |

---

## Inicio rápido

**Requisitos:** Node.js 20 o superior y PostgreSQL (local o con Docker).

```bash
# 1. Instalar dependencias
npm install

# 2. Crear el archivo de entorno
cp .env.example .env
#    Genera JWT_SECRET y TOTP_ENCRYPTION_KEY con los comandos indicados dentro del archivo.

# 3. Levantar PostgreSQL (opción Docker)
docker compose up -d

# 4. Crear las tablas
npm run db:migrate

# 5. Iniciar el servidor
npm run dev        # con recarga automática (nodemon)
# o
npm start
```

Abre `http://localhost:3000`. Para obtener una cuenta aprobadora, regístrate con un correo incluido en `ADMIN_EMAILS` (por defecto `aprobador@empresa.com`).

> **Cookies en local:** si tu navegador no guarda la sesión en `http://localhost`, pon `COOKIE_SECURE=false` en `.env`. En producción (`NODE_ENV=production`) la cookie siempre es `Secure`.

**Si usas PostgreSQL sin Docker**, crea el usuario y la base antes de migrar:

```sql
CREATE USER fintech WITH PASSWORD 'fintech_dev_password';
CREATE DATABASE fintech_core OWNER fintech;
```

---

## Estructura del proyecto

```
proyecto-robust-mvc/
├── src/
│   ├── config/
│   │   ├── db.js                 # Pool de PostgreSQL y helper query() parametrizado
│   │   ├── migrate.js            # ➕ Script de migración (tablas usuarios y gastos)
│   │   └── passport.js           # Estrategias OAuth 2.0 (Google y GitHub)
│   ├── controllers/
│   │   ├── authController.js     # Registro, login, logout, 2FA y callbacks OAuth
│   │   └── gastoController.js    # Crear/listar gastos, tasa del día y aprobación
│   ├── models/
│   │   ├── User.js               # Consultas de usuarios
│   │   └── Gasto.js              # Consultas de gastos
│   ├── middlewares/
│   │   ├── authMiddleware.js     # generarToken, verificarTokenMiddleware, roles
│   │   ├── security.js           # Helmet/CSP, rate limit, sanitización, validación, anti-CSRF
│   │   └── errorHandler.js       # Captura global de errores (try-catch)
│   ├── services/
│   │   ├── currencyService.js    # API externa de divisas USD→COP
│   │   └── cryptoService.js      # ➕ Cifrado AES-256-GCM de secretos 2FA
│   ├── routes/
│   │   ├── authRoutes.js
│   │   └── gastoRoutes.js
│   ├── public/
│   │   ├── css/styles.css
│   │   ├── fonts/                # ➕ Fuente autoalojada (exigida por la CSP)
│   │   ├── js/main.js
│   │   ├── js/validators.js
│   │   └── index.html
│   └── app.js
├── tests/                        # ➕ Pruebas del Viernes
│   ├── security.test.js
│   ├── validators.test.js
│   ├── currency.test.js
│   ├── crypto.test.js
│   └── qa-attacks.js
├── docker-compose.yml            # ➕ PostgreSQL para desarrollo
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

Los elementos marcados con ➕ no estaban en la plantilla inicial; se agregaron porque el cronograma los necesita (migración del Lunes, pruebas del Viernes) o porque un control de seguridad lo exige.

---

## Mapa del cronograma

| Día | Backend | Frontend |
| --- | --- | --- |
| **Lunes** — Cimientos | `config/db.js`, `config/migrate.js`, `app.js`, `middlewares/errorHandler.js` y la ruta `/api/test/error` | `index.html` (vistas Login, Registro, Dashboard) y `css/styles.css` |
| **Martes** — Autenticación | `authController.register/login`, `authMiddleware.js` (JWT + cookie HttpOnly), Helmet en `security.js` | `validators.js` (Regex) y el enrutador de vistas en `main.js` |
| **Miércoles** — OAuth y 2FA | `config/passport.js`, rutas `/google` y `/github`, `setupTwoFactor/enableTwoFactor/verifyTwoFactorLogin`, `cryptoService.js`, sanitización | Vista de Seguridad con QR, pantalla "Confirma que eres tú", revisión de `textContent` |
| **Jueves** — APIs y operaciones | `gastoRoutes.js`, `gastoController.js`, `currencyService.js`, modelo `Gasto.js` | Conexión con `fetch`, `sessionStorage`, libro de gastos, bandeja de aprobación |
| **Viernes** — QA | `npm test` y `npm run qa:ataques` | Pruebas manuales de inyección desde el navegador (ver abajo) |

---

## API

Todas las respuestas usan el formato `{ status: 'success', message?, data }` o `{ status: 'error', statusCode, message, detalles? }`.

| Método | Ruta | Acceso | Descripción |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | Público | Crea cuenta (`nombre`, `email`, `password`, `passwordConfirm`) |
| POST | `/api/auth/login` | Público | Inicia sesión. Si hay 2FA responde `requiere2FA: true` |
| POST | `/api/auth/2fa/verify` | Cookie pre-auth | Completa el login con el código de 6 dígitos |
| POST | `/api/auth/logout` | Sesión | Cierra sesión y revoca el token |
| GET | `/api/auth/me` | Sesión | Datos del usuario actual |
| GET | `/api/auth/providers` | Público | Proveedores OAuth configurados |
| POST | `/api/auth/2fa/setup` | Sesión | Genera QR y clave manual |
| POST | `/api/auth/2fa/enable` | Sesión | Activa 2FA con un código válido |
| POST | `/api/auth/2fa/disable` | Sesión | Desactiva 2FA con un código válido |
| GET | `/api/auth/google` y `/api/auth/github` | Público | Inicia OAuth 2.0 |
| GET | `/api/gastos?estado=` | Sesión | Gastos propios y resumen por estado |
| POST | `/api/gastos` | Sesión | Crea gasto (`descripcion`, `categoria`, `montoEnUSD`, `fechaGasto`) |
| GET | `/api/gastos/tasa` | Sesión | Tasa USD→COP y su fuente |
| GET | `/api/gastos/pendientes` | Aprobador | Pendientes de otros usuarios |
| PATCH | `/api/gastos/:id/estado` | Aprobador | `estado`: `aprobado` o `rechazado` (este exige `comentario`) |
| GET | `/api/test/error` | Solo desarrollo | Error intencional para probar el `errorHandler` |

---

## Matriz de seguridad (OWASP)

| Amenaza | Defensa implementada | Dónde |
| --- | --- | --- |
| **SQL Injection** | Solo consultas parametrizadas (`$1, $2`). El helper `query()` exige arreglo de parámetros. Los nombres de columna dinámicos salen de una lista blanca. Restricciones `CHECK` en la BD | `models/`, `config/db.js`, `migrate.js` |
| **XSS / JS Injection** | CSP `script-src 'self'` sin `unsafe-inline`; sanitización recursiva del body y query; validación por lista blanca; el frontend pinta solo con `textContent` y `<template>` | `security.js`, `main.js` |
| **Clickjacking** | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | `security.js` |
| **CSRF** | Cookie `SameSite=Strict`, verificación de cabecera `Origin` en métodos que modifican datos, `state` aleatorio en OAuth | `authMiddleware.js`, `security.js`, `authController.js` |
| **Robo de sesión** | JWT en cookie `HttpOnly` + `Secure`, expiración de 1 h, algoritmo fijado a HS256, revocación por `token_version` al cerrar sesión o cambiar el 2FA | `authMiddleware.js` |
| **Fuerza bruta** | Rate limit general (300/15 min) y de autenticación (10 fallos/15 min); bcrypt con coste 12 | `security.js`, `authController.js` |
| **Enumeración de usuarios** | Mismo mensaje y mismo tiempo de respuesta si el correo no existe (hash ficticio) | `authController.js` |
| **2FA débil** | Secretos cifrados con AES-256-GCM, códigos TOTP de un solo uso (anti-replay) | `cryptoService.js`, `User.js` |
| **Control de acceso roto** | Consultas filtradas por `usuario_id` del JWT, roles verificados en servidor, nadie aprueba su propio gasto (también como `CHECK` en BD), decisiones atómicas | `Gasto.js`, `gastoRoutes.js` |
| **Fuga de información** | Errores genéricos al cliente, stack solo en el log del servidor, sin `X-Powered-By` | `errorHandler.js`, `app.js` |
| **Prototype pollution / HPP** | Se descartan claves `__proto__`, `constructor`, `prototype`; `hpp` contra parámetros duplicados | `security.js` |
| **DoS por payload** | Cuerpos limitados a 10 kB, timeout de 4 s a la API externa | `app.js`, `currencyService.js` |
| **Datos financieros** | Montos en `NUMERIC`, conversión en centavos enteros, tasa y fuente guardadas por gasto | `currencyService.js`, `Gasto.js` |

---

## Pruebas del Viernes

### Automáticas

```bash
npm test               # 26 pruebas unitarias, no requieren base de datos
npm start              # en otra terminal
npm run qa:ataques     # 21 ataques contra el servidor en ejecución
QA_RATE_LIMIT=1 npm run qa:ataques   # incluye fuerza bruta (bloquea tu IP 15 minutos)
```

`qa:ataques` intenta, entre otros: `<script>` en nombre y descripción, `<img onerror>`, `' OR '1'='1' --` en login, `'); DROP TABLE gastos; --` en descripción, SQL en monto y filtros, JWT con `alg: none` y con clave falsa, prototype pollution, aprobar sin rol, peticiones desde otro origen, cuerpos gigantes y reutilizar un token tras cerrar sesión.

### Manuales (equipo Frontend)

1. **Validación del cliente:** escribe `<script>alert(1)</script>` en la descripción del gasto. Debe aparecer "No se permiten etiquetas HTML, scripts ni los caracteres…".
2. **Saltar el cliente:** en DevTools, abre la consola y ejecuta
   `fetch('/api/gastos', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ descripcion: "<script>alert(1)</script>Taxi", categoria: 'transporte', montoEnUSD: '10', fechaGasto: new Date().toISOString().slice(0,10) }) }).then(r => r.json()).then(console.log)`.
   El servidor debe guardar solo `Taxi`.
3. **SQL literal:** registra un gasto con descripción `Taxi'); DROP TABLE gastos; --`. Debe aparecer tal cual en el libro y la tabla debe seguir funcionando.
4. **Cookie inaccesible:** en la consola ejecuta `document.cookie`. Debe devolver `''` aunque haya sesión activa.
5. **Clickjacking:** crea un HTML local con `<iframe src="http://localhost:3000">`. El navegador debe negarse a mostrarlo.
6. **Storage:** en DevTools > Application > Session Storage solo deben existir `fc.perfil`, `fc.tasa` y `fc.filtro`, nunca un token.
7. **errorHandler:** visita `/api/test/error`. Debe responder un mensaje genérico sin stack trace, y la app debe seguir funcionando.

---

## Configurar OAuth 2.0 (opcional)

Los botones de Google y GitHub solo aparecen cuando sus credenciales existen en `.env`.

**Google:** en Google Cloud Console crea un "ID de cliente OAuth" de tipo aplicación web y agrega como URI de redirección `http://localhost:3000/api/auth/google/callback`. Copia el ID y el secreto en `GOOGLE_CLIENT_ID` y `GOOGLE_CLIENT_SECRET`.

**GitHub:** en Settings > Developer settings > OAuth Apps crea una app con callback `http://localhost:3000/api/auth/github/callback` y copia los valores en `GITHUB_CLIENT_ID` y `GITHUB_CLIENT_SECRET`.

Si el correo del proveedor coincide con una cuenta existente, solo se vinculan cuando el proveedor confirma que el correo está verificado. Si el usuario tiene 2FA activo, después de OAuth también se le pide el código.

---

## Ajustes respecto al material inicial del Lunes

El proyecto conserva los nombres y contratos que el equipo ya conoce (`errorHandler`, `window.Validators`, `generarToken`, `verificarTokenMiddleware`, `obtenerTasaCambio`, `crearGasto`, formato `{ status, statusCode, message }`), pero corrige estos puntos:

1. **`currencyService.js` nunca consultaba la API.** La URL `https://er-api.com{monedaBase}` estaba mal formada (faltaban `/v6/latest/` y el `$` de la interpolación), y `require('node-fetch')` lanzaba error porque el paquete no está instalado. Ambos fallos caían en el `catch` y devolvían siempre 4000 sin avisar. Ahora usa `fetch` nativo, la URL correcta y registra la fuente de la tasa.
2. **Clave JWT por defecto.** `process.env.JWT_SECRET || 'CLAVE_SECRETA_POR_DEFECTO…'` permite falsificar tokens si falta el `.env`. Ahora el servidor no arranca sin una clave de al menos 32 caracteres, y `jwt.verify` fija el algoritmo.
3. **`sanitizeInput()` + `textContent` producen doble codificación.** Si se escapa el texto y luego se asigna con `textContent`, el usuario verá `&lt;` u `O&#x27;Neil` en pantalla. `textContent` ya es la protección; para limpiar texto se usa `Validators.limpiarTexto()`. `sanitizeInput()` se mantiene solo por compatibilidad.
4. **Regex de contraseña.** La original solo aceptaba los símbolos `@$!%*?&`, así que rechazaba contraseñas fuertes con `#`, `.` o `-`. Ahora acepta cualquier símbolo y tiene tope de 72 caracteres (límite real de bcrypt). Frontend y backend usan exactamente los mismos patrones, y `validators.test.js` lo verifica.
5. **`app.js`:** `express.static('src/public')` fallaba si el servidor se ejecutaba desde otra carpeta; no había límite de tamaño en `express.json()`; `max` está obsoleto en express-rate-limit (ahora `limit`); faltaba la respuesta 404; y la CSP por defecto de Helmet permite estilos `unsafe-inline`.
6. **Multiplicación con coma flotante.** `montoEnUSD * tasaCambio` puede generar centavos erróneos. Se calcula en centavos enteros.

---

## Antes de desplegar

Configura `NODE_ENV=production`, usa HTTPS, genera claves nuevas para `JWT_SECRET` y `TOTP_ENCRYPTION_KEY`, define `APP_BASE_URL` y las URL de callback OAuth con el dominio real, ajusta `TRUST_PROXY` si hay un proxy delante (Render, Railway, Nginx), activa `DB_SSL=true` si tu proveedor lo exige, y actualiza `FALLBACK_USD_COP_RATE` a un valor vigente.

## ¿Y si el equipo prefiere MySQL?

Cambia `pg` por `mysql2`, usa `?` en lugar de `$1` en los modelos, reemplaza `GENERATED ALWAYS AS IDENTITY` por `AUTO_INCREMENT`, `TIMESTAMPTZ` por `DATETIME` y `RETURNING` por una consulta posterior al `insertId`. La regla de consultas parametrizadas no cambia.
