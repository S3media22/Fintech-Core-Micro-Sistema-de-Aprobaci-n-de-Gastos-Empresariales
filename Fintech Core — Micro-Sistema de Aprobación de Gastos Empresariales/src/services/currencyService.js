/**
 * Servicio de consumo de API externa de divisas (Microservicio de conversión) — Sprint Jueves.
 *
 * Conserva la interfaz del material entregado:
 *   const tasa = await CurrencyService.obtenerTasaCambio('USD', 'COP'); // → Number
 *
 * Mejoras sobre la versión inicial:
 *  - URL correcta (https://open.er-api.com/v6/latest/USD) y fetch nativo de Node 18+ (sin node-fetch).
 *  - Monedas validadas con lista blanca: nadie puede manipular la URL (SSRF / inyección de ruta).
 *  - Timeout de 4 s: una API lenta no congela el registro de gastos.
 *  - Caché en memoria por moneda base: no se satura la API ni se exceden sus límites.
 *  - Validación de rango: una respuesta corrupta no genera montos absurdos.
 *  - Respaldo TRAZABLE: si la API cae se usa la última tasa conocida o FALLBACK_USD_COP_RATE,
 *    y cada gasto guarda la fuente ('api' | 'cache' | 'respaldo') para auditoría.
 *    En un sistema financiero un respaldo silencioso es un error: siempre debe quedar registrado.
 *  - Conversión en centavos enteros: evita errores de coma flotante (0.1 + 0.2 !== 0.3).
 */

const API_BASE_URL = process.env.EXCHANGE_API_URL || 'https://open.er-api.com/v6/latest';
const REQUEST_TIMEOUT_MS = 4_000;
const MONEDAS_PERMITIDAS = new Set(['USD', 'COP', 'EUR', 'MXN']);
// Cotas de cordura por par de monedas (tasa mínima y máxima aceptable).
const RANGOS = { 'USD-COP': [500, 20_000] };

const cache = new Map(); // clave "USD-COP" → { tasa, obtenidaEn }

function ttlMs() {
  return Number(process.env.EXCHANGE_CACHE_TTL_MS) || 60 * 60 * 1000;
}

function validarMoneda(codigo) {
  const moneda = String(codigo || '').toUpperCase();
  if (!/^[A-Z]{3}$/.test(moneda) || !MONEDAS_PERMITIDAS.has(moneda)) {
    throw new Error(`Moneda no soportada: ${moneda}`);
  }
  return moneda;
}

function tasaValida(par, tasa) {
  if (!Number.isFinite(tasa) || tasa <= 0) return false;
  const [min, max] = RANGOS[par] || [0, Number.MAX_SAFE_INTEGER];
  return tasa >= min && tasa <= max;
}

async function consultarApi(monedaBase, monedaDestino) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const url = `${API_BASE_URL}/${encodeURIComponent(monedaBase)}`;
    const respuesta = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      redirect: 'error',
    });

    if (!respuesta.ok) {
      throw new Error(`Fallo en el servicio externo de divisas. Estatus: ${respuesta.status}`);
    }

    const datos = await respuesta.json();
    const tasa = Number(datos?.rates?.[monedaDestino]);

    if (!tasaValida(`${monedaBase}-${monedaDestino}`, tasa)) {
      throw new Error(`La API devolvió una tasa ${monedaBase}→${monedaDestino} inválida o fuera de rango.`);
    }
    return tasa;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Obtiene la tasa con su procedencia.
 * @returns {Promise<{ tasa: number, fuente: 'api'|'cache'|'respaldo', obtenidaEn: string, monedaBase: string, monedaDestino: string }>}
 */
async function obtenerTasaDetallada(monedaBase = 'USD', monedaDestino = 'COP') {
  const base = validarMoneda(monedaBase);
  const destino = validarMoneda(monedaDestino);
  const par = `${base}-${destino}`;
  const enCache = cache.get(par);
  const resultado = (tasa, fuente, fecha) => ({
    tasa,
    fuente,
    obtenidaEn: new Date(fecha).toISOString(),
    monedaBase: base,
    monedaDestino: destino,
  });

  if (enCache && Date.now() - enCache.obtenidaEn < ttlMs()) {
    return resultado(enCache.tasa, 'api', enCache.obtenidaEn);
  }

  try {
    const tasa = await consultarApi(base, destino);
    cache.set(par, { tasa, obtenidaEn: Date.now() });
    return resultado(tasa, 'api', Date.now());
  } catch (error) {
    console.error(`[FALLO MICROSERVICIO API EXTERNA]: ${error.message}`);

    if (enCache) {
      console.warn(`[API FALLBACK]: Usando la última tasa conocida ${par}: ${enCache.tasa}`);
      return resultado(enCache.tasa, 'cache', enCache.obtenidaEn);
    }

    const respaldo = Number(process.env.FALLBACK_USD_COP_RATE);
    if (par === 'USD-COP' && tasaValida(par, respaldo)) {
      console.warn(`[API FALLBACK]: Usando tasa de respaldo configurada: ${respaldo}`);
      return resultado(respaldo, 'respaldo', Date.now());
    }

    throw new Error(`No hay tasa ${par} disponible y no existe un respaldo válido configurado.`);
  }
}

/** Interfaz simple del material del Lunes: devuelve solo el número. */
async function obtenerTasaCambio(monedaBase = 'USD', monedaDestino = 'COP') {
  const { tasa } = await obtenerTasaDetallada(monedaBase, monedaDestino);
  return tasa;
}

/**
 * Convierte un monto usando centavos enteros.
 * @param {string|number} monto  p. ej. "125.50"
 * @param {number} tasa          p. ej. 3987.1234
 * @returns {string} monto convertido con 2 decimales, p. ej. "500383.99"
 */
function convertirMonto(monto, tasa) {
  const [enteros, decimales = ''] = String(monto).split('.');
  const centavos = Number(enteros) * 100 + Number(decimales.padEnd(2, '0').slice(0, 2));
  const tasaEscalada = Math.round(Number(tasa) * 10_000); // 4 decimales de precisión
  const centavosConvertidos = Math.round((centavos * tasaEscalada) / 10_000);
  return (centavosConvertidos / 100).toFixed(2);
}

/** Solo para pruebas automatizadas. */
function _limpiarCache() {
  cache.clear();
}

const CurrencyService = { obtenerTasaCambio, obtenerTasaDetallada, convertirMonto, _limpiarCache };

module.exports = CurrencyService;
