/**
 * Pruebas del microservicio de divisas con fetch simulado (no depende de internet).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const CurrencyService = require('../src/services/currencyService');

const fetchOriginal = global.fetch;

function simularFetch(respuesta) {
  global.fetch = async () => respuesta;
}

test.afterEach(() => {
  global.fetch = fetchOriginal;
  CurrencyService._limpiarCache();
  delete process.env.FALLBACK_USD_COP_RATE;
});

test('convierte en centavos sin errores de coma flotante', () => {
  assert.equal(CurrencyService.convertirMonto('0.10', 3), '0.30');
  assert.equal(CurrencyService.convertirMonto('38.00', 4012.5), '152475.00');
  assert.equal(CurrencyService.convertirMonto('125.5', 3987.1234), '500383.99');
  assert.equal(CurrencyService.convertirMonto('100000', 4123.4567), '412345670.00');
});

test('usa la API cuando responde bien', async () => {
  simularFetch({ ok: true, status: 200, json: async () => ({ rates: { COP: 4100.25 } }) });
  const tasa = await CurrencyService.obtenerTasaDetallada('USD', 'COP');
  assert.equal(tasa.tasa, 4100.25);
  assert.equal(tasa.fuente, 'api');
  assert.equal(await CurrencyService.obtenerTasaCambio('USD', 'COP'), 4100.25);
});

test('rechaza tasas absurdas y usa el respaldo configurado, dejando la fuente registrada', async () => {
  process.env.FALLBACK_USD_COP_RATE = '4000';
  simularFetch({ ok: true, status: 200, json: async () => ({ rates: { COP: 0.0001 } }) });
  const tasa = await CurrencyService.obtenerTasaDetallada('USD', 'COP');
  assert.equal(tasa.tasa, 4000);
  assert.equal(tasa.fuente, 'respaldo');
});

test('si la API cae después de un éxito, usa la última tasa conocida', async () => {
  process.env.EXCHANGE_CACHE_TTL_MS = '1';
  simularFetch({ ok: true, status: 200, json: async () => ({ rates: { COP: 3950 } }) });
  await CurrencyService.obtenerTasaDetallada('USD', 'COP');
  await new Promise((r) => setTimeout(r, 5));

  global.fetch = async () => {
    throw new Error('red caída');
  };
  const tasa = await CurrencyService.obtenerTasaDetallada('USD', 'COP');
  assert.equal(tasa.tasa, 3950);
  assert.equal(tasa.fuente, 'cache');
  delete process.env.EXCHANGE_CACHE_TTL_MS;
});

test('sin API ni respaldo válido lanza error en lugar de inventar una tasa', async () => {
  simularFetch({ ok: false, status: 503, json: async () => ({}) });
  await assert.rejects(() => CurrencyService.obtenerTasaDetallada('USD', 'COP'));
});

test('bloquea monedas fuera de la lista blanca (manipulación de URL)', async () => {
  await assert.rejects(() => CurrencyService.obtenerTasaDetallada('../../admin', 'COP'), /no soportada/);
  await assert.rejects(() => CurrencyService.obtenerTasaDetallada('USD', 'BTC'), /no soportada/);
});
