/**
 * Verifica que las validaciones del frontend (validators.js) y del backend (security.js)
 * acepten y rechacen exactamente los mismos datos.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const Validators = require('../src/public/js/validators.js');
const { PATTERNS } = require('../src/middlewares/security');

const PARES = [
  ['emailRegex', 'email', ['ana@empresa.com', 'A.B+c@sub.dominio.co', "' OR 1=1 --", 'ana@', 'ana@empresa', 'a b@c.com']],
  ['passwordRegex', 'password', ['Segura#2026', 'Clave.Larga9', 'corta1A!', 'sinmayuscula1!', 'SINMINUSCULA1!', 'SinNumero!!', 'SinSimbolo12', 'Espacio 1Aa']],
  ['nombreRegex', 'nombre', ['Ana', 'María José Núñez', "O'Neil", 'A', 'Ana<script>', 'Juan123']],
  ['textoSeguroRegex', 'textoSeguro', ['Taxi al aeropuerto', "'; DROP TABLE gastos; --", '<img src=x>', 'ab', '{{7*7}}', 'Hotel `x`']],
  ['montoRegex', 'montoUsd', ['1', '125.5', '125.50', '999999.99', '125.505', '-5', '1e3', '1; DELETE']],
  ['codigoRegex', 'codigoTotp', ['123456', '12345', '1234567', 'abcdef']],
];

for (const [regexFront, patronBack, muestras] of PARES) {
  test(`paridad front/back: ${regexFront} ↔ PATTERNS.${patronBack}`, () => {
    for (const muestra of muestras) {
      assert.equal(
        Validators[regexFront].test(muestra),
        PATTERNS[patronBack].test(muestra),
        `Difieren con la muestra: ${muestra}`
      );
    }
  });
}

test('reglas del cliente detectan código malicioso con mensaje claro', () => {
  assert.match(Validators.reglas.descripcion('<script>alert(1)</script>'), /etiquetas HTML/);
  assert.match(Validators.reglas.nombre('<img src=x onerror=alert(1)>'), /etiquetas HTML/);
  assert.equal(Validators.reglas.descripcion('Almuerzo con cliente'), '');
});

test('normalizarMonto acepta coma decimal', () => {
  assert.equal(Validators.normalizarMonto(' 125,50 '), '125.50');
  assert.equal(Validators.reglas.montoEnUSD('125,50'), '');
  assert.notEqual(Validators.reglas.montoEnUSD('0'), '');
  assert.notEqual(Validators.reglas.montoEnUSD('100000.01'), '');
});

test('API del material del Lunes sigue funcionando', () => {
  assert.equal(Validators.validateUserForm('ana@empresa.com', 'Segura#2026').isValid, true);
  assert.equal(Validators.validateUserForm('ana@empresa.com', 'debil').isValid, false);
  assert.equal(Validators.validateGastoForm('Taxi', '38.00').isValid, true);
  assert.equal(Validators.sanitizeInput('<b>"x"</b>'), '&lt;b&gt;&quot;x&quot;&lt;&#x2F;b&gt;');
});
