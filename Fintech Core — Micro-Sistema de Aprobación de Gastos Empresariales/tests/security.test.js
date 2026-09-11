/**
 * Pruebas unitarias de la capa de sanitización y validación del servidor (Viernes).
 * Ejecutar: npm test   (no requiere base de datos)
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeString, sanitizeValue, PATTERNS } = require('../src/middlewares/security');

test('elimina etiquetas <script> con su contenido', () => {
  assert.equal(sanitizeString('Taxi <script>alert("xss")</script>aeropuerto'), 'Taxi aeropuerto');
});

test('neutraliza anidamientos que intentan reconstruir la etiqueta', () => {
  const limpio = sanitizeString('<scr<script>ipt>alert(1)</scr</script>ipt>');
  assert.doesNotMatch(limpio, /<\s*script/i);
});

test('elimina manejadores de eventos y esquemas javascript:', () => {
  assert.doesNotMatch(sanitizeString('<img src=x onerror=alert(1)>'), /onerror|<img/i);
  assert.doesNotMatch(sanitizeString('javascript:alert(1)'), /javascript:/i);
});

test('normaliza caracteres Unicode de ancho completo antes de limpiar', () => {
  assert.doesNotMatch(sanitizeString('＜script＞alert(1)＜/script＞'), /script/i);
});

test('conserva texto legítimo con tildes, eñes y comillas', () => {
  assert.equal(sanitizeString("  Almuerzo con cliente en Bogotá, café y O'Neil  "), "Almuerzo con cliente en Bogotá, café y O'Neil");
});

test('bloquea prototype pollution y no toca contraseñas', () => {
  const entrada = JSON.parse('{"__proto__": {"rol": "aprobador"}, "password": "<Clave#123>", "nombre": "<b>Ana</b>"}');
  const limpio = sanitizeValue(entrada);
  assert.equal(limpio.rol, undefined);
  assert.equal({}.rol, undefined);
  assert.equal(limpio.password, '<Clave#123>');
  assert.equal(limpio.nombre, 'Ana');
});

test('los patrones rechazan payloads de inyección donde no aplican', () => {
  assert.equal(PATTERNS.montoUsd.test('1; DELETE FROM gastos'), false);
  assert.equal(PATTERNS.montoUsd.test("100' OR '1'='1"), false);
  assert.equal(PATTERNS.email.test("' OR 1=1 --"), false);
  assert.equal(PATTERNS.textoSeguro.test('<img src=x>'), false);
  assert.equal(PATTERNS.codigoTotp.test('12345a'), false);
});

test('los patrones aceptan datos válidos', () => {
  assert.ok(PATTERNS.montoUsd.test('125.50'));
  assert.ok(PATTERNS.email.test('ana.perez@empresa.com.co'));
  assert.ok(PATTERNS.password.test('Segura#2026'));
  assert.ok(PATTERNS.nombre.test('María José Núñez'));
  assert.ok(PATTERNS.fechaIso.test('2026-09-10'));
});
