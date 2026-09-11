/**
 * Endpoints protegidos de gastos. Todas las rutas exigen un JWT válido en cookie HttpOnly.
 */
const express = require('express');
const { body, param, query } = require('express-validator');
const gastos = require('../controllers/gastoController');
const Gasto = require('../models/Gasto');
const { verificarTokenMiddleware, requireRole } = require('../middlewares/authMiddleware');
const { validate, PATTERNS } = require('../middlewares/security');

const router = express.Router();
const MONTO_MAXIMO_USD = 100_000;
const DIAS_MAXIMOS_ANTIGUEDAD = 365;

function fechaLocalIso(date) {
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 10);
}

/* Reglas ----------------------------------------------------------- */

const crearRules = [
  body('descripcion')
    .isString().withMessage('La descripción es obligatoria.')
    .bail()
    .trim()
    .matches(PATTERNS.textoSeguro)
    .withMessage('La descripción debe tener de 3 a 100 caracteres, sin < > { } ni comillas invertidas.'),
  body('categoria')
    .isIn(Gasto.CATEGORIAS).withMessage('Selecciona una categoría de la lista.'),
  body('montoEnUSD')
    .customSanitizer((v) => (typeof v === 'number' ? String(v) : v))
    .isString().withMessage('El monto es obligatorio.')
    .bail()
    .trim()
    .matches(PATTERNS.montoUsd).withMessage('Escribe el monto en dólares con máximo 2 decimales, por ejemplo 125.50.')
    .bail()
    .custom((v) => Number(v) > 0 && Number(v) <= MONTO_MAXIMO_USD)
    .withMessage(`El monto debe ser mayor que 0 y como máximo ${MONTO_MAXIMO_USD.toLocaleString('es-CO')} USD.`),
  body('fechaGasto')
    .isString().withMessage('La fecha es obligatoria.')
    .bail()
    .matches(PATTERNS.fechaIso).withMessage('La fecha debe tener formato AAAA-MM-DD.')
    .bail()
    .custom((v) => {
      const hoy = new Date();
      const manana = new Date(hoy.getTime() + 86_400_000); // tolerancia por zona horaria del cliente
      const limite = new Date(hoy.getTime() - DIAS_MAXIMOS_ANTIGUEDAD * 86_400_000);
      const valida = !Number.isNaN(Date.parse(`${v}T00:00:00Z`)) && fechaLocalIso(new Date(`${v}T12:00:00`)) === v;
      return valida && v <= fechaLocalIso(manana) && v >= fechaLocalIso(limite);
    })
    .withMessage('La fecha no puede ser futura ni de hace más de un año.'),
];

const listarRules = [
  query('estado').optional().isIn(Gasto.ESTADOS).withMessage('Estado de filtro no válido.'),
];

const decidirRules = [
  param('id').isInt({ min: 1, max: 2_147_483_647 }).withMessage('Identificador de gasto inválido.'),
  body('estado').isIn(Gasto.DECISIONES).withMessage('La decisión debe ser "aprobado" o "rechazado".'),
  body('comentario')
    .optional({ values: 'falsy' })
    .isString()
    .bail()
    .trim()
    .matches(PATTERNS.textoSeguro)
    .withMessage('El comentario debe tener de 3 a 100 caracteres, sin < > { } ni comillas invertidas.'),
  body('comentario').custom((value, { req }) => {
    if (req.body.estado === 'rechazado' && !value) throw new Error('Explica el motivo del rechazo.');
    return true;
  }),
];

/* Rutas ------------------------------------------------------------ */

router.use(verificarTokenMiddleware); // todas las rutas de gastos exigen JWT válido

router.get('/', listarRules, validate, gastos.listarGastos);
router.post('/', crearRules, validate, gastos.crearGasto);
router.get('/tasa', gastos.obtenerTasa);
router.get('/pendientes', requireRole('aprobador'), gastos.listarPendientes);
router.patch('/:id/estado', requireRole('aprobador'), decidirRules, validate, gastos.decidirGasto);

module.exports = router;
