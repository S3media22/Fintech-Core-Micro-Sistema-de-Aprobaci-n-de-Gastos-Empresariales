/**
 * Controlador de gastos (Sprint Jueves).
 * Une el microservicio de divisas con el modelo, siguiendo el ejemplo del material:
 *   exports.crearGasto = async (req, res, next) => { ... CurrencyService.obtenerTasaCambio('USD', 'COP') ... }
 *
 * Diferencias con el ejemplo inicial:
 *  - La inserción parametrizada en BD ya está implementada (Gasto.create) usando req.user.id del JWT.
 *  - El monto se convierte en centavos enteros, no con montoEnUSD * tasa (coma flotante).
 *  - Se guarda la tasa aplicada y su fuente para auditoría.
 */
const Gasto = require('../models/Gasto');
const CurrencyService = require('../services/currencyService');
const { AppError, asyncHandler } = require('../middlewares/errorHandler');

/** GET /api/gastos?estado=aprobado — "Ver Gastos" del usuario autenticado */
exports.listarGastos = asyncHandler(async (req, res) => {
  const estado = req.query.estado || undefined;
  const [gastos, resumen] = await Promise.all([
    Gasto.findByUsuario(req.user.id, { estado }),
    Gasto.resumenPorUsuario(req.user.id),
  ]);

  res.json({ status: 'success', data: { gastos, resumen } });
});

/** POST /api/gastos — "Crear Gasto" con conversión USD → COP */
exports.crearGasto = asyncHandler(async (req, res) => {
  const { descripcion, categoria, montoEnUSD, fechaGasto } = req.body;

  // 1. Consumir la API externa (con caché y respaldo trazable)
  let tasa;
  try {
    tasa = await CurrencyService.obtenerTasaDetallada('USD', 'COP');
  } catch {
    throw new AppError('El servicio de tasas de cambio no está disponible. Intenta en unos minutos.', 503);
  }

  // 2. Calcular el monto convertido de forma exacta
  const montoFinalCOP = CurrencyService.convertirMonto(montoEnUSD, tasa.tasa);

  // 3. Inserción parametrizada usando el id que viene del JWT verificado (nunca del body)
  const gasto = await Gasto.create({
    usuarioId: req.user.id,
    descripcion,
    categoria,
    montoUsd: montoEnUSD,
    tasaCambio: tasa.tasa.toFixed(4),
    montoCop: montoFinalCOP,
    fuenteTasa: tasa.fuente,
    fechaGasto,
  });

  res.status(201).json({
    status: 'success',
    message: 'Gasto registrado con conversión de divisa exitosa.',
    data: {
      gasto,
      descripcion: gasto.descripcion,
      montoOriginalUSD: gasto.montoUsd,
      tasaAplicada: gasto.tasaCambio,
      montoFinalCOP: gasto.montoCop,
      fuenteTasa: tasa.fuente,
    },
  });
});

/** GET /api/gastos/tasa — tasa del día para mostrar en el dashboard */
exports.obtenerTasa = asyncHandler(async (req, res) => {
  try {
    const tasa = await CurrencyService.obtenerTasaDetallada('USD', 'COP');
    res.json({ status: 'success', data: { tasa } });
  } catch {
    throw new AppError('El servicio de tasas de cambio no está disponible.', 503);
  }
});

/** GET /api/gastos/pendientes — bandeja del aprobador */
exports.listarPendientes = asyncHandler(async (req, res) => {
  const gastos = await Gasto.findPendientesParaAprobador(req.user.id);
  res.json({ status: 'success', data: { gastos } });
});

/** PATCH /api/gastos/:id/estado — aprobar o rechazar */
exports.decidirGasto = asyncHandler(async (req, res) => {
  const id = Number(req.params.id);
  const { estado, comentario } = req.body;

  const gasto = await Gasto.decidir({ id, estado, aprobadorId: req.user.id, comentario });
  if (gasto) {
    return res.json({
      status: 'success',
      message: estado === 'aprobado' ? 'Gasto aprobado.' : 'Gasto rechazado.',
      data: { gasto },
    });
  }

  // No se actualizó: se explica el motivo exacto sin exponer datos ajenos.
  const actual = await Gasto.findRawById(id);
  if (!actual) throw new AppError('El gasto no existe.', 404);
  if (actual.usuario_id === req.user.id) throw new AppError('No puedes decidir sobre tus propios gastos.', 403);
  throw new AppError('Este gasto ya fue decidido por otro aprobador.', 409);
});
