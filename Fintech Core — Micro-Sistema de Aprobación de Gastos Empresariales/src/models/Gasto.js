/**
 * Modelo de la tabla "gastos".
 * Todas las consultas son parametrizadas y filtran por usuario cuando corresponde,
 * evitando que alguien lea gastos ajenos cambiando un id (OWASP A01: Broken Access Control).
 */
const { query } = require('../config/db');

const CATEGORIAS = Object.freeze(['transporte', 'alimentacion', 'hospedaje', 'software', 'equipos', 'otros']);
const ESTADOS = Object.freeze(['pendiente', 'aprobado', 'rechazado']);
const DECISIONES = Object.freeze(['aprobado', 'rechazado']);

// to_char evita desfases de zona horaria al convertir DATE a objeto Date de JS.
const SELECT_FIELDS = `
  g.id, g.usuario_id, g.descripcion, g.categoria,
  g.monto_usd, g.tasa_cambio, g.monto_cop, g.fuente_tasa,
  to_char(g.fecha_gasto, 'YYYY-MM-DD') AS fecha_gasto,
  g.estado, g.comentario_aprobador, g.decidido_en, g.creado_en
`;

/** Convierte la fila de BD al formato de la API. Los NUMERIC llegan como string (sin pérdida de precisión). */
function toDTO(row) {
  if (!row) return null;
  const dto = {
    id: row.id,
    descripcion: row.descripcion,
    categoria: row.categoria,
    montoUsd: row.monto_usd,
    tasaCambio: row.tasa_cambio,
    montoCop: row.monto_cop,
    fuenteTasa: row.fuente_tasa,
    fechaGasto: row.fecha_gasto,
    estado: row.estado,
    comentarioAprobador: row.comentario_aprobador,
    decididoEn: row.decidido_en,
    creadoEn: row.creado_en,
  };
  if (row.solicitante !== undefined) dto.solicitante = row.solicitante;
  if (row.aprobador !== undefined) dto.aprobador = row.aprobador;
  return dto;
}

const Gasto = {
  CATEGORIAS,
  ESTADOS,
  DECISIONES,
  toDTO,

  async create({ usuarioId, descripcion, categoria, montoUsd, tasaCambio, montoCop, fuenteTasa, fechaGasto }) {
    const { rows } = await query(
      `WITH nuevo AS (
         INSERT INTO gastos (usuario_id, descripcion, categoria, monto_usd, tasa_cambio, monto_cop, fuente_tasa, fecha_gasto)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *
       )
       SELECT ${SELECT_FIELDS} FROM nuevo g`,
      [usuarioId, descripcion, categoria, montoUsd, tasaCambio, montoCop, fuenteTasa, fechaGasto]
    );
    return toDTO(rows[0]);
  },

  /** Gastos del propio usuario, con filtro opcional por estado. */
  async findByUsuario(usuarioId, { estado } = {}) {
    const params = [usuarioId];
    let sql = `SELECT ${SELECT_FIELDS}, a.nombre AS aprobador
                 FROM gastos g
                 LEFT JOIN usuarios a ON a.id = g.aprobador_id
                WHERE g.usuario_id = $1`;

    if (estado) {
      params.push(estado);
      sql += ` AND g.estado = $${params.length}`; // se agrega el MARCADOR, no el valor
    }
    sql += ' ORDER BY g.fecha_gasto DESC, g.id DESC LIMIT 200';

    const { rows } = await query(sql, params);
    return rows.map(toDTO);
  },

  async resumenPorUsuario(usuarioId) {
    const { rows } = await query(
      `SELECT estado,
              COUNT(*)::int                  AS cantidad,
              COALESCE(SUM(monto_usd), 0)    AS total_usd,
              COALESCE(SUM(monto_cop), 0)    AS total_cop
         FROM gastos
        WHERE usuario_id = $1
        GROUP BY estado`,
      [usuarioId]
    );

    const resumen = Object.fromEntries(ESTADOS.map((e) => [e, { cantidad: 0, totalUsd: '0', totalCop: '0' }]));
    for (const r of rows) {
      resumen[r.estado] = { cantidad: r.cantidad, totalUsd: r.total_usd, totalCop: r.total_cop };
    }
    return resumen;
  },

  /** Gastos pendientes de OTROS usuarios (un aprobador no ve los suyos en su bandeja). */
  async findPendientesParaAprobador(aprobadorId) {
    const { rows } = await query(
      `SELECT ${SELECT_FIELDS}, u.nombre AS solicitante
         FROM gastos g
         JOIN usuarios u ON u.id = g.usuario_id
        WHERE g.estado = 'pendiente' AND g.usuario_id <> $1
        ORDER BY g.creado_en ASC
        LIMIT 200`,
      [aprobadorId]
    );
    return rows.map(toDTO);
  },

  async findRawById(id) {
    const { rows } = await query('SELECT id, usuario_id, estado FROM gastos WHERE id = $1', [id]);
    return rows[0] || null;
  },

  /**
   * Aprueba o rechaza de forma atómica: solo cambia si sigue pendiente y no es del propio aprobador.
   * Así dos aprobadores simultáneos no pueden decidir el mismo gasto dos veces.
   */
  async decidir({ id, estado, aprobadorId, comentario }) {
    const { rows } = await query(
      `WITH actualizado AS (
         UPDATE gastos
            SET estado = $1, aprobador_id = $2, comentario_aprobador = $3, decidido_en = NOW()
          WHERE id = $4 AND estado = 'pendiente' AND usuario_id <> $2
          RETURNING *
       )
       SELECT ${SELECT_FIELDS}, u.nombre AS solicitante
         FROM actualizado g
         JOIN usuarios u ON u.id = g.usuario_id`,
      [estado, aprobadorId, comentario || null, id]
    );
    return toDTO(rows[0]);
  },
};

module.exports = Gasto;
