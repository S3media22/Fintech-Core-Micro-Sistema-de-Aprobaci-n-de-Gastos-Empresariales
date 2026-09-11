/**
 * Modelo de la tabla "usuarios".
 * Todas las consultas usan marcadores $n: los valores nunca se concatenan al SQL.
 */
const { query } = require('../config/db');

// Único caso donde se interpola un identificador: sale de esta lista blanca, nunca del usuario.
const PROVIDER_COLUMNS = Object.freeze({ google: 'google_id', github: 'github_id' });

function providerColumn(provider) {
  const column = PROVIDER_COLUMNS[provider];
  if (!column) throw new Error(`Proveedor OAuth no soportado: ${provider}`);
  return column;
}

/** Correos con rol "aprobador", definidos por el administrador en ADMIN_EMAILS. */
function rolParaEmail(email) {
  const aprobadores = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  return aprobadores.includes(String(email).toLowerCase()) ? 'aprobador' : 'empleado';
}

/** Proyección segura para enviar al cliente: nunca incluye hashes ni secretos. */
function toPublic(row) {
  if (!row) return null;
  return {
    id: row.id,
    nombre: row.nombre,
    email: row.email,
    rol: row.rol,
    dosPasosActivo: row.two_factor_enabled,
    tienePassword: Boolean(row.password_hash),
    googleVinculado: Boolean(row.google_id),
    githubVinculado: Boolean(row.github_id),
    creadoEn: row.creado_en,
  };
}

const User = {
  rolParaEmail,
  toPublic,

  async findById(id) {
    const { rows } = await query('SELECT * FROM usuarios WHERE id = $1', [id]);
    return rows[0] || null;
  },

  async findByEmail(email) {
    const { rows } = await query('SELECT * FROM usuarios WHERE email = $1', [String(email).toLowerCase()]);
    return rows[0] || null;
  },

  async create({ nombre, email, passwordHash }) {
    const normalized = String(email).toLowerCase();
    const { rows } = await query(
      `INSERT INTO usuarios (nombre, email, password_hash, rol)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [nombre, normalized, passwordHash, rolParaEmail(normalized)]
    );
    return rows[0];
  },

  async findByProvider(provider, providerId) {
    const { rows } = await query(`SELECT * FROM usuarios WHERE ${providerColumn(provider)} = $1`, [String(providerId)]);
    return rows[0] || null;
  },

  async linkProvider(userId, provider, providerId) {
    const { rows } = await query(
      `UPDATE usuarios SET ${providerColumn(provider)} = $1, actualizado_en = NOW()
       WHERE id = $2
       RETURNING *`,
      [String(providerId), userId]
    );
    return rows[0];
  },

  async createFromOAuth({ nombre, email, provider, providerId }) {
    const normalized = String(email).toLowerCase();
    const { rows } = await query(
      `INSERT INTO usuarios (nombre, email, rol, ${providerColumn(provider)})
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [nombre, normalized, rolParaEmail(normalized), String(providerId)]
    );
    return rows[0];
  },

  async setTempTwoFactorSecret(userId, encryptedSecret) {
    await query(
      'UPDATE usuarios SET two_factor_temp_secret = $1, actualizado_en = NOW() WHERE id = $2',
      [encryptedSecret, userId]
    );
  },

  /** Promueve el secreto temporal a definitivo e invalida los tokens anteriores. */
  async enableTwoFactor(userId, usedStep) {
    const { rows } = await query(
      `UPDATE usuarios
          SET two_factor_secret = two_factor_temp_secret,
              two_factor_temp_secret = NULL,
              two_factor_enabled = TRUE,
              two_factor_last_step = $1,
              token_version = token_version + 1,
              actualizado_en = NOW()
        WHERE id = $2 AND two_factor_temp_secret IS NOT NULL
        RETURNING *`,
      [usedStep, userId]
    );
    return rows[0] || null;
  },

  async disableTwoFactor(userId) {
    const { rows } = await query(
      `UPDATE usuarios
          SET two_factor_secret = NULL,
              two_factor_temp_secret = NULL,
              two_factor_enabled = FALSE,
              two_factor_last_step = NULL,
              token_version = token_version + 1,
              actualizado_en = NOW()
        WHERE id = $1
        RETURNING *`,
      [userId]
    );
    return rows[0] || null;
  },

  /**
   * Registra el paso TOTP usado solo si es posterior al último.
   * Si dos peticiones usan el mismo código a la vez, solo una actualiza la fila.
   */
  async consumeTotpStep(userId, step) {
    const { rowCount } = await query(
      `UPDATE usuarios SET two_factor_last_step = $1
        WHERE id = $2 AND (two_factor_last_step IS NULL OR two_factor_last_step < $1)`,
      [step, userId]
    );
    return rowCount === 1;
  },

  async incrementTokenVersion(userId) {
    await query('UPDATE usuarios SET token_version = token_version + 1, actualizado_en = NOW() WHERE id = $1', [userId]);
  },
};

module.exports = User;
