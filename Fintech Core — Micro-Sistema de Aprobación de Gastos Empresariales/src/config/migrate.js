/**
 * Migración de base de datos — Sprint Lunes.
 * Uso: npm run db:migrate
 *
 * Es idempotente (IF NOT EXISTS): se puede ejecutar varias veces sin romper nada.
 * Las restricciones CHECK duplican en la BD las reglas de negocio validadas en la API,
 * así un dato inválido nunca llega a persistirse aunque falle otra capa.
 */
require('dotenv').config({ quiet: true });
const { pool } = require('./db');

const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS usuarios (
  id                     INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  nombre                 VARCHAR(80)  NOT NULL,
  email                  VARCHAR(254) NOT NULL UNIQUE,
  password_hash          VARCHAR(100),                       -- NULL para cuentas creadas solo con OAuth
  rol                    VARCHAR(20)  NOT NULL DEFAULT 'empleado'
                         CHECK (rol IN ('empleado', 'aprobador')),
  google_id              VARCHAR(100) UNIQUE,
  github_id              VARCHAR(100) UNIQUE,
  two_factor_enabled     BOOLEAN      NOT NULL DEFAULT FALSE,
  two_factor_secret      TEXT,                               -- cifrado con AES-256-GCM
  two_factor_temp_secret TEXT,                               -- secreto pendiente de confirmar
  two_factor_last_step   BIGINT,                             -- anti-reutilización de códigos TOTP
  token_version          INTEGER      NOT NULL DEFAULT 0,    -- permite revocar JWT emitidos
  creado_en              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  actualizado_en         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  CONSTRAINT email_en_minusculas CHECK (email = LOWER(email))
);

CREATE TABLE IF NOT EXISTS gastos (
  id                   INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  usuario_id           INTEGER       NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  descripcion          VARCHAR(200)  NOT NULL,
  categoria            VARCHAR(30)   NOT NULL
                       CHECK (categoria IN ('transporte', 'alimentacion', 'hospedaje', 'software', 'equipos', 'otros')),
  monto_usd            NUMERIC(12,2) NOT NULL CHECK (monto_usd > 0 AND monto_usd <= 100000),
  tasa_cambio          NUMERIC(14,4) NOT NULL CHECK (tasa_cambio > 0),
  monto_cop            NUMERIC(18,2) NOT NULL CHECK (monto_cop > 0),
  fuente_tasa          VARCHAR(20)   NOT NULL CHECK (fuente_tasa IN ('api', 'cache', 'respaldo')),
  fecha_gasto          DATE          NOT NULL,
  estado               VARCHAR(20)   NOT NULL DEFAULT 'pendiente'
                       CHECK (estado IN ('pendiente', 'aprobado', 'rechazado')),
  aprobador_id         INTEGER       REFERENCES usuarios(id) ON DELETE SET NULL,
  comentario_aprobador VARCHAR(200),
  decidido_en          TIMESTAMPTZ,
  creado_en            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  -- Segregación de funciones: nadie aprueba su propio gasto.
  CONSTRAINT no_autoaprobacion CHECK (aprobador_id IS NULL OR aprobador_id <> usuario_id)
);

CREATE INDEX IF NOT EXISTS idx_gastos_usuario_fecha ON gastos (usuario_id, creado_en DESC);
CREATE INDEX IF NOT EXISTS idx_gastos_estado        ON gastos (estado);
`;

async function migrate() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(MIGRATION_SQL);
    await client.query('COMMIT');
    console.log('✔ Migración aplicada: tablas "usuarios" y "gastos" listas.');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('✖ La migración falló y se revirtió:', err.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
