/**
 * Conexión a PostgreSQL mediante un pool de conexiones (node-postgres).
 *
 * Regla anti SQL Injection del proyecto: NUNCA se concatenan valores del usuario
 * dentro del texto SQL. Todos los valores viajan como parámetros ($1, $2, ...)
 * y el driver los envía por separado al motor, que jamás los interpreta como código.
 */
const { Pool } = require('pg');

const useSsl = process.env.DB_SSL === 'true';

const poolLimits = {
  // Límites del pool: evitan agotar el servidor de BD ante picos o ataques.
  max: Number(process.env.DB_POOL_MAX) || 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
};

const connection = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL }
  : {
      host: process.env.DB_HOST || 'localhost',
      port: Number(process.env.DB_PORT) || 5432,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    };

const pool = new Pool({
  ...connection,
  ...poolLimits,
  ssl: useSsl ? { rejectUnauthorized: true } : false,
});

pool.on('error', (err) => {
  console.error('[db] Error inesperado en un cliente inactivo del pool:', err.message);
});

/**
 * Ejecuta una consulta parametrizada.
 * @param {string} text  SQL con marcadores $1, $2...
 * @param {Array}  params Valores que reemplazan a los marcadores.
 */
async function query(text, params = []) {
  if (typeof text !== 'string') {
    throw new TypeError('La consulta SQL debe ser un string.');
  }
  if (!Array.isArray(params)) {
    throw new TypeError('Los valores deben enviarse como arreglo (consulta parametrizada).');
  }
  return pool.query(text, params);
}

/**
 * Ejecuta varias consultas dentro de una transacción (todo o nada).
 * @param {(client: import('pg').PoolClient) => Promise<any>} work
 */
async function withTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function testConnection() {
  const { rows } = await pool.query('SELECT NOW() AS ahora');
  return rows[0].ahora;
}

module.exports = { pool, query, withTransaction, testConnection };
