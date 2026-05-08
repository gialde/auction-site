const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABASE,
});

// Функция инициализации таблиц (выполняет schema.sql при первом запуске)
async function initDB() {
  const fs = require('fs');
  const path = require('path');
  const schemaPath = path.join(__dirname, 'schema.sql');
  const schemaSQL = fs.readFileSync(schemaPath, 'utf-8');
  
  try {
    await pool.query(schemaSQL);
    console.log('База данных инициализирована.');
  } catch (err) {
    console.error('Ошибка инициализации БД:', err);
  }
}

module.exports = { pool, initDB };