const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
  host: (process.env.DB_HOST || '').trim(),
  user: (process.env.DB_USER || 'root').trim(),
  password: (process.env.DB_PASSWORD || '').trim(),
  database: (process.env.DB_NAME || 'kodbankapp').trim(),
  port: parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: (process.env.DB_HOST || '').includes('localhost') ? null : { rejectUnauthorized: false }
});

module.exports = pool.promise();
