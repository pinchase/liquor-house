require('dotenv').config();

const pool = require('./db');

async function testDatabase() {
  try {
    const result = await pool.query('SELECT NOW()');

    console.log('Database connected successfully!');
    console.log(result.rows[0]);

  } catch (error) {
    console.error('Database connection failed:');
    console.error(error);
  } finally {
    await pool.end();
  }
}

testDatabase();
