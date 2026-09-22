require('dotenv').config();
const fs = require('fs');
const pool = require('./db');

async function setupDatabase() {
    try {
        const schema = fs.readFileSync('./schema.sql', 'utf8');

        await pool.query(schema);

        console.log('Database schema created successfully.');

        await pool.end();
    } catch (error) {
        console.error('Database setup failed:');
        console.error(error);
        process.exit(1);
    }
}

setupDatabase();
