require('dotenv').config();

const fs = require('fs');
const pool = require('./db');

const data = JSON.parse(fs.readFileSync('./data.json', 'utf8'));
const users = JSON.parse(fs.readFileSync('./users.json', 'utf8'));
const audit = JSON.parse(fs.readFileSync('./audit.json', 'utf8'));

function numberOrZero(value) {
    if (
        value === null ||
        value === undefined ||
        value === '' ||
        value === '—' ||
        value === '-'
    ) {
        return 0;
    }

    const number = Number(value);

    return Number.isFinite(number) ? number : 0;
}

async function migrate() {
    const client = await pool.connect();

    try {
        console.log('Starting migration...');

        await client.query('BEGIN');

        // --------------------------------------------------
        // USERS
        // --------------------------------------------------

        console.log(`Migrating ${users.length} users...`);

        for (const user of users) {
            await client.query(
                `
                INSERT INTO users (
                    id,
                    username,
                    password_hash,
                    salt,
                    role,
                    permissions,
                    created_at,
                    security_question,
                    security_answer_salt,
                    security_answer_hash
                )
                VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
                )
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    user.id,
                    user.username,
                    user.passwordHash,
                    user.salt,
                    user.role,
                    JSON.stringify(user.permissions || {}),
                    user.createdAt || null,
                    user.securityQuestion || null,
                    user.securityAnswerSalt || null,
                    user.securityAnswerHash || null
                ]
            );
        }

        // --------------------------------------------------
        // PRODUCTS
        // --------------------------------------------------

        console.log(`Migrating ${data.products.length} products...`);

        for (const product of data.products) {
            await client.query(
                `
                INSERT INTO products (
                    id,
                    name,
                    size,
                    buying_price,
                    price,
                    stock,
                    created_at,
                    added_by
                )
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    product.id,
                    product.name,
                    product.size || null,
                    numberOrZero(product.buyingPrice),
                    numberOrZero(product.price),
                    numberOrZero(product.stock),
                    product.createdAt || null,
                    product.addedBy || null
                ]
            );
        }

        // --------------------------------------------------
        // SALES
        // --------------------------------------------------

        console.log(`Migrating ${data.sales.length} sales...`);

        for (const sale of data.sales) {
            await client.query(
                `
                INSERT INTO sales (
                    id,
                    date,
                    time,
                    total,
                    payment,
                    attendant,
                    attendant_id,
                    created_at,
                    payment_status,
                    amount_paid,
                    balance,
                    customer_name,
                    customer_phone,
                    due_date
                )
                VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,
                    $9,$10,$11,$12,$13,$14
                )
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    sale.id,
                    sale.date || null,
                    sale.time || null,
                    numberOrZero(sale.total),
                    sale.payment || null,
                    sale.attendant || null,
                    sale.attendantId || null,
                    sale.createdAt || null,
                    sale.paymentStatus || null,
                    numberOrZero(sale.amountPaid),
                    numberOrZero(sale.balance),
                    sale.customerName || null,
                    sale.customerPhone || null,
                    sale.dueDate || null
                ]
            );

            // --------------------------------------------------
            // SALE ITEMS
            // --------------------------------------------------

            if (Array.isArray(sale.items)) {
                for (const item of sale.items) {
                    await client.query(
                        `
                        INSERT INTO sale_items (
                            sale_id,
                            product_id,
                            name,
                            size,
                            price,
                            buying_price,
                            qty
                        )
                        VALUES ($1,$2,$3,$4,$5,$6,$7)
                        `,
                        [
                            sale.id,
                            item.productId || null,
                            item.name || null,
                            item.size || null,
                            numberOrZero(item.price),
                            numberOrZero(item.buyingPrice),
                            numberOrZero(item.qty)
                        ]
                    );
                }
            }

            // --------------------------------------------------
            // SALE PAYMENTS
            // --------------------------------------------------

            if (Array.isArray(sale.payments)) {
                for (const payment of sale.payments) {
                    const paymentDate =
                        payment.date && payment.time
                            ? `${payment.date} ${payment.time}`
                            : payment.date || null;

                    await client.query(
                        `
                        INSERT INTO sale_payments (
                            sale_id,
                            amount,
                            payment_date
                        )
                        VALUES ($1,$2,$3)
                        `,
                        [
                            sale.id,
                            numberOrZero(payment.amount),
                            paymentDate
                        ]
                    );
                }
            }
        }

        // --------------------------------------------------
        // EXPENDITURES
        // --------------------------------------------------

        console.log(
            `Migrating ${data.expenditures.length} expenditures...`
        );

        for (const expenditure of data.expenditures) {
            await client.query(
                `
                INSERT INTO expenditures (
                    id,
                    nature,
                    date,
                    amount
                )
                VALUES ($1,$2,$3,$4)
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    expenditure.id,
                    expenditure.nature || null,
                    expenditure.date || null,
                    numberOrZero(expenditure.amount)
                ]
            );
        }

        // --------------------------------------------------
        // STOCK ACTIVITIES
        // --------------------------------------------------

        console.log(
            `Migrating ${data.stockActivities.length} stock activities...`
        );

        for (const activity of data.stockActivities) {
            await client.query(
                `
                INSERT INTO stock_activities (
                    id,
                    date,
                    time,
                    attendant,
                    action,
                    product_id,
                    product,
                    size,
                    quantity,
                    stock_after
                )
                VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
                )
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    activity.id,
                    activity.date || null,
                    activity.time || null,
                    activity.attendant || null,
                    activity.action || null,
                    activity.productId || null,
                    activity.product || null,
                    activity.size || null,
                    numberOrZero(activity.quantity),
                    numberOrZero(activity.stockAfter)
                ]
            );
        }

        // --------------------------------------------------
        // SETTINGS
        // --------------------------------------------------

        console.log('Migrating settings...');

        if (data.settings) {
            await client.query(
                `
                INSERT INTO settings (
                    id,
                    business_name
                )
                VALUES ($1,$2)
                ON CONFLICT (id)
                DO UPDATE SET business_name = EXCLUDED.business_name
                `,
                [
                    1,
                    data.settings.businessName || null
                ]
            );
        }

        // --------------------------------------------------
        // AUDIT LOG
        // --------------------------------------------------

        console.log(`Migrating ${audit.length} audit records...`);

        for (const entry of audit) {
            await client.query(
                `
                INSERT INTO audit_logs (
                    id,
                    timestamp,
                    date,
                    time,
                    username,
                    role,
                    category,
                    action,
                    details
                )
                VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9
                )
                ON CONFLICT (id) DO NOTHING
                `,
                [
                    entry.id,
                    entry.timestamp || null,
                    entry.date || null,
                    entry.time || null,
                    entry.username || null,
                    entry.role || null,
                    entry.category || null,
                    entry.action || null,
                    entry.details || null
                ]
            );
        }

        await client.query('COMMIT');

        console.log('');
        console.log('====================================');
        console.log('MIGRATION COMPLETED SUCCESSFULLY');
        console.log('====================================');

    } catch (error) {
        await client.query('ROLLBACK');

        console.error('');
        console.error('MIGRATION FAILED');
        console.error('All changes have been rolled back.');
        console.error('');
        console.error(error);

        process.exitCode = 1;
    } finally {
        client.release();
        await pool.end();
    }
}

migrate();
