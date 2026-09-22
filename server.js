// U-Choice Liquor POS — Backend server
//
// Production persistence:
//   Browser → Express → Neon PostgreSQL
//
// JSON files are no longer used for live application data.
// They are intentionally kept in the project directory as a backup
// until the PostgreSQL deployment has been fully verified.

const express = require('express');
const crypto = require('crypto');
const pool = require('./db');

const PORT = process.env.PORT || 3000;

const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.static(require('path').join(__dirname, 'public')));

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

function genId(prefix) {
    return (
        prefix +
        '-' +
        Date.now().toString(36) +
        crypto.randomBytes(4).toString('hex')
    );
}

function makeSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password, salt) {
    return crypto
        .scryptSync(String(password), salt, 64)
        .toString('hex');
}

function verifyPassword(password, user) {
    try {
        const candidate = Buffer.from(
            hashPassword(password, user.salt),
            'hex'
        );

        const actual = Buffer.from(user.password_hash, 'hex');

        return (
            candidate.length === actual.length &&
            crypto.timingSafeEqual(candidate, actual)
        );
    } catch {
        return false;
    }
}

function normalizeAnswer(answer) {
    return String(answer || '').trim().toLowerCase();
}

function verifySecurityAnswer(answer, user) {
    if (
        !user.security_answer_hash ||
        !user.security_answer_salt
    ) {
        return false;
    }

    try {
        const candidate = Buffer.from(
            hashPassword(
                normalizeAnswer(answer),
                user.security_answer_salt
            ),
            'hex'
        );

        const actual = Buffer.from(
            user.security_answer_hash,
            'hex'
        );

        return (
            candidate.length === actual.length &&
            crypto.timingSafeEqual(candidate, actual)
        );
    } catch {
        return false;
    }
}

function toNumber(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : fallback;
}

// ---------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------

const ALL_TRUE = {
    sales: true,
    stock: true,
    reports: true,
    profit: true,
    expenditure: true,
    history: true,
    settings: true
};

const ALL_FALSE = {
    sales: false,
    stock: false,
    reports: false,
    profit: false,
    expenditure: false,
    history: false,
    settings: false
};

function publicUser(user) {
    return {
        id: user.id,
        username: user.username,
        role: user.role,
        permissions:
            user.role === 'admin'
                ? { ...ALL_TRUE }
                : {
                      ...ALL_FALSE,
                      ...(user.permissions || {})
                  },
        securityQuestion:
            user.security_question || null
    };
}

// ---------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------

// Sessions intentionally remain in memory.
// A Render restart logs users out, exactly like the previous version.

const sessions = new Map();

function createSession(userId) {
    const token = crypto.randomBytes(24).toString('hex');

    sessions.set(token, {
        userId,
        createdAt: Date.now()
    });

    return token;
}

function invalidateUserSessions(userId) {
    for (const [token, session] of sessions) {
        if (session.userId === userId) {
            sessions.delete(token);
        }
    }
}

// ---------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------

async function auth(req, res, next) {
    const header = req.headers.authorization || '';

    const token = header.startsWith('Bearer ')
        ? header.slice(7)
        : null;

    const session = token ? sessions.get(token) : null;

    if (!session) {
        return res.status(401).json({
            error: 'Not authenticated'
        });
    }

    try {
        const result = await pool.query(
            `SELECT * FROM users WHERE id = $1`,
            [session.userId]
        );

        if (!result.rows.length) {
            sessions.delete(token);

            return res.status(401).json({
                error: 'Not authenticated'
            });
        }

        req.user = result.rows[0];
        req.token = token;

        next();
    } catch (err) {
        console.error('Authentication lookup failed:', err);

        return res.status(500).json({
            error: 'Authentication service unavailable.'
        });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            error: 'Admin access required'
        });
    }

    next();
}

function requirePerm(...allowed) {
    return (req, res, next) => {
        if (req.user.role === 'admin') {
            return next();
        }

        const permissions = req.user.permissions || {};

        if (allowed.some(permission => permissions[permission])) {
            return next();
        }

        return res.status(403).json({
            error: "You don't have permission to access this."
        });
    };
}

// ---------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------

async function appendAudit({
    username,
    role,
    category,
    action,
    details
}) {
    const now = new Date();

    const id = 'a-' + crypto.randomBytes(6).toString('hex');

    await pool.query(
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
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        `,
        [
            id,
            now.toISOString(),
            now.toISOString().slice(0, 10),
            now.toLocaleTimeString('en-GB'),
            username || 'unknown',
            role || '—',
            category || 'General',
            action || '',
            details || ''
        ]
    );

    // Keep the same maximum as the previous JSON implementation.
    await pool.query(`
        DELETE FROM audit_logs
        WHERE id IN (
            SELECT id
            FROM audit_logs
            ORDER BY timestamp DESC
            OFFSET 5000
        )
    `);
}

// ---------------------------------------------------------------------
// AUTH ROUTES
// ---------------------------------------------------------------------

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({
            error: 'Username and password required'
        });
    }

    try {
        const result = await pool.query(
            `
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER($1)
            `,
            [String(username)]
        );

        const user = result.rows[0];

        if (!user || !verifyPassword(password, user)) {
            await appendAudit({
                username: username || 'unknown',
                role: '—',
                category: 'Authentication',
                action: 'Login failed',
                details: 'Invalid username or password'
            });

            return res.status(401).json({
                error: 'Invalid username or password'
            });
        }

        const token = createSession(user.id);

        await appendAudit({
            username: user.username,
            role: user.role,
            category: 'Authentication',
            action: 'Login succeeded',
            details: ''
        });

        res.json({
            token,
            user: publicUser(user)
        });
    } catch (err) {
        console.error('Login failed:', err);

        res.status(500).json({
            error: 'Login service unavailable.'
        });
    }
});

app.post('/api/logout', auth, async (req, res) => {
    sessions.delete(req.token);

    await appendAudit({
        username: req.user.username,
        role: req.user.role,
        category: 'Authentication',
        action: 'Logout',
        details: ''
    });

    res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
    res.json({
        user: publicUser(req.user)
    });
});

app.post('/api/change-password', auth, async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};

    if (
        !currentPassword ||
        !newPassword ||
        String(newPassword).length < 4
    ) {
        return res.status(400).json({
            error:
                'Provide your current password and a new password (min 4 characters).'
        });
    }

    if (!verifyPassword(currentPassword, req.user)) {
        return res.status(401).json({
            error: 'Current password is incorrect.'
        });
    }

    const salt = makeSalt();

    await pool.query(
        `
        UPDATE users
        SET salt = $1,
            password_hash = $2
        WHERE id = $3
        `,
        [
            salt,
            hashPassword(newPassword, salt),
            req.user.id
        ]
    );

    await appendAudit({
        username: req.user.username,
        role: req.user.role,
        category: 'Account',
        action: 'Password changed',
        details: 'Self-service password change'
    });

    res.json({ ok: true });
});

// ---------------------------------------------------------------------
// SECURITY QUESTION
// ---------------------------------------------------------------------

app.post(
    '/api/account/security-question',
    auth,
    async (req, res) => {
        const { currentPassword, question, answer } =
            req.body || {};

        if (!verifyPassword(currentPassword || '', req.user)) {
            return res.status(401).json({
                error: 'Current password is incorrect.'
            });
        }

        if (
            !question ||
            !String(question).trim() ||
            !answer ||
            !normalizeAnswer(answer)
        ) {
            return res.status(400).json({
                error: 'Choose a question and provide an answer.'
            });
        }

        const salt = makeSalt();

        await pool.query(
            `
            UPDATE users
            SET security_question = $1,
                security_answer_salt = $2,
                security_answer_hash = $3
            WHERE id = $4
            `,
            [
                String(question).trim(),
                salt,
                hashPassword(
                    normalizeAnswer(answer),
                    salt
                ),
                req.user.id
            ]
        );

        await appendAudit({
            username: req.user.username,
            role: req.user.role,
            category: 'Account',
            action: 'Recovery question set',
            details: ''
        });

        res.json({ ok: true });
    }
);

// ---------------------------------------------------------------------
// FORGOT PASSWORD
// ---------------------------------------------------------------------

app.post('/api/forgot-password/question', async (req, res) => {
    const { username } = req.body || {};

    try {
        const result = await pool.query(
            `
            SELECT security_question
            FROM users
            WHERE LOWER(username) = LOWER($1)
            `,
            [String(username || '')]
        );

        const user = result.rows[0];

        if (!user || !user.security_question) {
            return res.json({
                question: null
            });
        }

        res.json({
            question: user.security_question
        });
    } catch (err) {
        console.error(
            'Failed to retrieve security question:',
            err
        );

        res.status(500).json({
            error: 'Unable to retrieve security question.'
        });
    }
});

app.post('/api/forgot-password/reset', async (req, res) => {
    const { username, answer, newPassword } =
        req.body || {};

    if (!newPassword || String(newPassword).length < 4) {
        return res.status(400).json({
            error: 'Choose a new password (min 4 characters).'
        });
    }

    try {
        const result = await pool.query(
            `
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER($1)
            `,
            [String(username || '')]
        );

        const user = result.rows[0];

        if (
            !user ||
            !user.security_question ||
            !user.security_answer_hash
        ) {
            return res.status(400).json({
                error:
                    'No recovery question is set for this account. Ask an admin to reset your password.'
            });
        }

        if (!verifySecurityAnswer(answer, user)) {
            await appendAudit({
                username: user.username,
                role: user.role,
                category: 'Authentication',
                action: 'Password reset failed',
                details: 'Incorrect recovery answer'
            });

            return res.status(401).json({
                error:
                    "That answer doesn't match our records."
            });
        }

        const salt = makeSalt();

        await pool.query(
            `
            UPDATE users
            SET salt = $1,
                password_hash = $2
            WHERE id = $3
            `,
            [
                salt,
                hashPassword(newPassword, salt),
                user.id
            ]
        );

        invalidateUserSessions(user.id);

        await appendAudit({
            username: user.username,
            role: user.role,
            category: 'Authentication',
            action:
                'Password reset via security question',
            details: ''
        });

        res.json({ ok: true });
    } catch (err) {
        console.error('Password reset failed:', err);

        res.status(500).json({
            error: 'Password reset failed.'
        });
    }
});

// ---------------------------------------------------------------------
// USER MANAGEMENT
// ---------------------------------------------------------------------

app.get(
    '/api/users',
    auth,
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT *
                FROM users
                ORDER BY username ASC
            `);

            res.json({
                users: result.rows.map(publicUser)
            });
        } catch (err) {
            console.error('Failed to load users:', err);

            res.status(500).json({
                error: 'Failed to load users.'
            });
        }
    }
);

app.post(
    '/api/users',
    auth,
    requireAdmin,
    async (req, res) => {
        const {
            username,
            password,
            role,
            permissions
        } = req.body || {};

        if (!username || !password) {
            return res.status(400).json({
                error:
                    'Username and password required.'
            });
        }

        if (String(password).length < 4) {
            return res.status(400).json({
                error:
                    'Password must be at least 4 characters.'
            });
        }

        try {
            const existing = await pool.query(
                `
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER($1)
                `,
                [String(username).trim()]
            );

            if (existing.rows.length) {
                return res.status(409).json({
                    error:
                        'That username is already taken.'
                });
            }

            const id =
                'u-' +
                crypto.randomBytes(6).toString('hex');

            const salt = makeSalt();

            const userRole =
                role === 'admin'
                    ? 'admin'
                    : 'attendant';

            const userPermissions =
                userRole === 'admin'
                    ? ALL_TRUE
                    : {
                          ...ALL_FALSE,
                          ...(permissions || {})
                      };

            const createdAt = new Date().toISOString();

            await pool.query(
                `
                INSERT INTO users (
                    id,
                    username,
                    password_hash,
                    salt,
                    role,
                    permissions,
                    created_at
                )
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                `,
                [
                    id,
                    String(username).trim(),
                    hashPassword(password, salt),
                    salt,
                    userRole,
                    JSON.stringify(userPermissions),
                    createdAt
                ]
            );

            const createdUser = {
                id,
                username: String(username).trim(),
                role: userRole,
                permissions: userPermissions,
                security_question: null
            };

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Users',
                action: 'User created',
                details:
                    `Created "${createdUser.username}" as ${createdUser.role}`
            });

            res.status(201).json({
                user: publicUser(createdUser)
            });
        } catch (err) {
            console.error('Failed to create user:', err);

            res.status(500).json({
                error: 'Failed to create user.'
            });
        }
    }
);

app.put(
    '/api/users/:id',
    auth,
    requireAdmin,
    async (req, res) => {
        const {
            role,
            permissions,
            password
        } = req.body || {};

        try {
            const result = await pool.query(
                `SELECT * FROM users WHERE id = $1`,
                [req.params.id]
            );

            const user = result.rows[0];

            if (!user) {
                return res.status(404).json({
                    error: 'User not found.'
                });
            }

            const newRole =
                role === undefined
                    ? user.role
                    : role === 'admin'
                    ? 'admin'
                    : 'attendant';

            let newPermissions =
                user.permissions || {};

            if (newRole === 'admin') {
                newPermissions = {
                    ...ALL_TRUE
                };
            } else if (permissions) {
                newPermissions = {
                    ...ALL_FALSE,
                    ...(user.permissions || {}),
                    ...permissions
                };
            }

            let newSalt = user.salt;
            let newHash = user.password_hash;

            if (password) {
                if (String(password).length < 4) {
                    return res.status(400).json({
                        error:
                            'Password must be at least 4 characters.'
                    });
                }

                newSalt = makeSalt();
                newHash = hashPassword(
                    password,
                    newSalt
                );
            }

            await pool.query(
                `
                UPDATE users
                SET role = $1,
                    permissions = $2,
                    salt = $3,
                    password_hash = $4
                WHERE id = $5
                `,
                [
                    newRole,
                    JSON.stringify(newPermissions),
                    newSalt,
                    newHash,
                    user.id
                ]
            );

            if (password) {
                invalidateUserSessions(user.id);
            }

            const changeParts = [];

            if (role) {
                changeParts.push(
                    `role -> ${newRole}`
                );
            }

            if (permissions) {
                changeParts.push(
                    'permissions updated'
                );
            }

            if (password) {
                changeParts.push(
                    'password reset'
                );
            }

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Users',
                action: 'User updated',
                details:
                    `"${user.username}": ${
                        changeParts.join(', ') ||
                        'no changes'
                    }`
            });

            const updatedUser = {
                ...user,
                role: newRole,
                permissions: newPermissions,
                salt: newSalt,
                password_hash: newHash
            };

            res.json({
                user: publicUser(updatedUser)
            });
        } catch (err) {
            console.error('Failed to update user:', err);

            res.status(500).json({
                error: 'Failed to update user.'
            });
        }
    }
);

app.delete(
    '/api/users/:id',
    auth,
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT * FROM users WHERE id = $1`,
                [req.params.id]
            );

            const target = result.rows[0];

            if (!target) {
                return res.status(404).json({
                    error: 'User not found.'
                });
            }

            if (target.id === req.user.id) {
                return res.status(400).json({
                    error:
                        "You can't delete your own account while logged in."
                });
            }

            const admins = await pool.query(
                `
                SELECT COUNT(*) AS count
                FROM users
                WHERE role = 'admin'
                AND id <> $1
                `,
                [target.id]
            );

            if (
                target.role === 'admin' &&
                Number(admins.rows[0].count) === 0
            ) {
                return res.status(400).json({
                    error:
                        'Cannot delete the last remaining admin account.'
                });
            }

            await pool.query(
                `DELETE FROM users WHERE id = $1`,
                [target.id]
            );

            invalidateUserSessions(target.id);

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Users',
                action: 'User deleted',
                details:
                    `Deleted "${target.username}" (${target.role})`
            });

            res.json({ ok: true });
        } catch (err) {
            console.error('Failed to delete user:', err);

            res.status(500).json({
                error: 'Failed to delete user.'
            });
        }
    }
);

// ---------------------------------------------------------------------
// PRODUCTS
// ---------------------------------------------------------------------

function mapProduct(row) {
    return {
        id: row.id,
        name: row.name,
        size: row.size,
        buyingPrice: Number(row.buying_price),
        price: Number(row.price),
        stock: Number(row.stock),
        createdAt: row.created_at,
        addedBy: row.added_by
    };
}

app.get(
    '/api/products',
    auth,
    requirePerm(
        'sales',
        'stock',
        'reports',
        'profit'
    ),
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT *
                FROM products
                ORDER BY created_at ASC
            `);

            res.json({
                products: result.rows.map(mapProduct)
            });
        } catch (err) {
            console.error('Failed to load products:', err);

            res.status(500).json({
                error: 'Failed to load products.'
            });
        }
    }
);

app.post(
    '/api/products',
    auth,
    requirePerm('stock'),
    async (req, res) => {
        const {
            name,
            size,
            buyingPrice,
            price,
            stock
        } = req.body || {};

        const bp = Number(buyingPrice);
        const sp = Number(price);
        const qty = Number(stock);

        if (
            !name ||
            !size ||
            !Number.isFinite(bp) ||
            bp < 0 ||
            !Number.isFinite(sp) ||
            sp < 0 ||
            !Number.isFinite(qty) ||
            qty < 0
        ) {
            return res.status(400).json({
                error:
                    'Enter product name, size, buying price, selling price and stock.'
            });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const existingResult = await client.query(
                `
                SELECT *
                FROM products
                WHERE LOWER(name) = LOWER($1)
                AND LOWER(size) = LOWER($2)
                FOR UPDATE
                `,
                [
                    String(name).trim(),
                    String(size).trim()
                ]
            );

            let product;
            let merged;

            if (existingResult.rows.length) {
                const row = existingResult.rows[0];

                const newPrice =
                    Math.round(sp / 5) * 5;

                const newStock =
                    Number(row.stock) + qty;

                const updated = await client.query(
                    `
                    UPDATE products
                    SET buying_price = $1,
                        price = $2,
                        stock = $3
                    WHERE id = $4
                    RETURNING *
                    `,
                    [
                        bp,
                        newPrice,
                        newStock,
                        row.id
                    ]
                );

                product = mapProduct(
                    updated.rows[0]
                );
                merged = true;

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
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    `,
                    [
                        genId('sa'),
                        new Date()
                            .toISOString()
                            .slice(0, 10),
                        new Date().toLocaleTimeString(),
                        req.user.username,
                        'STOCK ADDED',
                        product.id,
                        product.name,
                        product.size,
                        qty,
                        product.stock
                    ]
                );
            } else {
                const id = genId('p');
                const createdAt =
                    new Date().toISOString();

                const inserted = await client.query(
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
                    RETURNING *
                    `,
                    [
                        id,
                        String(name).trim(),
                        String(size).trim(),
                        bp,
                        Math.round(sp / 5) * 5,
                        qty,
                        createdAt,
                        req.user.username
                    ]
                );

                product = mapProduct(
                    inserted.rows[0]
                );
                merged = false;

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
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    `,
                    [
                        genId('sa'),
                        createdAt.slice(0, 10),
                        new Date().toLocaleTimeString(),
                        req.user.username,
                        'PRODUCT ADDED',
                        product.id,
                        product.name,
                        product.size,
                        qty,
                        product.stock
                    ]
                );
            }

            await client.query('COMMIT');

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Stock',
                action: merged
                    ? 'Stock added'
                    : 'Product added',
                details:
                    `${product.name} ${product.size}`.trim()
            });

            res.status(201).json({
                product,
                merged
            });
        } catch (err) {
            await client.query('ROLLBACK');

            console.error(
                'Failed to save product:',
                err
            );

            res.status(500).json({
                error: 'Failed to save product.'
            });
        } finally {
            client.release();
        }
    }
);

app.put(
    '/api/products/:id',
    auth,
    requireAdmin,
    async (req, res) => {
        const {
            size,
            buyingPrice,
            price,
            stock
        } = req.body || {};

        const bp = Number(buyingPrice);
        const sp = Number(price);
        const qty = Number(stock);

        if (
            !size ||
            !Number.isFinite(bp) ||
            bp < 0 ||
            !Number.isFinite(sp) ||
            sp < 0 ||
            !Number.isFinite(qty) ||
            qty < 0
        ) {
            return res.status(400).json({
                error:
                    'Enter a valid size, buying price, selling price and stock.'
            });
        }

        try {
            const result = await pool.query(
                `
                UPDATE products
                SET size = $1,
                    buying_price = $2,
                    price = $3,
                    stock = $4
                WHERE id = $5
                RETURNING *
                `,
                [
                    String(size).trim(),
                    bp,
                    Math.round(sp / 5) * 5,
                    qty,
                    req.params.id
                ]
            );

            if (!result.rows.length) {
                return res.status(404).json({
                    error: 'Product not found.'
                });
            }

            const product = mapProduct(
                result.rows[0]
            );

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Stock',
                action: 'Stock edited',
                details:
                    `${product.name} ${product.size}`.trim()
            });

            res.json({ product });
        } catch (err) {
            console.error(
                'Failed to edit product:',
                err
            );

            res.status(500).json({
                error: 'Failed to edit product.'
            });
        }
    }
);

app.put(
    '/api/products/:id/add-stock',
    auth,
    requirePerm('stock'),
    async (req, res) => {
        const quantity = Number(
            (req.body || {}).quantity
        );

        if (
            !Number.isFinite(quantity) ||
            quantity <= 0
        ) {
            return res.status(400).json({
                error:
                    'Enter a quantity greater than 0.'
            });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const result = await client.query(
                `
                SELECT *
                FROM products
                WHERE id = $1
                FOR UPDATE
                `,
                [req.params.id]
            );

            if (!result.rows.length) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    error: 'Product not found.'
                });
            }

            const current = result.rows[0];

            const newStock =
                Number(current.stock) + quantity;

            const updated = await client.query(
                `
                UPDATE products
                SET stock = $1
                WHERE id = $2
                RETURNING *
                `,
                [
                    newStock,
                    req.params.id
                ]
            );

            const product = mapProduct(
                updated.rows[0]
            );

            const now = new Date();

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
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                `,
                [
                    genId('sa'),
                    now.toISOString().slice(0, 10),
                    now.toLocaleTimeString(),
                    req.user.username,
                    'STOCK ADDED',
                    product.id,
                    product.name,
                    product.size,
                    quantity,
                    product.stock
                ]
            );

            await client.query('COMMIT');

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Stock',
                action: 'Stock added',
                details:
                    `${product.name} ${product.size}: +${quantity} (now ${product.stock})`.trim()
            });

            res.json({ product });
        } catch (err) {
            await client.query('ROLLBACK');

            console.error(
                'Failed to add stock:',
                err
            );

            res.status(500).json({
                error: 'Failed to add stock.'
            });
        } finally {
            client.release();
        }
    }
);

app.delete(
    '/api/products/:id',
    auth,
    requirePerm('stock'),
    async (req, res) => {
        try {
            const result = await pool.query(
                `
                DELETE FROM products
                WHERE id = $1
                RETURNING *
                `,
                [req.params.id]
            );

            if (!result.rows.length) {
                return res.status(404).json({
                    error: 'Product not found.'
                });
            }

            const product = mapProduct(
                result.rows[0]
            );

            await appendAudit({
                username: req.user.username,
                role: req.user.role,
                category: 'Stock',
                action: 'Product deleted',
                details:
                    `${product.name} ${product.size}`.trim()
            });

            res.json({ ok: true });
        } catch (err) {
            console.error(
                'Failed to delete product:',
                err
            );

            res.status(500).json({
                error: 'Failed to delete product.'
            });
        }
    }
);

// ---------------------------------------------------------------------
// SALES HELPERS
// ---------------------------------------------------------------------

function mapSale(row, items, payments) {
    return {
        id: row.id,
        date: row.date
            ? new Date(row.date)
                  .toISOString()
                  .slice(0, 10)
            : null,
        time: row.time,
        total: Number(row.total),
        payment: row.payment,
        attendant: row.attendant,
        attendantId: row.attendant_id,
        items: items.map(item => ({
            productId: item.product_id,
            name: item.name,
            size: item.size,
            price: Number(item.price),
            buyingPrice: Number(
                item.buying_price
            ),
            qty: Number(item.qty)
        })),
        createdAt: row.created_at,
        paymentStatus: row.payment_status,
        amountPaid: Number(row.amount_paid),
        balance: Number(row.balance),
        customerName: row.customer_name || '',
        customerPhone: row.customer_phone || '',
        dueDate: row.due_date || '',
        payments: payments.map(payment => ({
            date: payment.payment_date
                ? new Date(payment.payment_date)
                      .toISOString()
                      .slice(0, 10)
                : null,
            time: payment.payment_date
                ? new Date(
                      payment.payment_date
                  ).toLocaleTimeString()
                : '',
            amount: Number(payment.amount),
            by: payment.paid_by || ''
        }))
    };
}

async function getAllSales() {
    const salesResult = await pool.query(`
        SELECT *
        FROM sales
        ORDER BY created_at DESC
    `);

    const itemsResult = await pool.query(`
        SELECT *
        FROM sale_items
        ORDER BY id ASC
    `);

    const paymentsResult = await pool.query(`
        SELECT *
        FROM sale_payments
        ORDER BY id ASC
    `);

    const itemsBySale = new Map();
    const paymentsBySale = new Map();

    for (const item of itemsResult.rows) {
        if (!itemsBySale.has(item.sale_id)) {
            itemsBySale.set(item.sale_id, []);
        }

        itemsBySale.get(item.sale_id).push(item);
    }

    for (const payment of paymentsResult.rows) {
        if (!paymentsBySale.has(payment.sale_id)) {
            paymentsBySale.set(
                payment.sale_id,
                []
            );
        }

        paymentsBySale
            .get(payment.sale_id)
            .push(payment);
    }

    return salesResult.rows.map(sale =>
        mapSale(
            sale,
            itemsBySale.get(sale.id) || [],
            paymentsBySale.get(sale.id) || []
        )
    );
}

// ---------------------------------------------------------------------
// SALES
// ---------------------------------------------------------------------

app.get(
    '/api/sales',
    auth,
    requirePerm(
        'sales',
        'reports',
        'profit',
        'history'
    ),
    async (req, res) => {
        try {
            const sales = await getAllSales();

            res.json({ sales });
        } catch (err) {
            console.error(
                'Failed to load sales:',
                err
            );

            res.status(500).json({
                error: 'Failed to load sales.'
            });
        }
    }
);

app.post(
    '/api/sales',
    auth,
    requirePerm('sales'),
    async (req, res) => {
        const {
            items,
            payment,
            paymentStatus,
            amountPaid,
            customerName,
            customerPhone,
            dueDate
        } = req.body || {};

        if (
            !Array.isArray(items) ||
            !items.length
        ) {
            return res.status(400).json({
                error: 'Cart is empty.'
            });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const saleItems = [];
            let total = 0;

            // Lock products during the entire sale transaction.
            // This prevents two simultaneous sales from selling
            // the same stock.
            for (const item of items) {
                const qty = Number(item.qty);

                if (
                    !item.productId ||
                    !Number.isFinite(qty) ||
                    qty <= 0
                ) {
                    throw Object.assign(
                        new Error('BAD_ITEM'),
                        { status: 400 }
                    );
                }

                const productResult =
                    await client.query(
                        `
                        SELECT *
                        FROM products
                        WHERE id = $1
                        FOR UPDATE
                        `,
                        [item.productId]
                    );

                const product =
                    productResult.rows[0];

                if (!product) {
                    throw Object.assign(
                        new Error('BAD_ITEM'),
                        { status: 400 }
                    );
                }

                if (
                    Number(product.stock) + 1e-9 <
                    qty
                ) {
                    throw Object.assign(
                        new Error(
                            'Not enough stock for ' +
                                product.name +
                                '.'
                        ),
                        { status: 409 }
                    );
                }

                saleItems.push({
                    product,
                    qty
                });
            }

            for (const entry of saleItems) {
                const product = entry.product;
                const qty = entry.qty;

                const newStock =
                    Math.max(
                        0,
                        Number(product.stock) -
                            qty
                    );

                await client.query(
                    `
                    UPDATE products
                    SET stock = $1
                    WHERE id = $2
                    `,
                    [
                        newStock,
                        product.id
                    ]
                );

                total +=
                    Number(product.price) *
                    qty;
            }

            const requestedPending =
                paymentStatus === 'pending';

            let status = requestedPending
                ? 'pending'
                : 'paid';

            let paidNow =
                status === 'pending'
                    ? Number(amountPaid)
                    : total;

            if (
                !Number.isFinite(paidNow) ||
                paidNow < 0
            ) {
                paidNow = 0;
            }

            if (paidNow > total) {
                paidNow = total;
            }

            if (
                paidNow + 1e-9 >= total
            ) {
                status = 'paid';
            }

            const now = new Date();

            const saleId = genId('s');

            const sale = {
                id: saleId,
                date: now
                    .toISOString()
                    .slice(0, 10),
                time: now.toLocaleTimeString(),
                total,
                payment: payment || 'Cash',
                attendant:
                    req.user.username,
                attendantId: req.user.id,
                createdAt:
                    now.toISOString(),
                paymentStatus: status,
                amountPaid: paidNow,
                balance: Math.max(
                    0,
                    total - paidNow
                ),
                customerName:
                    requestedPending
                        ? String(
                              customerName ||
                                  ''
                          ).trim()
                        : '',
                customerPhone:
                    requestedPending
                        ? String(
                              customerPhone ||
                                  ''
                          ).trim()
                        : '',
                dueDate:
                    requestedPending
                        ? String(
                              dueDate || ''
                          ).trim()
                        : ''
            };

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
                `,
                [
                    sale.id,
                    sale.date,
                    sale.time,
                    sale.total,
                    sale.payment,
                    sale.attendant,
                    sale.attendantId,
                    sale.createdAt,
                    sale.paymentStatus,
                    sale.amountPaid,
                    sale.balance,
                    sale.customerName,
                    sale.customerPhone,
                    sale.dueDate
                ]
            );

            for (const entry of saleItems) {
                const product = entry.product;
                const qty = entry.qty;

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
                        product.id,
                        product.name,
                        product.size,
                        Number(product.price),
                        Number(
                            product.buying_price
                        ),
                        qty
                    ]
                );

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
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    `,
                    [
                        genId('sa'),
                        sale.date,
                        sale.time,
                        req.user.username,
                        'SALE',
                        product.id,
                        product.name,
                        product.size,
                        -qty,
                        Math.max(
                            0,
                            Number(
                                product.stock
                            ) - qty
                        )
                    ]
                );
            }

            if (paidNow > 0) {
                await client.query(
                    `
                    INSERT INTO sale_payments (
                        sale_id,
                        amount,
                        payment_date,
                        paid_by
                    )
                    VALUES ($1,$2,$3,$4)
                    `,
                    [
                        sale.id,
                        paidNow,
                        now.toISOString(),
                        req.user.username
                    ]
                );
            }

            await client.query('COMMIT');

            const itemSummary =
                saleItems
                    .map(
                        x =>
                            `${x.product.name} x${x.qty}`
                    )
                    .join(', ');

            const pendingNote =
                sale.paymentStatus ===
                'pending'
                    ? ` — PENDING balance KES ${sale.balance.toFixed(
                          2
                      )}${
                          sale.customerName
                              ? ' (' +
                                sale.customerName +
                                ')'
                              : ''
                      }`
                    : '';

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: 'Sales',
                action:
                    sale.paymentStatus ===
                    'pending'
                        ? 'Sale completed (pending payment)'
                        : 'Sale completed',
                details:
                    `KES ${sale.total.toFixed(
                        2
                    )} (${sale.payment}) — ${itemSummary}${pendingNote}`
            });

            res.status(201).json({
                sale: {
                    ...sale,
                    items: saleItems.map(
                        x => ({
                            productId:
                                x.product.id,
                            name:
                                x.product.name,
                            size:
                                x.product.size,
                            price: Number(
                                x.product.price
                            ),
                            buyingPrice:
                                Number(
                                    x.product
                                        .buying_price
                                ),
                            qty: x.qty
                        })
                    ),
                    payments:
                        paidNow > 0
                            ? [
                                  {
                                      date: sale.date,
                                      time: sale.time,
                                      amount:
                                          paidNow,
                                      by: req
                                          .user
                                          .username
                                  }
                              ]
                            : []
                }
            });
        } catch (err) {
            await client.query('ROLLBACK');

            if (err.status === 400) {
                return res.status(400).json({
                    error:
                        'Invalid item in cart.'
                });
            }

            if (err.status === 409) {
                return res.status(409).json({
                    error: err.message
                });
            }

            console.error(
                'Failed to complete sale:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to complete sale.'
            });
        } finally {
            client.release();
        }
    }
);

// ---------------------------------------------------------------------
// COLLECT PAYMENT
// ---------------------------------------------------------------------

app.put(
    '/api/sales/:id/pay',
    auth,
    requirePerm('sales'),
    async (req, res) => {
        const amount = Number(
            (req.body || {}).amount
        );

        if (
            !Number.isFinite(amount) ||
            amount <= 0
        ) {
            return res.status(400).json({
                error:
                    'Enter a payment amount greater than 0.'
            });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const saleResult =
                await client.query(
                    `
                    SELECT *
                    FROM sales
                    WHERE id = $1
                    FOR UPDATE
                    `,
                    [req.params.id]
                );

            const sale = saleResult.rows[0];

            if (!sale) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    error: 'Sale not found.'
                });
            }

            const currentBalance =
                sale.balance != null
                    ? Number(sale.balance)
                    : Math.max(
                          0,
                          Number(sale.total) -
                              Number(
                                  sale.amount_paid ||
                                      0
                              )
                      );

            if (currentBalance <= 0.005) {
                await client.query('ROLLBACK');

                return res.status(400).json({
                    error:
                        'This sale is already fully paid.'
                });
            }

            const applied = Math.min(
                amount,
                currentBalance
            );

            const newAmountPaid =
                Number(sale.amount_paid || 0) +
                applied;

            const newBalance = Math.max(
                0,
                Number(sale.total) -
                    newAmountPaid
            );

            const newStatus =
                newBalance <= 0.005
                    ? 'paid'
                    : 'pending';

            const now = new Date();

            await client.query(
                `
                UPDATE sales
                SET amount_paid = $1,
                    balance = $2,
                    payment_status = $3
                WHERE id = $4
                `,
                [
                    newAmountPaid,
                    newBalance,
                    newStatus,
                    sale.id
                ]
            );

            await client.query(
                `
                INSERT INTO sale_payments (
                    sale_id,
                    amount,
                    payment_date,
                    paid_by
                )
                VALUES ($1,$2,$3,$4)
                `,
                [
                    sale.id,
                    applied,
                    now.toISOString(),
                    req.user.username
                ]
            );

            await client.query('COMMIT');

            const updatedSaleResult =
                await pool.query(
                    `
                    SELECT *
                    FROM sales
                    WHERE id = $1
                    `,
                    [sale.id]
                );

            const itemsResult =
                await pool.query(
                    `
                    SELECT *
                    FROM sale_items
                    WHERE sale_id = $1
                    ORDER BY id ASC
                    `,
                    [sale.id]
                );

            const paymentsResult =
                await pool.query(
                    `
                    SELECT *
                    FROM sale_payments
                    WHERE sale_id = $1
                    ORDER BY id ASC
                    `,
                    [sale.id]
                );

            const result = mapSale(
                updatedSaleResult.rows[0],
                itemsResult.rows,
                paymentsResult.rows
            );

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: 'Sales',
                action:
                    'Pending payment collected',
                details:
                    `KES ${amount.toFixed(
                        2
                    )} towards ${
                        result.customerName ||
                        'a credit sale'
                    } from ${
                        result.date
                    } — balance now KES ${result.balance.toFixed(
                        2
                    )}`
            });

            res.json({
                sale: result
            });
        } catch (err) {
            await client.query('ROLLBACK');

            console.error(
                'Failed to record payment:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to record payment.'
            });
        } finally {
            client.release();
        }
    }
);

// ---------------------------------------------------------------------
// DELETE ONE SALE
// ---------------------------------------------------------------------

app.delete(
    '/api/sales/:id',
    auth,
    requireAdmin,
    async (req, res) => {
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const saleResult =
                await client.query(
                    `
                    SELECT *
                    FROM sales
                    WHERE id = $1
                    FOR UPDATE
                    `,
                    [req.params.id]
                );

            const sale = saleResult.rows[0];

            if (!sale) {
                await client.query('ROLLBACK');

                return res.json({
                    ok: true
                });
            }

            const itemsResult =
                await client.query(
                    `
                    SELECT *
                    FROM sale_items
                    WHERE sale_id = $1
                    `,
                    [sale.id]
                );

            for (const item of itemsResult.rows) {
                const productResult =
                    await client.query(
                        `
                        SELECT *
                        FROM products
                        WHERE id = $1
                        FOR UPDATE
                        `,
                        [item.product_id]
                    );

                if (productResult.rows.length) {
                    const product =
                        productResult.rows[0];

                    const newStock =
                        Number(product.stock) +
                        Number(item.qty);

                    await client.query(
                        `
                        UPDATE products
                        SET stock = $1
                        WHERE id = $2
                        `,
                        [
                            newStock,
                            product.id
                        ]
                    );

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
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                        `,
                        [
                            genId('sa'),
                            new Date()
                                .toISOString()
                                .slice(
                                    0,
                                    10
                                ),
                            new Date().toLocaleTimeString(),
                            req.user.username,
                            'SALE DELETED - STOCK RESTORED',
                            product.id,
                            product.name,
                            product.size,
                            Number(item.qty),
                            newStock
                        ]
                    );
                }
            }

            await client.query(
                `DELETE FROM sales WHERE id = $1`,
                [sale.id]
            );

            await client.query('COMMIT');

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: 'Sales',
                action: 'Sale deleted',
                details:
                    `KES ${Number(
                        sale.total
                    ).toFixed(
                        2
                    )} sale from ${sale.date} ${sale.time} — stock restored`
            });

            res.json({ ok: true });
        } catch (err) {
            await client.query('ROLLBACK');

            console.error(
                'Failed to delete sale:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to delete sale.'
            });
        } finally {
            client.release();
        }
    }
);

// ---------------------------------------------------------------------
// CLEAR SALES
// ---------------------------------------------------------------------

app.delete(
    '/api/sales',
    auth,
    requireAdmin,
    async (req, res) => {
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const salesResult =
                await client.query(`
                    SELECT id
                    FROM sales
                    FOR UPDATE
                `);

            const itemsResult =
                await client.query(`
                    SELECT *
                    FROM sale_items
                `);

            for (const item of itemsResult.rows) {
                const productResult =
                    await client.query(
                        `
                        SELECT *
                        FROM products
                        WHERE id = $1
                        FOR UPDATE
                        `,
                        [item.product_id]
                    );

                if (productResult.rows.length) {
                    const product =
                        productResult.rows[0];

                    const newStock =
                        Number(product.stock) +
                        Number(item.qty);

                    await client.query(
                        `
                        UPDATE products
                        SET stock = $1
                        WHERE id = $2
                        `,
                        [
                            newStock,
                            product.id
                        ]
                    );
                }
            }

            await client.query(
                `DELETE FROM sales`
            );

            await client.query('COMMIT');

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: 'Sales',
                action:
                    'Sales history cleared',
                details:
                    'All sales removed and their stock restored'
            });

            res.json({ ok: true });
        } catch (err) {
            await client.query('ROLLBACK');

            console.error(
                'Failed to clear sales history:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to clear sales history.'
            });
        } finally {
            client.release();
        }
    }
);

// ---------------------------------------------------------------------
// EXPENDITURES
// ---------------------------------------------------------------------

function mapExpenditure(row) {
    return {
        id: row.id,
        nature: row.nature,
        date: row.date
            ? new Date(row.date)
                  .toISOString()
                  .slice(0, 10)
            : null,
        amount: Number(row.amount)
    };
}

app.get(
    '/api/expenditures',
    auth,
    requirePerm('expenditure'),
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT *
                FROM expenditures
                ORDER BY date DESC
            `);

            res.json({
                expenditures:
                    result.rows.map(
                        mapExpenditure
                    )
            });
        } catch (err) {
            console.error(
                'Failed to load expenditures:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to load expenditures.'
            });
        }
    }
);

app.post(
    '/api/expenditures',
    auth,
    requirePerm('expenditure'),
    async (req, res) => {
        const {
            nature,
            date,
            amount
        } = req.body || {};

        const amt = Number(amount);

        if (
            !nature ||
            !date ||
            !Number.isFinite(amt) ||
            amt <= 0
        ) {
            return res.status(400).json({
                error:
                    'Enter nature, date and amount.'
            });
        }

        const entry = {
            id: genId('e'),
            nature: String(nature).trim(),
            date,
            amount: amt
        };

        try {
            await pool.query(
                `
                INSERT INTO expenditures (
                    id,
                    nature,
                    date,
                    amount
                )
                VALUES ($1,$2,$3,$4)
                `,
                [
                    entry.id,
                    entry.nature,
                    entry.date,
                    entry.amount
                ]
            );

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category:
                    'Expenditure',
                action:
                    'Expenditure added',
                details:
                    `${entry.nature}: KES ${amt.toFixed(
                        2
                    )} (${date})`
            });

            res.status(201).json({
                expenditure: entry
            });
        } catch (err) {
            console.error(
                'Failed to add expenditure:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to add expenditure.'
            });
        }
    }
);

app.delete(
    '/api/expenditures/:id',
    auth,
    requirePerm('expenditure'),
    async (req, res) => {
        try {
            const result = await pool.query(
                `
                DELETE FROM expenditures
                WHERE id = $1
                RETURNING *
                `,
                [req.params.id]
            );

            const deleted =
                result.rows[0] || null;

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category:
                    'Expenditure',
                action:
                    'Expenditure deleted',
                details: deleted
                    ? `${deleted.nature}: KES ${Number(
                          deleted.amount
                      ).toFixed(
                          2
                      )} (${deleted.date})`
                    : req.params.id
            });

            res.json({ ok: true });
        } catch (err) {
            console.error(
                'Failed to delete expenditure:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to delete expenditure.'
            });
        }
    }
);

app.delete(
    '/api/expenditures',
    auth,
    requirePerm('expenditure'),
    async (req, res) => {
        try {
            await pool.query(
                `DELETE FROM expenditures`
            );

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category:
                    'Expenditure',
                action:
                    'All expenditures cleared',
                details: ''
            });

            res.json({ ok: true });
        } catch (err) {
            console.error(
                'Failed to clear expenditures:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to clear expenditures.'
            });
        }
    }
);

// ---------------------------------------------------------------------
// SETTINGS
// ---------------------------------------------------------------------

app.get(
    '/api/settings',
    auth,
    requirePerm('settings'),
    async (req, res) => {
        try {
            const result = await pool.query(
                `
                SELECT *
                FROM settings
                WHERE id = 1
                `
            );

            const row = result.rows[0];

            res.json({
                settings: {
                    businessName:
                        row?.business_name ||
                        'U-CHOICE LIQUOR'
                }
            });
        } catch (err) {
            console.error(
                'Failed to load settings:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to load settings.'
            });
        }
    }
);

app.put(
    '/api/settings',
    auth,
    requirePerm('settings'),
    async (req, res) => {
        const businessName =
            (
                (req.body || {})
                    .businessName || ''
            ).trim() ||
            'U-CHOICE LIQUOR';

        try {
            await pool.query(
                `
                INSERT INTO settings (
                    id,
                    business_name
                )
                VALUES (1,$1)
                ON CONFLICT (id)
                DO UPDATE SET
                    business_name =
                        EXCLUDED.business_name
                `,
                [businessName]
            );

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: 'Settings',
                action:
                    'Business settings updated',
                details:
                    `Business name set to "${businessName}"`
            });

            res.json({
                settings: {
                    businessName
                }
            });
        } catch (err) {
            console.error(
                'Failed to save settings:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to save settings.'
            });
        }
    }
);

// ---------------------------------------------------------------------
// AUDIT LOG
// ---------------------------------------------------------------------

app.get(
    '/api/audit-log',
    auth,
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(`
                SELECT *
                FROM audit_logs
                ORDER BY timestamp DESC
                LIMIT 5000
            `);

            res.json({
                entries: result.rows
            });
        } catch (err) {
            console.error(
                'Failed to load audit log:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to load audit log.'
            });
        }
    }
);

app.post(
    '/api/audit-log',
    auth,
    async (req, res) => {
        const {
            category,
            action,
            details
        } = req.body || {};

        if (!action) {
            return res.status(400).json({
                error: 'action is required'
            });
        }

        try {
            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: category
                    ? String(category).slice(
                          0,
                          40
                      )
                    : 'Business',
                action: String(action).slice(
                    0,
                    80
                ),
                details: details
                    ? String(details).slice(
                          0,
                          500
                      )
                    : ''
            });

            res.json({ ok: true });
        } catch (err) {
            console.error(
                'Failed to append audit entry:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to append audit entry.'
            });
        }
    }
);

app.delete(
    '/api/audit-log',
    auth,
    requireAdmin,
    async (req, res) => {
        try {
            await pool.query(
                `DELETE FROM audit_logs`
            );

            await appendAudit({
                username:
                    req.user.username,
                role: req.user.role,
                category: 'Audit',
                action:
                    'Audit log cleared',
                details:
                    'All prior entries were deleted'
            });

            res.json({ ok: true });
        } catch (err) {
            console.error(
                'Failed to clear audit log:',
                err
            );

            res.status(500).json({
                error:
                    'Failed to clear audit log.'
            });
        }
    }
);

// ---------------------------------------------------------------------
// HEALTH
// ---------------------------------------------------------------------

app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');

        res.json({
            ok: true,
            database: 'connected'
        });
    } catch (err) {
        console.error(
            'Database health check failed:',
            err
        );

        res.status(503).json({
            ok: false,
            database: 'disconnected'
        });
    }
});

// ---------------------------------------------------------------------
// SERVER
// ---------------------------------------------------------------------

app.listen(PORT, () => {
    console.log(
        `U-Choice Liquor POS server running on port ${PORT}`
    );
});