CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ,
    security_question TEXT,
    security_answer_salt TEXT,
    security_answer_hash TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    size TEXT,
    buying_price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    stock NUMERIC(12, 3) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    added_by TEXT
);

CREATE TABLE IF NOT EXISTS sales (
    id TEXT PRIMARY KEY,
    date DATE,
    time TEXT,
    total NUMERIC(12, 2) NOT NULL DEFAULT 0,
    payment TEXT,
    attendant TEXT,
    attendant_id TEXT,
    created_at TIMESTAMPTZ,
    payment_status TEXT,
    amount_paid NUMERIC(12, 2) NOT NULL DEFAULT 0,
    balance NUMERIC(12, 2) NOT NULL DEFAULT 0,
    customer_name TEXT,
    customer_phone TEXT,
    due_date TEXT
);

CREATE TABLE IF NOT EXISTS sale_items (
    id BIGSERIAL PRIMARY KEY,
    sale_id TEXT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id TEXT,
    name TEXT,
    size TEXT,
    price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    buying_price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    qty NUMERIC(12, 3) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sale_payments (
    id BIGSERIAL PRIMARY KEY,
    sale_id TEXT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
    payment_date TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS expenditures (
    id TEXT PRIMARY KEY,
    nature TEXT,
    date DATE,
    amount NUMERIC(12, 2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stock_activities (
    id TEXT PRIMARY KEY,
    date DATE,
    time TEXT,
    attendant TEXT,
    action TEXT,
    product_id TEXT,
    product TEXT,
    size TEXT,
    quantity NUMERIC(12, 3) NOT NULL DEFAULT 0,
    stock_after NUMERIC(12, 3) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY,
    business_name TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ,
    date DATE,
    time TEXT,
    username TEXT,
    role TEXT,
    category TEXT,
    action TEXT,
    details TEXT
);
