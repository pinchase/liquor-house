// U-Choice Liquor POS — Backend server
// - Serves the frontend (public/)
// - Persists business data (products/sales/expenditures/etc.) in data.json
// - Handles user accounts, login sessions, roles and per-section permissions
//   in users.json, so an admin can create attendant accounts and restrict
//   which parts of the POS each one can see.

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const AUDIT_FILE = path.join(__dirname, 'audit.json');
const AUDIT_MAX_ENTRIES = 5000;

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------
// Generic JSON file persistence (used for both business data and users)
// ---------------------------------------------------------------------
function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8');
    return raw ? JSON.parse(raw) : fallback;
  } catch (err) {
    console.error('Failed to read', file, err);
    return fallback;
  }
}

const writeQueues = {};
function writeJSON(file, value) {
  const prev = writeQueues[file] || Promise.resolve();
  const next = prev.then(
    () =>
      new Promise((resolve, reject) => {
        const tmp = file + '.tmp';
        fs.writeFile(tmp, JSON.stringify(value, null, 2), (err) => {
          if (err) return reject(err);
          fs.rename(tmp, file, (err2) => (err2 ? reject(err2) : resolve()));
        });
      })
  );
  writeQueues[file] = next;
  return next;
}

// Safe read-modify-write: queues onto the same per-file chain as writeJSON
// so two requests can never read the same stale copy and clobber each
// other. `mutator` receives the freshly-read object, mutates it in place
// (or returns a replacement), and whatever it returns is passed back to
// the caller — while the (possibly mutated) object is what gets written.
function mutateJSON(file, fallback, mutator) {
  const prev = writeQueues[file] || Promise.resolve();
  const result = prev.then(async () => {
    const current = readJSON(file, typeof fallback === 'function' ? fallback() : fallback);
    const returned = await mutator(current);
    await new Promise((resolve, reject) => {
      const tmp = file + '.tmp';
      fs.writeFile(tmp, JSON.stringify(current, null, 2), (err) => {
        if (err) return reject(err);
        fs.rename(tmp, file, (err2) => (err2 ? reject(err2) : resolve()));
      });
    });
    return returned;
  });
  // Keep the queue alive even if this mutation failed, so later requests
  // aren't stuck behind a rejected promise forever.
  writeQueues[file] = result.catch(() => {});
  return result;
}

function genId(prefix) {
  return prefix + '-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// ---------------------------------------------------------------------
// Users, passwords, permissions
// ---------------------------------------------------------------------
const ALL_TRUE = { sales: true, stock: true, reports: true, profit: true, expenditure: true, history: true, settings: true };
const ALL_FALSE = { sales: false, stock: false, reports: false, profit: false, expenditure: false, history: false, settings: false };

function loadUsers() { return readJSON(USERS_FILE, []); }
function saveUsers(users) { return writeJSON(USERS_FILE, users); }

function makeSalt() { return crypto.randomBytes(16).toString('hex'); }
function hashPassword(password, salt) { return crypto.scryptSync(String(password), salt, 64).toString('hex'); }
function verifyPassword(password, user) {
  try {
    const candidate = Buffer.from(hashPassword(password, user.salt), 'hex');
    const actual = Buffer.from(user.passwordHash, 'hex');
    return candidate.length === actual.length && crypto.timingSafeEqual(candidate, actual);
  } catch {
    return false;
  }
}
// Security-question answers are normalized (trimmed + lowercased) before
// hashing, so "Blue" and " blue " both verify — same scrypt+salt scheme as
// passwords, just on the normalized text.
function normalizeAnswer(a) { return String(a || '').trim().toLowerCase(); }
function verifySecurityAnswer(answer, user) {
  if (!user.securityAnswerHash || !user.securityAnswerSalt) return false;
  try {
    const candidate = Buffer.from(hashPassword(normalizeAnswer(answer), user.securityAnswerSalt), 'hex');
    const actual = Buffer.from(user.securityAnswerHash, 'hex');
    return candidate.length === actual.length && crypto.timingSafeEqual(candidate, actual);
  } catch {
    return false;
  }
}

function ensureDefaultAdmin() {
  const users = loadUsers();
  if (users.length === 0) {
    const salt = makeSalt();
    users.push({
      id: 'u-' + crypto.randomBytes(6).toString('hex'),
      username: 'admin',
      passwordHash: hashPassword('admin123', salt),
      salt,
      role: 'admin',
      permissions: { ...ALL_TRUE },
      createdAt: new Date().toISOString()
    });
    saveUsers(users);
    console.log('No users found — created default admin account: username "admin", password "admin123". Please change this password after logging in.');
  }
}
ensureDefaultAdmin();

// ---------------------------------------------------------------------
// Business data shape + seeding
// ---------------------------------------------------------------------
function defaultData() {
  return { products: [], sales: [], expenditures: [], settings: { businessName: 'U-CHOICE LIQUOR' } };
}

const SEED_PRODUCTS = [{"name":"4TH STREET RED","size":"","buyingPrice":865,"price":1200,"stock":50},{"name":"4TH STREET WHITE","size":"","buyingPrice":865,"price":1200,"stock":50},{"name":"BAILEYS 375ML","size":"","buyingPrice":900,"price":1200,"stock":50},{"name":"BALOZI CAN","size":"","buyingPrice":201,"price":300,"stock":50},{"name":"BLUE ICE 250ML","size":"","buyingPrice":150,"price":200,"stock":50},{"name":"BOND 7 250ML","size":"","buyingPrice":420,"price":600,"stock":50},{"name":"CAPRICE RED","size":"","buyingPrice":885,"price":1200,"stock":50},{"name":"CAPRICE WHITE","size":"","buyingPrice":885,"price":1100,"stock":50},{"name":"CAPTAIN MUCK PIT 250ML","size":"","buyingPrice":394,"price":560,"stock":50},{"name":"CAPTAIN MUCK PIT 750ML","size":"","buyingPrice":1107,"price":1400,"stock":50},{"name":"CAPTAIN MORGAN 250ML","size":"","buyingPrice":344,"price":450,"stock":50},{"name":"CAPTAIN MORGAN 750ML","size":"","buyingPrice":942,"price":1300,"stock":50},{"name":"CELLAR RED WINE","size":"","buyingPrice":970,"price":1300,"stock":50},{"name":"CELLAR WHITE WINE","size":"","buyingPrice":970,"price":1300,"stock":50},{"name":"CHROME GIN 250ML","size":"","buyingPrice":210,"price":300,"stock":50},{"name":"CHROME GIN 750ML","size":"","buyingPrice":575,"price":950,"stock":50},{"name":"CHROME VODKA 250ML","size":"","buyingPrice":212,"price":300,"stock":50},{"name":"COUNTY 250ML","size":"","buyingPrice":235,"price":300,"stock":50},{"name":"COUNTY 750ML","size":"","buyingPrice":645,"price":950,"stock":50},{"name":"DALLAS BRANDY 250ML","size":"","buyingPrice":125,"price":200,"stock":50},{"name":"DROSTDY SWEET RED","size":"","buyingPrice":935,"price":1300,"stock":50},{"name":"DROSTDY WHITE","size":"","buyingPrice":935,"price":1300,"stock":50},{"name":"FOUR COUSINS","size":"","buyingPrice":875,"price":1200,"stock":50},{"name":"FAXE","size":"","buyingPrice":280,"price":350,"stock":50},{"name":"GUINNESS CAN","size":"","buyingPrice":216,"price":300,"stock":50},{"name":"KC GINGER 250ML","size":"","buyingPrice":259,"price":350,"stock":50},{"name":"KC GINGER 750ML","size":"","buyingPrice":702,"price":900,"stock":50},{"name":"KC PINEAPPL 250ML","size":"","buyingPrice":259,"price":350,"stock":50},{"name":"KC PINEAPPLE 750ML","size":"","buyingPrice":702,"price":900,"stock":50},{"name":"K.C SMOOTH 250ML","size":"","buyingPrice":259,"price":350,"stock":50},{"name":"KIBAO VODKA 250ML","size":"","buyingPrice":226,"price":300,"stock":50},{"name":"KIBAO VODKA 350ML","size":"","buyingPrice":343,"price":400,"stock":50},{"name":"KONYAGI 250ML","size":"","buyingPrice":235,"price":300,"stock":50},{"name":"KONYAGI 350ML","size":"","buyingPrice":510,"price":700,"stock":50},{"name":"KONYAGI 750ML","size":"","buyingPrice":670,"price":900,"stock":50},{"name":"MONSTER","size":"","buyingPrice":195,"price":350,"stock":50},{"name":"RED BULL","size":"","buyingPrice":185,"price":280,"stock":50},{"name":"LEMONADE","size":"","buyingPrice":40,"price":60,"stock":50},{"name":"PREDITOR","size":"","buyingPrice":55,"price":70,"stock":50},{"name":"SMIRNOFF GUARANA","size":"","buyingPrice":176,"price":250,"stock":50},{"name":"SMIRNOFF BLACK ICE","size":"","buyingPrice":176,"price":250,"stock":50},{"name":"SMIRNOFF PINEAPLE PUNCH","size":"","buyingPrice":176,"price":250,"stock":50},{"name":"SNAPP APPLE 330ML","size":"","buyingPrice":176,"price":250,"stock":50},{"name":"POWER PLAY","size":"","buyingPrice":55,"price":70,"stock":50},{"name":"V&A 250ML","size":"","buyingPrice":309,"price":400,"stock":50},{"name":"V&A 750ML","size":"","buyingPrice":803,"price":1200,"stock":50},{"name":"BLACK N WHITE 350ML","size":"","buyingPrice":593,"price":800,"stock":50},{"name":"BLACK N WHITE 750ML","size":"","buyingPrice":1155,"price":1400,"stock":50},{"name":"CASABUENA RED","size":"","buyingPrice":747,"price":1200,"stock":50},{"name":"CASABUENA WHITE","size":"","buyingPrice":747,"price":1200,"stock":50},{"name":"HUNTERS GIN 250ML","size":"","buyingPrice":437,"price":650,"stock":50},{"name":"HUNTERS GIN 750ML","size":"","buyingPrice":922,"price":1200,"stock":50},{"name":"HUNTERS DRY BOTTTLE","size":"","buyingPrice":202,"price":350,"stock":50},{"name":"GILBEYS 250ML","size":"","buyingPrice":416,"price":650,"stock":50},{"name":"GILBEYS 350ML","size":"","buyingPrice":602,"price":800,"stock":50},{"name":"GILBEYS 750ML","size":"","buyingPrice":1277,"price":1500,"stock":50},{"name":"RICHOT 250ML","size":"","buyingPrice":435,"price":650,"stock":50},{"name":"RICHOT350ML","size":"","buyingPrice":576,"price":800,"stock":50},{"name":"JINRO","size":"","buyingPrice":365,"price":500,"stock":50},{"name":"ORIJIN","size":"","buyingPrice":242,"price":350,"stock":50},{"name":"SMIRNOFF 250ML","size":"","buyingPrice":429,"price":650,"stock":50},{"name":"SMIRNOFF 350ML","size":"","buyingPrice":593,"price":800,"stock":50},{"name":"TRIPLE ACE 250ML","size":"","buyingPrice":203,"price":350,"stock":50},{"name":"TUSKER CIDER","size":"","buyingPrice":234,"price":350,"stock":50},{"name":"TUSKER LITE","size":"","buyingPrice":243,"price":350,"stock":50},{"name":"TUSKER CAN","size":"","buyingPrice":201,"price":300,"stock":50},{"name":"VICEROY 250ML","size":"","buyingPrice":437,"price":650,"stock":50},{"name":"VICEROY 350ML","size":"","buyingPrice":627,"price":800,"stock":50},{"name":"VICEROY 750ML","size":"","buyingPrice":1265,"price":1500,"stock":50},{"name":"GENERAL MIKINS 250ML","size":"","buyingPrice":220,"price":300,"stock":50},{"name":"GENERAL MIKINS 750ML","size":"","buyingPrice":635,"price":900,"stock":50},{"name":"J.MOVERS","size":"","buyingPrice":120,"price":200,"stock":50},{"name":"GRAYSON WHISKEY 250ML","size":"","buyingPrice":260,"price":400,"stock":50},{"name":"WHITE CAP","size":"","buyingPrice":216,"price":300,"stock":50},{"name":"MANYATTA","size":"","buyingPrice":242,"price":350,"stock":50},{"name":"NAPOLION 250ML","size":"","buyingPrice":225,"price":350,"stock":50}];

function ensureSeedProducts() {
  const data = readJSON(DATA_FILE, defaultData());
  if (!data.products || !data.products.length) {
    data.products = SEED_PRODUCTS.map((p) => ({ id: genId('p'), ...p, createdAt: new Date().toISOString(), addedBy: 'system' }));
    data.sales = data.sales || [];
    data.expenditures = data.expenditures || [];
    data.settings = data.settings || { businessName: 'U-CHOICE LIQUOR' };
    writeJSON(DATA_FILE, data);
    console.log(`Seeded ${data.products.length} default products into data.json.`);
  }
}
ensureSeedProducts();

// In-memory sessions: token -> { userId, createdAt }. Lost on server restart
// (by design, to keep this simple) — users just log in again.
const sessions = new Map();
function createSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { userId, createdAt: Date.now() });
  return token;
}
function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    permissions: u.role === 'admin' ? { ...ALL_TRUE } : { ...ALL_FALSE, ...(u.permissions || {}) },
    securityQuestion: u.securityQuestion || null
  };
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token ? sessions.get(token) : null;
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  const user = loadUsers().find((u) => u.id === session.userId);
  if (!user) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Not authenticated' });
  }
  req.user = user;
  req.token = token;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}
// Section-level permission gate for business-data endpoints. Admins always
// pass. Anyone else must have at least one of the listed permissions on
// their account (checked server-side, not just hidden in the UI).
function requirePerm(...allowed) {
  return (req, res, next) => {
    if (req.user.role === 'admin') return next();
    const perms = req.user.permissions || {};
    if (allowed.some((p) => perms[p])) return next();
    return res.status(403).json({ error: "You don't have permission to access this." });
  };
}

// ---------------------------------------------------------------------
// Audit log — a system-wide, admin-only record of who did what and when.
// Authentication and user-management events are logged automatically by
// the server itself (so they can't be spoofed by the client). Business
// actions (sales, stock, expenditure, settings) are logged via a small
// POST endpoint that the frontend calls right after each action, with
// the actor's identity always taken from their verified session — never
// from the request body.
// ---------------------------------------------------------------------
function loadAudit() { return readJSON(AUDIT_FILE, []); }
function saveAudit(entries) { return writeJSON(AUDIT_FILE, entries); }

async function appendAudit({ username, role, category, action, details }) {
  const entries = loadAudit();
  const now = new Date();
  entries.unshift({
    id: 'a-' + crypto.randomBytes(6).toString('hex'),
    timestamp: now.toISOString(),
    date: now.toISOString().slice(0, 10),
    time: now.toLocaleTimeString('en-GB'),
    username: username || 'unknown',
    role: role || '—',
    category: category || 'General',
    action: action || '',
    details: details || ''
  });
  if (entries.length > AUDIT_MAX_ENTRIES) entries.length = AUDIT_MAX_ENTRIES;
  await saveAudit(entries);
}

// ---------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = loadUsers().find((u) => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user || !verifyPassword(password, user)) {
    await appendAudit({ username: username || 'unknown', role: '—', category: 'Authentication', action: 'Login failed', details: 'Invalid username or password' });
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = createSession(user.id);
  await appendAudit({ username: user.username, role: user.role, category: 'Authentication', action: 'Login succeeded', details: '' });
  res.json({ token, user: publicUser(user) });
});

app.post('/api/logout', auth, async (req, res) => {
  sessions.delete(req.token);
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Authentication', action: 'Logout', details: '' });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post('/api/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || String(newPassword).length < 4) {
    return res.status(400).json({ error: 'Provide your current password and a new password (min 4 characters).' });
  }
  if (!verifyPassword(currentPassword, req.user)) return res.status(401).json({ error: 'Current password is incorrect.' });
  const users = loadUsers();
  const u = users.find((x) => x.id === req.user.id);
  u.salt = makeSalt();
  u.passwordHash = hashPassword(newPassword, u.salt);
  await saveUsers(users);
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Account', action: 'Password changed', details: 'Self-service password change' });
  res.json({ ok: true });
});

// Lets a logged-in user set/update the recovery question used by "Forgot
// password?" on the login screen. Requires the current password so an
// unattended session can't silently take over recovery.
app.post('/api/account/security-question', auth, async (req, res) => {
  const { currentPassword, question, answer } = req.body || {};
  if (!verifyPassword(currentPassword || '', req.user)) return res.status(401).json({ error: 'Current password is incorrect.' });
  if (!question || !String(question).trim() || !answer || !normalizeAnswer(answer)) {
    return res.status(400).json({ error: 'Choose a question and provide an answer.' });
  }
  const users = loadUsers();
  const u = users.find((x) => x.id === req.user.id);
  u.securityQuestion = String(question).trim();
  u.securityAnswerSalt = makeSalt();
  u.securityAnswerHash = hashPassword(normalizeAnswer(answer), u.securityAnswerSalt);
  await saveUsers(users);
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Account', action: 'Recovery question set', details: '' });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------
// Forgot password (self-service, no email required) — public routes.
// Step 1: look up the recovery question for a username, if one was set.
// Step 2: answer it correctly to set a brand-new password. Both steps
// are rate-limited-in-spirit by requiring the exact answer (scrypt +
// timing-safe compare) and by invalidating every existing session for
// that account the moment a reset succeeds.
// ---------------------------------------------------------------------
app.post('/api/forgot-password/question', (req, res) => {
  const { username } = req.body || {};
  const user = loadUsers().find((u) => u.username.toLowerCase() === String(username || '').toLowerCase());
  if (!user || !user.securityQuestion || !user.securityAnswerHash) {
    return res.json({ question: null });
  }
  res.json({ question: user.securityQuestion });
});

app.post('/api/forgot-password/reset', async (req, res) => {
  const { username, answer, newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 4) {
    return res.status(400).json({ error: 'Choose a new password (min 4 characters).' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.username.toLowerCase() === String(username || '').toLowerCase());
  if (!user || !user.securityQuestion || !user.securityAnswerHash) {
    return res.status(400).json({ error: 'No recovery question is set for this account. Ask an admin to reset your password.' });
  }
  if (!verifySecurityAnswer(answer, user)) {
    await appendAudit({ username: user.username, role: user.role, category: 'Authentication', action: 'Password reset failed', details: 'Incorrect recovery answer' });
    return res.status(401).json({ error: "That answer doesn't match our records." });
  }
  user.salt = makeSalt();
  user.passwordHash = hashPassword(newPassword, user.salt);
  await saveUsers(users);
  for (const [token, s] of sessions) if (s.userId === user.id) sessions.delete(token);
  await appendAudit({ username: user.username, role: user.role, category: 'Authentication', action: 'Password reset via security question', details: '' });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------
// User management — admin only
// ---------------------------------------------------------------------
app.get('/api/users', auth, requireAdmin, (req, res) => {
  res.json({ users: loadUsers().map(publicUser) });
});

app.post('/api/users', auth, requireAdmin, async (req, res) => {
  const { username, password, role, permissions } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  if (String(password).length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  const users = loadUsers();
  if (users.some((u) => u.username.toLowerCase() === String(username).toLowerCase())) {
    return res.status(409).json({ error: 'That username is already taken.' });
  }
  const salt = makeSalt();
  const newUser = {
    id: 'u-' + crypto.randomBytes(6).toString('hex'),
    username: String(username).trim(),
    passwordHash: hashPassword(password, salt),
    salt,
    role: role === 'admin' ? 'admin' : 'attendant',
    permissions: role === 'admin' ? { ...ALL_TRUE } : { ...ALL_FALSE, ...(permissions || {}) },
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  await saveUsers(users);
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Users', action: 'User created', details: `Created "${newUser.username}" as ${newUser.role}` });
  res.status(201).json({ user: publicUser(newUser) });
});

app.put('/api/users/:id', auth, requireAdmin, async (req, res) => {
  const users = loadUsers();
  const u = users.find((x) => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  const { role, permissions, password } = req.body || {};
  if (role) u.role = role === 'admin' ? 'admin' : 'attendant';
  if (u.role === 'admin') {
    u.permissions = { ...ALL_TRUE };
  } else if (permissions) {
    u.permissions = { ...ALL_FALSE, ...(u.permissions || {}), ...permissions };
  }
  if (password) {
    if (String(password).length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
    u.salt = makeSalt();
    u.passwordHash = hashPassword(password, u.salt);
  }
  await saveUsers(users);
  const changeParts = [];
  if (role) changeParts.push(`role -> ${u.role}`);
  if (permissions) changeParts.push('permissions updated');
  if (password) changeParts.push('password reset');
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Users', action: 'User updated', details: `"${u.username}": ${changeParts.join(', ') || 'no changes'}` });
  res.json({ user: publicUser(u) });
});

app.delete('/api/users/:id', auth, requireAdmin, async (req, res) => {
  const users = loadUsers();
  const target = users.find((x) => x.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (target.id === req.user.id) return res.status(400).json({ error: "You can't delete your own account while logged in." });
  const remainingAdmins = users.filter((u) => u.role === 'admin' && u.id !== target.id);
  if (target.role === 'admin' && remainingAdmins.length === 0) {
    return res.status(400).json({ error: 'Cannot delete the last remaining admin account.' });
  }
  await saveUsers(users.filter((x) => x.id !== target.id));
  for (const [token, s] of sessions) if (s.userId === target.id) sessions.delete(token);
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Users', action: 'User deleted', details: `Deleted "${target.username}" (${target.role})` });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------
// Products — read needs sales, stock, reports or profit access; writing
// (adding a product/stock, deleting a product) needs stock access.
// ---------------------------------------------------------------------
app.get('/api/products', auth, requirePerm('sales', 'stock', 'reports', 'profit'), (req, res) => {
  const data = readJSON(DATA_FILE, defaultData());
  res.json({ products: data.products || [] });
});

app.post('/api/products', auth, requirePerm('stock'), async (req, res) => {
  const { name, size, buyingPrice, price, stock } = req.body || {};
  const bp = Number(buyingPrice), sp = Number(price), qty = Number(stock);
  if (!name || !size || !Number.isFinite(bp) || bp < 0 || !Number.isFinite(sp) || sp < 0 || !Number.isFinite(qty) || qty < 0) {
    return res.status(400).json({ error: 'Enter product name, size, buying price, selling price and stock.' });
  }
  try {
    const result = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.products = data.products || [];
      const existing = data.products.find(
        (p) => p.name.toLowerCase() === String(name).toLowerCase() && p.size.toLowerCase() === String(size).toLowerCase()
      );
      if (existing) {
        existing.buyingPrice = bp;
        existing.price = Math.round(sp / 5) * 5;
        existing.stock = Number(existing.stock) + qty;
        return { product: existing, merged: true };
      }
      const np = { id: genId('p'), name: String(name).trim(), size: String(size).trim(), buyingPrice: bp, price: Math.round(sp / 5) * 5, stock: qty, createdAt: new Date().toISOString(), addedBy: req.user.username };
      data.products.push(np);
      return { product: np, merged: false };
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Stock', action: result.merged ? 'Stock added' : 'Product added', details: `${result.product.name} ${result.product.size}`.trim() });
    res.status(201).json(result);
  } catch (err) {
    console.error('Failed to save product:', err);
    res.status(500).json({ error: 'Failed to save product.' });
  }
});

// Full edit of an existing product (size, buying price, selling price,
// stock quantity) — admin only. Unlike add-stock (which increments the
// existing quantity), this sets the fields directly to whatever the
// admin enters.
app.put('/api/products/:id', auth, requireAdmin, async (req, res) => {
  const { size, buyingPrice, price, stock } = req.body || {};
  const bp = Number(buyingPrice), sp = Number(price), qty = Number(stock);
  if (!size || !Number.isFinite(bp) || bp < 0 || !Number.isFinite(sp) || sp < 0 || !Number.isFinite(qty) || qty < 0) {
    return res.status(400).json({ error: 'Enter a valid size, buying price, selling price and stock.' });
  }
  try {
    const result = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.products = data.products || [];
      const p = data.products.find((x) => x.id === req.params.id);
      if (!p) throw Object.assign(new Error('NOT_FOUND'), { status: 404 });
      p.size = String(size).trim();
      p.buyingPrice = bp;
      p.price = Math.round(sp / 5) * 5;
      p.stock = qty;
      return p;
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Stock', action: 'Stock edited', details: `${result.name} ${result.size}`.trim() });
    res.json({ product: result });
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: 'Product not found.' });
    console.error('Failed to edit product:', err);
    res.status(500).json({ error: 'Failed to edit product.' });
  }
});

app.put('/api/products/:id/add-stock', auth, requirePerm('stock'), async (req, res) => {
  const n = Number((req.body || {}).quantity);
  if (!Number.isFinite(n) || n <= 0) return res.status(400).json({ error: 'Enter a quantity greater than 0.' });
  try {
    const result = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.products = data.products || [];
      const p = data.products.find((x) => x.id === req.params.id);
      if (!p) throw Object.assign(new Error('NOT_FOUND'), { status: 404 });
      p.stock = Number(p.stock) + n;
      return p;
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Stock', action: 'Stock added', details: `${result.name} ${result.size}: +${n} (now ${result.stock})`.trim() });
    res.json({ product: result });
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: 'Product not found.' });
    console.error('Failed to add stock:', err);
    res.status(500).json({ error: 'Failed to add stock.' });
  }
});

app.delete('/api/products/:id', auth, requirePerm('stock'), async (req, res) => {
  try {
    const result = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.products = data.products || [];
      const p = data.products.find((x) => x.id === req.params.id);
      if (!p) throw Object.assign(new Error('NOT_FOUND'), { status: 404 });
      data.products = data.products.filter((x) => x.id !== req.params.id);
      return p;
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Stock', action: 'Product deleted', details: `${result.name} ${result.size}`.trim() });
    res.json({ ok: true });
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: 'Product not found.' });
    console.error('Failed to delete product:', err);
    res.status(500).json({ error: 'Failed to delete product.' });
  }
});

// ---------------------------------------------------------------------
// Sales — reading needs sales, reports, profit or history access;
// completing a sale needs sales access; deleting needs history access.
// Stock validation and decrementing happens here, atomically, so the
// server is always the source of truth for whether a sale is valid.
// ---------------------------------------------------------------------
app.get('/api/sales', auth, requirePerm('sales', 'reports', 'profit', 'history'), (req, res) => {
  const data = readJSON(DATA_FILE, defaultData());
  res.json({ sales: data.sales || [] });
});

app.post('/api/sales', auth, requirePerm('sales'), async (req, res) => {
  const { items, payment, paymentStatus, amountPaid, customerName, customerPhone, dueDate } = req.body || {};
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'Cart is empty.' });
  try {
    const sale = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.products = data.products || [];
      data.sales = data.sales || [];
      for (const it of items) {
        const p = data.products.find((x) => x.id === it.productId);
        const qty = Number(it.qty);
        if (!p || !Number.isFinite(qty) || qty <= 0) throw Object.assign(new Error('BAD_ITEM'), { status: 400 });
        if (Number(p.stock) + 1e-9 < qty) throw Object.assign(new Error('Not enough stock for ' + p.name + '.'), { status: 409 });
      }
      const saleItems = [];
      let total = 0;
      for (const it of items) {
        const p = data.products.find((x) => x.id === it.productId);
        const qty = Number(it.qty);
        p.stock = Math.max(0, Number(p.stock) - qty);
        total += Number(p.price) * qty;
        saleItems.push({ productId: p.id, name: p.name, size: p.size, price: Number(p.price), buyingPrice: Number(p.buyingPrice) || 0, qty });
      }
      // A sale is "pending" (sold on credit) when the client explicitly asks
      // for it and the amount paid now is less than the total. Any deposit
      // paid at the time of sale is recorded as the first payment entry.
      const requestedPending = paymentStatus === 'pending';
      let status = requestedPending ? 'pending' : 'paid';
      let paidNow = status === 'pending' ? Number(amountPaid) : total;
      if (!Number.isFinite(paidNow) || paidNow < 0) paidNow = 0;
      if (paidNow > total) paidNow = total;
      if (paidNow + 1e-9 >= total) status = 'paid';
      const now = new Date();
      const s = {
        id: genId('s'), date: now.toISOString().slice(0, 10), time: now.toLocaleTimeString(),
        total, payment: payment || 'Cash', attendant: req.user.username, attendantId: req.user.id,
        items: saleItems, createdAt: now.toISOString(),
        paymentStatus: status, amountPaid: paidNow, balance: Math.max(0, total - paidNow),
        customerName: requestedPending ? String(customerName || '').trim() : '',
        customerPhone: requestedPending ? String(customerPhone || '').trim() : '',
        dueDate: requestedPending ? String(dueDate || '').trim() : '',
        payments: paidNow > 0 ? [{ date: now.toISOString().slice(0, 10), time: now.toLocaleTimeString(), amount: paidNow, by: req.user.username }] : []
      };
      data.sales.unshift(s);
      return s;
    });
    const itemSummary = sale.items.map((x) => `${x.name} x${x.qty}`).join(', ');
    const pendingNote = sale.paymentStatus === 'pending' ? ` — PENDING balance KES ${sale.balance.toFixed(2)}${sale.customerName ? ' (' + sale.customerName + ')' : ''}` : '';
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Sales', action: sale.paymentStatus === 'pending' ? 'Sale completed (pending payment)' : 'Sale completed', details: `KES ${sale.total.toFixed(2)} (${sale.payment}) — ${itemSummary}${pendingNote}` });
    res.status(201).json({ sale });
  } catch (err) {
    if (err.status === 400) return res.status(400).json({ error: 'Invalid item in cart.' });
    if (err.status === 409) return res.status(409).json({ error: err.message });
    console.error('Failed to complete sale:', err);
    res.status(500).json({ error: 'Failed to complete sale.' });
  }
});

// Record a payment against a pending (credit) sale. Applies at most the
// remaining balance, appends to the sale's payment history, and flips it
// back to "paid" once the balance reaches zero.
app.put('/api/sales/:id/pay', auth, requirePerm('sales'), async (req, res) => {
  const amount = Number((req.body || {}).amount);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Enter a payment amount greater than 0.' });
  try {
    const result = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.sales = data.sales || [];
      const s = data.sales.find((x) => x.id === req.params.id);
      if (!s) throw Object.assign(new Error('NOT_FOUND'), { status: 404 });
      const currentBalance = s.balance != null ? Number(s.balance) : Math.max(0, Number(s.total) - Number(s.amountPaid || 0));
      if (currentBalance <= 0.005) throw Object.assign(new Error('ALREADY_PAID'), { status: 400 });
      const applied = Math.min(amount, currentBalance);
      const now = new Date();
      s.amountPaid = Number(s.amountPaid || 0) + applied;
      s.balance = Math.max(0, Number(s.total) - s.amountPaid);
      s.payments = s.payments || [];
      s.payments.push({ date: now.toISOString().slice(0, 10), time: now.toLocaleTimeString(), amount: applied, by: req.user.username });
      s.paymentStatus = s.balance <= 0.005 ? 'paid' : 'pending';
      return s;
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Sales', action: 'Pending payment collected', details: `KES ${amount.toFixed(2)} towards ${result.customerName || 'a credit sale'} from ${result.date} — balance now KES ${result.balance.toFixed(2)}` });
    res.json({ sale: result });
  } catch (err) {
    if (err.status === 404) return res.status(404).json({ error: 'Sale not found.' });
    if (err.status === 400) return res.status(400).json({ error: 'This sale is already fully paid.' });
    console.error('Failed to record payment:', err);
    res.status(500).json({ error: 'Failed to record payment.' });
  }
});

app.delete('/api/sales/:id', auth, requireAdmin, async (req, res) => {
  try {
    const deleted = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.sales = data.sales || [];
      data.products = data.products || [];
      const found = data.sales.find((s) => s.id === req.params.id) || null;
      if (found) {
        for (const item of found.items || []) {
          const p = data.products.find((x) => x.id === item.productId);
          if (p) p.stock = Number(p.stock) + Number(item.qty || 0);
        }
      }
      data.sales = data.sales.filter((s) => s.id !== req.params.id);
      return found;
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Sales', action: 'Sale deleted', details: deleted ? `KES ${Number(deleted.total).toFixed(2)} sale from ${deleted.date} ${deleted.time} — stock restored` : req.params.id });
    res.json({ ok: true });
  } catch (err) {
    console.error('Failed to delete sale:', err);
    res.status(500).json({ error: 'Failed to delete sale.' });
  }
});

app.delete('/api/sales', auth, requireAdmin, async (req, res) => {
  try {
    await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.products = data.products || [];
      (data.sales || []).forEach((s) => {
        (s.items || []).forEach((item) => {
          const p = data.products.find((x) => x.id === item.productId);
          if (p) p.stock = Number(p.stock) + Number(item.qty || 0);
        });
      });
      data.sales = [];
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Sales', action: 'Sales history cleared', details: 'All sales removed and their stock restored' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Failed to clear sales history:', err);
    res.status(500).json({ error: 'Failed to clear sales history.' });
  }
});

// ---------------------------------------------------------------------
// Expenditures — requires expenditure access for everything.
// ---------------------------------------------------------------------
app.get('/api/expenditures', auth, requirePerm('expenditure'), (req, res) => {
  const data = readJSON(DATA_FILE, defaultData());
  res.json({ expenditures: data.expenditures || [] });
});

app.post('/api/expenditures', auth, requirePerm('expenditure'), async (req, res) => {
  const { nature, date, amount } = req.body || {};
  const amt = Number(amount);
  if (!nature || !date || !Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'Enter nature, date and amount.' });
  try {
    const entry = { id: genId('e'), nature: String(nature).trim(), date, amount: amt };
    await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.expenditures = data.expenditures || [];
      data.expenditures.unshift(entry);
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Expenditure', action: 'Expenditure added', details: `${entry.nature}: KES ${amt.toFixed(2)} (${date})` });
    res.status(201).json({ expenditure: entry });
  } catch (err) {
    console.error('Failed to add expenditure:', err);
    res.status(500).json({ error: 'Failed to add expenditure.' });
  }
});

app.delete('/api/expenditures/:id', auth, requirePerm('expenditure'), async (req, res) => {
  try {
    const deleted = await mutateJSON(DATA_FILE, defaultData, (data) => {
      data.expenditures = data.expenditures || [];
      const found = data.expenditures.find((e) => e.id === req.params.id) || null;
      data.expenditures = data.expenditures.filter((e) => e.id !== req.params.id);
      return found;
    });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Expenditure', action: 'Expenditure deleted', details: deleted ? `${deleted.nature}: KES ${Number(deleted.amount).toFixed(2)} (${deleted.date})` : req.params.id });
    res.json({ ok: true });
  } catch (err) {
    console.error('Failed to delete expenditure:', err);
    res.status(500).json({ error: 'Failed to delete expenditure.' });
  }
});

app.delete('/api/expenditures', auth, requirePerm('expenditure'), async (req, res) => {
  try {
    await mutateJSON(DATA_FILE, defaultData, (data) => { data.expenditures = []; });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Expenditure', action: 'All expenditures cleared', details: '' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Failed to clear expenditures:', err);
    res.status(500).json({ error: 'Failed to clear expenditures.' });
  }
});

// ---------------------------------------------------------------------
// Settings — requires settings access to read or write.
// ---------------------------------------------------------------------
app.get('/api/settings', auth, requirePerm('settings'), (req, res) => {
  const data = readJSON(DATA_FILE, defaultData());
  res.json({ settings: data.settings || { businessName: 'U-CHOICE LIQUOR' } });
});

app.put('/api/settings', auth, requirePerm('settings'), async (req, res) => {
  const businessName = ((req.body || {}).businessName || '').trim() || 'U-CHOICE LIQUOR';
  try {
    const settings = { businessName };
    await mutateJSON(DATA_FILE, defaultData, (data) => { data.settings = settings; });
    await appendAudit({ username: req.user.username, role: req.user.role, category: 'Settings', action: 'Business settings updated', details: `Business name set to "${businessName}"` });
    res.json({ settings });
  } catch (err) {
    console.error('Failed to save settings:', err);
    res.status(500).json({ error: 'Failed to save settings.' });
  }
});

// ---------------------------------------------------------------------
// Audit log endpoints
// Reading and clearing the log is admin-only. Any authenticated user can
// append a business-event entry (sale completed, stock added, etc.) — but
// the actor identity is always taken from their verified session, never
// from the request body, so entries can't be forged as someone else.
// ---------------------------------------------------------------------
app.get('/api/audit-log', auth, requireAdmin, (req, res) => {
  res.json({ entries: loadAudit() });
});

app.post('/api/audit-log', auth, async (req, res) => {
  const { category, action, details } = req.body || {};
  if (!action) return res.status(400).json({ error: 'action is required' });
  await appendAudit({
    username: req.user.username,
    role: req.user.role,
    category: category ? String(category).slice(0, 40) : 'Business',
    action: String(action).slice(0, 80),
    details: details ? String(details).slice(0, 500) : ''
  });
  res.json({ ok: true });
});

app.delete('/api/audit-log', auth, requireAdmin, async (req, res) => {
  await saveAudit([]);
  await appendAudit({ username: req.user.username, role: req.user.role, category: 'Audit', action: 'Audit log cleared', details: 'All prior entries were deleted' });
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`U-Choice Liquor POS server running on http://localhost:${PORT}`);
});
