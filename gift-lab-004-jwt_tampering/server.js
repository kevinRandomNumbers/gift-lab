const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// JWT Config
const JWT_SECRET = "bugforge_gift_lab_003_2026";
const JWT_EXPIRES_IN = "2h";

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.locals.baseUrl = `${req.protocol}://${req.get('host')}`;
  next();
});

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Database instance 
let db;

// Helper functions for sql.js
function dbRun(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  stmt.step();
  stmt.free();
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const result = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  return result;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

// JWT middleware
function requireLogin(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    // ! Vulnerable
    const decoded = jwt.decode(token);
    req.user = decoded;
    res.locals.currentUser = decoded;
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}

// Initialize database
async function initDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE lists (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      share_token TEXT UNIQUE,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE list_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      list_id INTEGER NOT NULL,
      item_name TEXT NOT NULL,
      FOREIGN KEY(list_id) REFERENCES lists(id)
    )
  `);

  // Seed users
  const jessamyPass = bcrypt.hashSync("BugForgeIsTheB3st!", 10);
  const jeremyPass = bcrypt.hashSync("password", 10);

  dbRun(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, ["jessamy", jessamyPass]);
  dbRun(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, ["jeremy", jeremyPass]);
  // Seed lists
  db.run(`INSERT INTO lists (user_id, title, share_token ) VALUES (1, 'Jessamy B-day', 'zdy9xzep')`);
  db.run(`INSERT INTO lists (user_id, title, share_token ) VALUES (2, 'Jeremy B-day', '7npsze5r')`);

  // Seed items
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'Mechanical keyboard')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'Noise cancelling headphones')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (2, 'bug{us3r_enum3rati0n}')`);
}

// Routes

app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/register');

  try {
    jwt.verify(token, JWT_SECRET);
    return res.redirect('/dashboard');
  } catch (err) {
    return res.redirect('/login');
  }
});

// Login
app.get('/login', (req, res) => {
  const error = req.query.error;
  res.render('login', { error });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const user = dbGet(`SELECT * FROM users WHERE username = ?`, [username]);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.redirect('/login?error=invalid');
  }

  // Create JWT token
  const token = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  // Set token in cookie
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/"
  });

  res.redirect('/dashboard');
});

// Dashboard
app.get('/dashboard', requireLogin, (req, res) => {
  const shared = req.query.shared;
  const lists = dbAll(`SELECT * FROM lists WHERE user_id = ? ORDER BY id DESC`, [req.user.id]);
  res.render('dashboard', { lists, shared });
});

// View List
app.get('/list/:id', requireLogin, (req, res) => {
  const listId = req.params.id;

  const list = dbGet(`SELECT * FROM lists WHERE id = ? and user_id = ?`, [listId, req.user.id]);
  if (!list) {
    return res.redirect('/dashboard');
  }

  const items = dbAll(`SELECT * FROM list_items WHERE list_id = ?`, [listId]);
  res.render('list', { list, items });
});

// Add item to list
app.post('/lists/:id/items/add', requireLogin, (req, res) => {
  const listId = req.params.id;
  const item_name = req.body.new_item;
  const userId = req.user.id;

  // Check ownership before inserting
  const list = dbGet(`SELECT id FROM lists WHERE id = ? AND user_id = ?`, [listId, userId]);
  if (!list) {
    return res.status(403).send("Nice try. That's not your list.");
  }
  // Insert into db only after ownership is verified
  dbRun(`INSERT INTO list_items (list_id, item_name) values (?, ?)`, [listId, item_name]);
  res.redirect(`/list/${listId}`);
});

// Create a list
app.post('/lists', requireLogin, (req, res) => {
  const newList = req.body.new_list;
  dbRun(`INSERT INTO lists (user_id, title) VALUES (?, ?)`, [req.user.id, newList]);
  res.redirect('/dashboard');
});

// Delete list
app.post('/lists/:id/delete', requireLogin, (req, res) => {
  const listId = req.params.id;
  const list = dbGet('SELECT id FROM lists WHERE id = ? AND user_id = ?', [listId, req.user.id]);
  if (!list) {
    return res.status(403).send('Not your list');
  }

  dbRun('DELETE FROM list_items WHERE list_id = ?', [listId]);
  dbRun('DELETE FROM lists WHERE id = ?', [listId]);
  res.redirect('/dashboard');
});

// Generate share link
app.post('/lists/:id/share', requireLogin, (req, res) => {
  const token = Math.random().toString(36).slice(2, 10);
  const listId = req.params.id;

  dbRun(`UPDATE lists SET share_token = ? WHERE id = ? AND user_id = ?`, [token, listId, req.user.id]);
  res.redirect(`/dashboard?shared=shared`);
});

// Public shared list view
app.get('/share/:token', (req, res) => {
  const list = dbGet(`SELECT * FROM lists WHERE share_token = ?`, [req.params.token]);
  if (!list) return res.status(404).send("Not found.");

  const items = dbAll(`SELECT * FROM list_items WHERE list_id = ?`, [list.id]);
  res.render('share', { list, items });
});

// Delete item
app.post('/delete/:item_id/:list_id', requireLogin, (req, res) => {
  const item_id = req.params.item_id;
  const list_id = req.params.list_id;

  // Validate Referer to prevent open redirect
  let backUrl = "/dashboard";
  const referer = req.get("Referer");
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const host = req.get("host");
      // Only use referer if it's from the same host
      if (refererUrl.host === host) {
        backUrl = refererUrl.pathname;
      }
    } catch (err) {
      console.log(err)
    }
  }

  // Verify ownership before deleting
  const list = dbGet(`SELECT id FROM lists WHERE id = ? AND user_id = ?`, [list_id, req.user.id]);
  if (!list) {
    return res.status(403).send("Nice try. That's not your list.");
  }
  dbRun(`DELETE FROM list_items WHERE id = ? AND list_id = ?`, [item_id, list_id]);
  res.redirect(backUrl);
});

// Register
app.get('/register', (req, res) => {
  const error = req.query.error;
  res.render('register', { error });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.redirect('/register');
  }

  // Check if username already exists
  const existingUser = dbGet(`SELECT id FROM users WHERE username = ?`, [username]);
  if (existingUser) {
    return res.redirect('/register?error=exists');
  }

  const hash = bcrypt.hashSync(password, 10);
  dbRun(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, [username, hash]);
  res.redirect('/login');
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Server
const PORT = process.env.PORT || 3000;

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Gift Lab running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
