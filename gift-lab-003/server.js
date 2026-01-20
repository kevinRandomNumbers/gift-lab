const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// JWT Config
const JWT_SECRET = "gift_lab_001_2026"; //! Make this simple for JWT cracking lab
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


// JWT middleware
function requireLogin(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    res.locals.currentUser = decoded;
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}

// DB in memory
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
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
  const adminPass = bcrypt.hashSync("BugForgeIsTheB3st!", 10);

  db.run(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, ["admin", adminPass]);
  // Seed lists
  db.run(`INSERT INTO lists (user_id, title, share_token ) VALUES (1, 'Admin B-day', 'bGlzdFdpdGhJZC0x')`);

  // Seed items
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'Lego set')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'Noise cancelling headphones')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'bug{0bscur3_i5_n0t_s3cur3')`);
});

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
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) return res.status(500).send("Internal error.");

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.redirect('/login');
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
});

// Dashboard
app.get('/dashboard', requireLogin, (req, res) => {
  const shared = req.query.shared;
  db.all(
    `SELECT * FROM lists WHERE user_id = ? ORDER BY id DESC`,
    [req.user.id],
    (err, lists) => {
      if (err) {
        return res.redirect('/login');
      }
      res.render('dashboard', { lists, shared });
    }
  );
});

// View List
app.get('/list/:id', requireLogin, (req, res) => {
  const listId = req.params.id;

  db.get(
    `SELECT * FROM lists WHERE id = ? and user_id = ?`,  //! Delete `and user_id` to enable IDOR
    [listId, req.user.id],
    (err, list) => {
      if (!list) {
        return res.redirect('/dashboard');
      }

      db.all(
        `SELECT * FROM list_items WHERE list_id = ?`,
        [listId],
        (err2, items) => {
          res.render('list', { list, items });
        }
      );
    }
  );
});

// Add item to list
app.post('/lists/:id/items/add', requireLogin, (req, res) => {
  const listId = req.params.id;
  const item_name = req.body.new_item;
  const userId = req.user.id;

  // Step 1: Check ownership
  // ! If I comment this, you can add items on lists not owned by you
  db.get(
    `SELECT id FROM lists WHERE id = ? AND user_id = ?`,
    [listId, userId],
    (err, list) => {
      if (err) {
        return res.status(500).send("DB error");
      }
      if (!list) {
        // Either the list doesn't exist or it doesn't belong to them
        return res.status(403).send("Nice try. That's not your list.");
      }
    });
  // Insert into db
  db.run(
    `INSERT INTO list_items (list_id, item_name) values (?, ?)`,
    [listId, item_name],
    () => res.redirect(`/list/${listId}`)
  )
});

// Create a list
app.post('/lists', requireLogin, (req, res) => {
  const newList = req.body.new_list;

  db.run(
    `INSERT INTO lists (user_id, title) VALUES (?, ?)`,
    [req.user.id, newList],
    function (err) {
      if (err) {
        return res.redirect('/dashboard');
      }
      res.redirect('/dashboard');
    }
  );
});

// Delete list
app.post('/lists/:id/delete', requireLogin, (req, res) => {
  const listId = req.params.id;
  
  //! Remove `and user_id` if you want somebody else to delete other user's lists
  db.get('SELECT id FROM lists WHERE id = ? AND user_id = ?', 
    [listId, req.user.id], 
    (err, list) => {
      if (err || !list) {
        return res.status(403).send('Not your list');
      }

      db.run('DELETE FROM list_items WHERE list_id = ?', [listId], (err) => {
        db.run('DELETE FROM lists WHERE id = ?', [listId], (err) => {
          res.redirect('/dashboard');
        });
      });
    }
  );
});

// Generate share link
app.post('/lists/:id/share', requireLogin, (req, res) => {
  // const token = Math.random().toString(36).slice(2, 10); //! This is good enough for lab, make weaker for vuln lab
  const baseDecoded = "listWithId-";
  const baseEncoded = Buffer.from(baseDecoded).toString('base64');
  const listId = req.params.id;
  const listIdEncoded = Buffer.from(listId).toString('base64');
  const token = `${baseEncoded}${listIdEncoded}`

  db.run(
    `UPDATE lists SET share_token = ? WHERE id = ? AND user_id = ?`,
    [token, listId, req.user.id],
    function (err) {
      if (err || this.changes === 0) {
        console.log("error creating link")
      }
      res.redirect(`/dashboard?shared=shared`);
    }
  );
});

// Public shared list view
app.get('/share/:token', (req, res) => {
  db.get(
    `SELECT * FROM lists WHERE share_token = ?`,
    [req.params.token],
    (err, list) => {
      if (!list) return res.status(404).send("Not found.");

      db.all(
        `SELECT * FROM list_items WHERE list_id = ?`,
        [list.id],
        (err2, items) => {
          res.render('share', { list, items });
        }
      );
    }
  );
});

// Delete item
app.post('/delete/:item_name/:list_id', requireLogin, (req, res) => {
  const item_name = req.params.item_name;
  const list_id = req.params.list_id;
  const backUrl = req.get("Referer") || "/dashboard";
  db.run(`DELETE FROM list_items where list_id = ? and item_name = ?`, [list_id, item_name], () => {
    res.redirect(backUrl)
  })
});

// Register
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.redirect('/register');
  }

  // Check if username already exists
  db.get(
    `SELECT id FROM users WHERE username = ?`,
    [username],
    (err, existingUser) => {
      if (err) {
        return res.redirect('/register');
      }

      if (existingUser) {
        return res.redirect('/register');
      }

      const hash = bcrypt.hashSync(password, 10);
      db.run(
        `INSERT INTO users (username, password_hash) VALUES (?, ?)`,
        [username, hash],
        function (err) {
          if (err) {
            return res.redirect('/register');
          }
          res.redirect('/login');
        }
      );
    }
  );
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});


// Endpoints for testing
app.get("/api/dev/listItems", (req, res) => {
  db.all(`SELECT * FROM list_items`, (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

app.get("/api/dev/lists", (req, res) => {
  db.all(`SELECT * FROM lists`, (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(data);
  });
});

// Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Gift Lab running on http://localhost:${PORT}`);
});
