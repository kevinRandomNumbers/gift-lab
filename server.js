const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// JWT Config
const JWT_SECRET = "password"; //Lab for cracking JWT
const JWT_EXPIRES_IN = "2h";

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));


// JWT middleware
function requireLogin(req, res, next) {
  // const token = req.cookies.token;
  // if (!token) return res.redirect('/login');

  // try {
  //   const decoded = jwt.verify(token, JWT_SECRET);
  //   req.user = decoded;
  //   res.locals.currentUser = decoded;
  //   next();
  // } catch (err) {
  //   return res.redirect('/login');
  // }
  next(); // just for testing
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
  const adminPass = bcrypt.hashSync("56yTDv!!SQWxcez&&2S", 10);
  const jeremyPass = bcrypt.hashSync("cheesecake",10);

  db.run(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, ["admin", adminPass]);
  db.run(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, ["jeremy", jeremyPass]);
  // Seed lists
  db.run(`INSERT INTO lists (user_id, title, share_token) VALUES (1, 'Admin b-day', 'share-admin')`);
  db.run(`INSERT INTO lists (user_id, title, share_token) VALUES (2, 'Jeremey b-day', 'share-jeremey')`);

  // Seed items
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'Lego set')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'Noise cancelling headphones')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (1, 'You found the bug!')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (2, 'keyboard')`);
  db.run(`INSERT INTO list_items (list_id, item_name) VALUES (2, 'computer')`);
});

// Routes

app.get('/', (req, res) => {
  // const token = req.cookies.token;
  // if (!token) return res.redirect('/login');
  return res.redirect('/dashboard');
});

/* LOGIN */

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

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // insecure on purpose for labs
    res.cookie("token", token, {
      httpOnly: false,
      secure: false,
      sameSite: "Lax"
    });

    res.redirect('/dashboard');
  });
});

/* REGISTER */

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  const hash = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (username, password_hash) VALUES (?, ?)`,
    [username, hash],
    function (err) {
      if (err) {
        flash(res, 'error', 'Username taken.');
        return res.redirect('/register');
      }
      flash(res, 'success', 'Account created.');
      res.redirect('/login');
    }
  );
});

/* LOGOUT */

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

/* DASHBOARD */

app.get('/dashboard', requireLogin, (req, res) => {
  db.all(
    `SELECT * FROM lists WHERE user_id = ? ORDER BY id DESC`,
    [/*req.user.id*/1],
    (err, lists) => {
      if (err) {
        return res.redirect('/login');
      }
      console.log(lists)
      res.render('dashboard', { lists });
    }
  );
});

/* CREATE LIST */

app.post('/lists', requireLogin, (req, res) => {
  const { title } = req.body;

  db.run(
    `INSERT INTO lists (user_id, title) VALUES (?, ?)`,
    [req.user.id, title],
    function (err) {
      if (err) {
        flash(res, 'error', 'Could not create list.');
        return res.redirect('/dashboard');
      }
      res.redirect(`/lists/${this.lastID}`);
    }
  );
});

/* VIEW LIST */

app.get('/list/:id', requireLogin, (req, res) => {
  const listId = req.params.id;

  db.get(
    `SELECT * FROM lists WHERE id = ?`,
    [listId],
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

/* EDIT LIST TITLE */

app.post('/lists/:id/edit', requireLogin, (req, res) => {
  const { title } = req.body;
  const listId = req.params.id;

  db.run(
    `UPDATE lists SET title = ? WHERE id = ? AND user_id = ?`,
    [title, listId, req.user.id],
    function (err) {
      if (err || this.changes === 0) flash(res, 'error', 'Could not update list.');
      res.redirect(`/lists/${listId}`);
    }
  );
});

/* DELETE LIST */

app.post('/lists/:id/delete', requireLogin, (req, res) => {
  const listId = req.params.id;

  db.run(`DELETE FROM list_items WHERE list_id = ?`, [listId], () => {
    db.run(
      `DELETE FROM lists WHERE id = ? AND user_id = ?`,
      [listId, req.user.id],
      function (err2) {
        if (err2 || this.changes === 0) flash(res, 'error', 'Could not delete list.');
        res.redirect('/dashboard');
      }
    );
  });
});

/* ADD ITEM */

app.post('/lists/:id/items/add', /*requireLogin,*/ (req, res) => {
  const listId = req.params.id;
  const  item_name  = req.body.new_item;

  db.run(
    `INSERT INTO list_items (list_id, item_name) values (?, ?)`,
    [listId, item_name],
    () => res.redirect(`/list/${listId}`)
  )
});

/* DELETE ITEM */

app.post('/items/:id/delete', requireLogin, (req, res) => {
  const itemId = req.params.id;

  db.get(
    `SELECT list_items.list_id, lists.user_id
     FROM list_items
     JOIN lists ON lists.id = list_items.list_id
     WHERE list_items.id = ?`,
    [itemId],
    (err, row) => {
      if (!row || row.user_id !== req.user.id) {
        return res.redirect('/dashboard');
      }

      db.run(`DELETE FROM list_items WHERE id = ?`, [itemId], () => {
        res.redirect(`/lists/${row.list_id}`);
      });
    }
  );
});

/* SHARING */

// Generate share link
app.post('/lists/:id/share', requireLogin, (req, res) => {
  const token = Math.random().toString(36).slice(2, 10);
  const listId = req.params.id;

  db.run(
    `UPDATE lists SET share_token = ? WHERE id = ? AND user_id = ?`,
    [token, listId, req.user.id],
    function (err) {
      if (err || this.changes === 0) flash(res, 'error', 'Could not create share link.');
      else flash(res, 'success', 'Share link created.');
      res.redirect(`/lists/${listId}`);
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

/* SERVER */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Gift Lab running on http://localhost:${PORT}`);
});
