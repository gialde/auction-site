const crypto = require('crypto');
const { sendVerificationCode } = require('./mailer');
const express = require('express');
require('dotenv').config();
const { pool, initDB } = require('./db');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Сессии
app.use(session({
  secret: process.env.SECRET_KEY || 'auction-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 часа
}));

// Делаем user доступным во всех шаблонах
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Middleware проверки авторизации
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      return res.status(403).send('Доступ запрещён');
    }
    next();
  };
}

// ---------- Главная ----------
// ---------- Регистрация (шаг 1 — отправка кода) ----------
app.route('/register')
  .get((req, res) => {
    res.render('register', { error: null, step: 1 });
  })
  .post(async (req, res) => {
    const { email, password, full_name, role } = req.body;
    
    // Проверяем, существует ли уже пользователь
    const exist = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (exist.rows.length > 0) {
      return res.render('register', { error: 'Этот email уже занят.', step: 1 });
    }
    
    // Генерируем код
    const code = crypto.randomInt(100000, 999999).toString();
    const hash = await bcrypt.hash(password, 10);
    
    // Сохраняем неподтверждённого пользователя
    await pool.query(
      'INSERT INTO users (email, password, full_name, role, verification_code, verified) VALUES ($1,$2,$3,$4,$5,FALSE)',
      [email, hash, full_name, role || 'user', code]
    );
    
    // Отправляем код на почту
    try {
      await sendVerificationCode(email, code);
    } catch (err) {
      console.error('Ошибка отправки:', err);
      return res.render('register', { error: 'Не удалось отправить код. Проверьте email.', step: 1 });
    }
    
    res.render('verify', { email, error: null });
  });

// ---------- Подтверждение кода ----------
app.route('/verify')
  .get((req, res) => res.redirect('/register'))
  .post(async (req, res) => {
    const { email, code } = req.body;
    const result = await pool.query(
      'SELECT * FROM users WHERE email=$1 AND verification_code=$2 AND verified=FALSE',
      [email, code]
    );
    
    if (result.rows.length === 0) {
      return res.render('verify', { email, error: 'Неверный код. Попробуйте снова.' });
    }
    
    await pool.query(
      'UPDATE users SET verified=TRUE, verification_code=NULL WHERE email=$1',
      [email]
    );
    
    res.redirect('/login?msg=verified');
  });

// ---------- Вход ----------
app.route('/login')
  .get((req, res) => {
    res.render('login', { error: null, msg: req.query.msg || null });
  })
  .post(async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Неверный email или пароль', msg: null });
    }

    if (!user.verified) {
      return res.render('login', { error: 'Email не подтверждён. Проверьте почту.', msg: null });
    }

    if (user.banned) {
      return res.render('login', { error: 'Ваш аккаунт заблокирован.', msg: null });
    }

    req.session.user = { id: user.id, email: user.email, full_name: user.full_name, role: user.role };
    res.redirect('/');
  });

// ---------- Выход ----------
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});
app.get('/', async (req, res) => {
  const search = req.query.search || '';
  const auction_filter = req.query.auction_filter || '';
  
  let query = `
    SELECT i.*, a.name AS auction_name, a.date AS auction_date
    FROM items i
    JOIN auctions a ON i.auction_id = a.id
    WHERE i.name ILIKE $1
  `;
  let params = [`%${search}%`];
  
  if (auction_filter) {
    query += ' AND i.auction_id = $2';
    params.push(auction_filter);
  }
  
  query += ' ORDER BY a.date, i.lot_number';
  
  const items = await pool.query(query, params);
  const auctions = await pool.query('SELECT * FROM auctions ORDER BY date');
  
  res.render('index', {
    items: items.rows,
    auctions: auctions.rows,
    search,
    auction_filter
  });
});

// ---------- Запрос 1 ----------
app.route('/query1')
  .get(async (req, res) => {
  const auctions = await pool.query('SELECT id, name, date FROM auctions ORDER BY date');
  res.render('query1', { items: undefined, auctions: auctions.rows });
  })
  .post(async (req, res) => {
  const { auction_id } = req.body;
  const result = await pool.query(`
    SELECT i.id, i.lot_number, i.name, i.start_price, s.full_name AS seller
    FROM items i
    JOIN sellers s ON i.seller_id = s.id
    WHERE i.auction_id = $1
    ORDER BY i.lot_number
  `, [auction_id]);
  const auctions = await pool.query('SELECT id, name, date FROM auctions ORDER BY date');
  res.render('query1', { items: result.rows, auctions: auctions.rows });
});

// ---------- Запрос 2 ----------
app.route('/query2')
  .get(async (req, res) => {
    const specifics = await pool.query('SELECT DISTINCT specifics FROM auctions ORDER BY specifics');
    res.render('query2', { auctions: undefined, specifics: specifics.rows });
  })
  .post(async (req, res) => {
    const { specifics } = req.body;
    const result = await pool.query(`
      SELECT DISTINCT a.name, a.place, a.date
      FROM auctions a
      JOIN items i ON i.auction_id = a.id
      JOIN sales s ON s.item_id = i.id
      WHERE a.specifics = $1
    `, [specifics]);
    const allSpecifics = await pool.query('SELECT DISTINCT specifics FROM auctions ORDER BY specifics');
    res.render('query2', { auctions: result.rows, specifics: allSpecifics.rows });
  });
// ---------- Запрос 3 ----------
app.get('/query3', async (req, res) => {
  const result = await pool.query(`
    SELECT i.name, i.start_price, s.final_price,
           (s.final_price - i.start_price) AS difference
    FROM items i JOIN sales s ON i.id = s.item_id
    ORDER BY difference DESC LIMIT 1
  `);
  res.render('query3', { item: result.rows[0] });
});

// ---------- Запрос 4 ----------
app.get('/query4', async (req, res) => {
  const result = await pool.query(`
    SELECT a.name, a.place, a.date, COUNT(s.item_id)::int AS sold
    FROM auctions a
    JOIN items i ON i.auction_id = a.id
    JOIN sales s ON s.item_id = i.id
    GROUP BY a.id
    ORDER BY sold DESC LIMIT 1
  `);
  res.render('query4', { auction: result.rows[0] });
});

// ---------- Запрос 5 ----------
app.get('/query5', async (req, res) => {
  const result = await pool.query(`
    SELECT b.full_name, b.passport, s.final_price
    FROM buyers b
    JOIN sales s ON b.id = s.buyer_id
    JOIN items i ON s.item_id = i.id
    ORDER BY s.final_price DESC LIMIT 1
  `);
  res.render('query5', { buyer: result.rows[0] });
});

// ---------- Запрос 6 ----------
app.get('/query6', async (req, res) => {
  const result = await pool.query(`
    SELECT sel.full_name, sel.passport, s.final_price
    FROM sellers sel
    JOIN items i ON sel.id = i.seller_id
    JOIN sales s ON s.item_id = i.id
    ORDER BY s.final_price DESC LIMIT 1
  `);
  res.render('query6', { seller: result.rows[0] });
});

// ---------- Управление лотами ----------
app.route('/add-item')
  .get(async (req, res) => {
    const aucRes = await pool.query('SELECT * FROM auctions ORDER BY date');
    const selRes = await pool.query('SELECT id, full_name FROM sellers ORDER BY full_name');
    res.render('add_item', {
      auctions: aucRes.rows,
      sellers: selRes.rows,
      selectedAuction: null,
      lots: [],
      message: null
    });
  })
  .post(async (req, res) => {
    const { auction_id, action, lot_id, seller_id, name, description, start_price } = req.body;

    // Вспомогательная функция для загрузки данных аукциона
    async function loadAuctionData(aid, msg) {
      const aucRes = await pool.query('SELECT * FROM auctions ORDER BY date');
      const selRes = await pool.query('SELECT id, full_name FROM sellers ORDER BY full_name');
      const lotsRes = await pool.query(`
        SELECT i.*, s.full_name AS seller_name,
               CASE WHEN sales.item_id IS NULL THEN FALSE ELSE TRUE END AS is_sold
        FROM items i
        JOIN sellers s ON i.seller_id = s.id
        LEFT JOIN sales ON sales.item_id = i.id
        WHERE i.auction_id = $1
        ORDER BY i.lot_number
      `, [aid]);
      return {
        auctions: aucRes.rows,
        sellers: selRes.rows,
        selectedAuction: aid,
        lots: lotsRes.rows,
        message: msg
      };
    }

    if (action === 'select') {
      const data = await loadAuctionData(auction_id, null);
      return res.render('add_item', data);
    }

    if (action === 'add') {
      const sid = parseInt(seller_id);
      
      if (!sid || sid <= 0) {
        const data = await loadAuctionData(auction_id, 'Ошибка: выберите продавца из списка.');
        return res.render('add_item', data);
      }

      const lotRes = await pool.query(
        'SELECT COALESCE(MAX(lot_number),0)+1 AS next_lot FROM items WHERE auction_id=$1',
        [auction_id]
      );
      const nextLot = lotRes.rows[0].next_lot;

      await pool.query(`
        INSERT INTO items (auction_id, lot_number, seller_id, name, description, start_price)
        VALUES ($1,$2,$3,$4,$5,$6)
      `, [auction_id, nextLot, sid, name, description, start_price]);

      return res.redirect(303, `/add-item?auction_id=${auction_id}&msg=added`);
    }

    if (action === 'delete') {
      const check = await pool.query('SELECT * FROM sales WHERE item_id=$1', [lot_id]);
      if (check.rows.length > 0) {
        const data = await loadAuctionData(auction_id, 'Ошибка: нельзя удалить проданный лот.');
        return res.render('add_item', data);
      }

      await pool.query('DELETE FROM items WHERE id=$1', [lot_id]);
      return res.redirect(303, `/add-item?auction_id=${auction_id}&msg=deleted`);
    }

    res.redirect('/add-item');
  });

// Для редиректов с сообщением
app.get('/add-item', async (req, res) => {
  const auction_id = req.query.auction_id;
  const msg = req.query.msg;
  const aucRes = await pool.query('SELECT * FROM auctions ORDER BY date');
  const selRes = await pool.query('SELECT id, full_name FROM sellers ORDER BY full_name');
  let lots = [];
  if (auction_id) {
    const lotsRes = await pool.query(`
      SELECT i.*, s.full_name AS seller_name,
             CASE WHEN sales.item_id IS NULL THEN FALSE ELSE TRUE END AS is_sold
      FROM items i
      JOIN sellers s ON i.seller_id = s.id
      LEFT JOIN sales ON sales.item_id = i.id
      WHERE i.auction_id = $1
      ORDER BY i.lot_number
    `, [auction_id]);
    lots = lotsRes.rows;
  }
  let message = null;
  if (msg === 'added') message = 'Лот успешно добавлен.';
  if (msg === 'deleted') message = 'Лот удалён.';
  res.render('add_item', {
    auctions: aucRes.rows,
    sellers: selRes.rows,
    selectedAuction: auction_id || null,
    lots,
    message
  });
});

// ---------- Админ-панель ----------
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  res.render('admin');
});

// Список пользователей
app.get('/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  const result = await pool.query('SELECT * FROM users ORDER BY id');
  res.render('admin_users', { users: result.rows, message: req.query.msg || null });
});

// Забанить
app.post('/admin/users/ban', requireAuth, requireRole('admin'), async (req, res) => {
  await pool.query('UPDATE users SET banned=TRUE WHERE id=$1', [req.body.user_id]);
  res.redirect('/admin/users?msg=Пользователь+забанен');
});

// Разбанить
app.post('/admin/users/unban', requireAuth, requireRole('admin'), async (req, res) => {
  await pool.query('UPDATE users SET banned=FALSE WHERE id=$1', [req.body.user_id]);
  res.redirect('/admin/users?msg=Пользователь+разбанен');
});

// Удалить
app.post('/admin/users/delete', requireAuth, requireRole('admin'), async (req, res) => {
  await pool.query('DELETE FROM users WHERE id=$1', [req.body.user_id]);
  res.redirect('/admin/users?msg=Пользователь+удалён');
});
// ---------- Старт ----------

app.get('/privacy', (req, res) => res.render('privacy'));
app.get('/terms', (req, res) => res.render('terms'));
app.get('/favorites', (req, res) => res.render('favorites'));
app.get('/cart', (req, res) => res.render('cart'));
app.get('/profile', requireAuth, (req, res) => res.render('profile'));
initDB().then(() => {
  app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
});