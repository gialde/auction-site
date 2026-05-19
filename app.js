const crypto = require('crypto');
const { sendVerificationCode } = require('./mailer');
const express = require('express');
require('dotenv').config();
const { pool, initDB } = require('./db');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Сессии
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SECRET_KEY || 'auction-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
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
// Socket.io
io.on('connection', (socket) => {
  console.log('Пользователь подключился:', socket.id);
  
  // Присоединение к комнате чата
  socket.on('join-chat', (dealId) => {
    socket.join(`chat-${dealId}`);
  });
  
  // Присоединение к комнате поддержки
  socket.on('join-support', (userId) => {
    socket.join(`support-${userId}`);
  });
  
  // Присоединение к комнате лота (для ставок)
  socket.on('join-item', (itemId) => {
    socket.join(`item-${itemId}`);
  });
  
  socket.on('disconnect', () => {
    console.log('Пользователь отключился:', socket.id);
  });
});

// Делаем io доступным в маршрутах
app.use((req, res, next) => {
  req.io = io;
  next();
});
// ---------- Главная ----------
app.post('/profile/topup', requireAuth, async (req, res) => {
  const amount = parseFloat(req.body.amount);
  if (!amount || amount <= 0) return res.redirect('/profile');
  
  await pool.query(
    'UPDATE users SET balance = balance + $1 WHERE id = $2',
    [amount, req.session.user.id]
  );
  res.redirect('/profile');
});
// ---------- Регистрация (шаг 1 — отправка кода) ----------
app.route('/register')
  .get((req, res) => {
    res.render('register', { error: null, step: 1 });
  })
  .post(async (req, res) => {
  const { email, password, first_name, last_name, middle_name, passport, phone, role } = req.body;
  
  if (password !== req.body.password_confirm) {
    return res.render('register', { error: 'Пароли не совпадают!', step: 1 });
  }
  
  const full_name = [last_name, first_name, middle_name].filter(Boolean).join(' ');
  
  const exist = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  if (exist.rows.length > 0) {
    return res.render('register', { error: 'Этот email уже занят.', step: 1 });
  }
  
  const code = crypto.randomInt(100000, 999999).toString();
  const hash = await bcrypt.hash(password, 10);
  
  await pool.query(
    `INSERT INTO users (email, password, full_name, first_name, last_name, middle_name, passport, phone, role, verification_code, verified)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,FALSE)`,
    [email, hash, full_name, first_name, last_name, middle_name || null, passport, phone || null, role || 'user', code]
  );
  
  try {
    await sendVerificationCode(email, code);
  } catch (err) {
    console.error('Ошибка отправки:', err);
    return res.render('register', { error: 'Не удалось отправить код.', step: 1 });
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

    req.session.user = { 
  id: user.id, 
  email: user.email, 
  full_name: user.full_name, 
  role: user.role,
  balance: user.balance 
};
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
  WHERE i.name ILIKE $1 AND i.status = 'approved' AND i.is_ended = FALSE
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
      SELECT i.id, i.lot_number, i.name, i.start_price, u.full_name AS creator_name, i.status
      FROM items i
      JOIN users u ON i.creator_id = u.id
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
      JOIN deals d ON d.item_id = i.id
      WHERE a.specifics = $1 AND d.status = 'done'
    `, [specifics]);
    const allSpecifics = await pool.query('SELECT DISTINCT specifics FROM auctions ORDER BY specifics');
    res.render('query2', { auctions: result.rows, specifics: allSpecifics.rows });
  });
// ---------- Запрос 3 ----------
app.get('/query3', async (req, res) => {
  const result = await pool.query(`
    SELECT i.name, i.start_price, d.amount AS final_price,
           (d.amount - i.start_price) AS difference
    FROM items i
    JOIN deals d ON i.id = d.item_id
    WHERE d.status = 'done'
    ORDER BY difference DESC LIMIT 1
  `);
  res.render('query3', { item: result.rows[0] || null });
});

// ---------- Запрос 4 ----------
app.get('/query4', async (req, res) => {
  const result = await pool.query(`
    SELECT a.name, a.place, a.date, COUNT(d.item_id)::int AS sold
    FROM auctions a
    JOIN items i ON i.auction_id = a.id
    JOIN deals d ON d.item_id = i.id
    WHERE d.status = 'done'
    GROUP BY a.id
    ORDER BY sold DESC LIMIT 1
  `);
  res.render('query4', { auction: result.rows[0] || null });
});

// ---------- Запрос 5 ----------
app.get('/query5', async (req, res) => {
  const result = await pool.query(`
    SELECT u.full_name, u.email, d.amount AS final_price
    FROM users u
    JOIN deals d ON u.id = d.buyer_id
    ORDER BY d.amount DESC LIMIT 1
  `);
  res.render('query5', { buyer: result.rows[0] || null });
});

// ---------- Запрос 6 ----------
app.get('/query6', async (req, res) => {
  const result = await pool.query(`
    SELECT u.full_name, u.email, d.amount AS final_price
    FROM users u
    JOIN deals d ON u.id = d.seller_id
    ORDER BY d.amount DESC LIMIT 1
  `);
  res.render('query6', { seller: result.rows[0] || null });
});
// ---------- Управление лотами ----------

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
// ---------- Страница лота ----------
app.get('/item/:id', async (req, res) => {
  const item = await pool.query(`
    SELECT i.*, a.name AS auction_name, a.date AS auction_date
    FROM items i
    JOIN auctions a ON i.auction_id = a.id
    WHERE i.id = $1
  `, [req.params.id]);
  
  const bids = await pool.query(`
    SELECT b.*, u.full_name
    FROM bids b
    JOIN users u ON b.user_id = u.id
    WHERE b.item_id = $1
    ORDER BY b.amount DESC
  `, [req.params.id]);
  
  const maxBid = bids.rows[0] || null;
  
  res.render('item', {
    item: item.rows[0],
    bids: bids.rows,
    maxBid,
    user: req.session.user ? await pool.query('SELECT * FROM users WHERE id=$1', [req.session.user.id]).then(r => r.rows[0]) : null
  });
});

// ---------- Сделать ставку ----------
app.post('/item/:id/bid', requireAuth, async (req, res) => {
  const itemId = req.params.id;
  // Проверяем, не завершён ли аукцион
  const itemCheck = await pool.query('SELECT is_ended FROM items WHERE id=$1', [itemId]);
  if (itemCheck.rows[0].is_ended) {
    return res.send('<script>alert("Аукцион завершён, ставки больше не принимаются."); window.history.back();</script>');
}
  const amount = parseFloat(req.body.amount);
  const userId = req.session.user.id;
  
  // Проверяем баланс
  const user = await pool.query('SELECT balance FROM users WHERE id=$1', [userId]);
  if (user.rows[0].balance < amount) {
    return res.send('<script>alert("Недостаточно средств!"); window.history.back();</script>');
  }
  
  // Проверяем, что ставка выше предыдущей
  const maxBid = await pool.query('SELECT MAX(amount) AS max FROM bids WHERE item_id=$1', [itemId]);
  const item = await pool.query('SELECT start_price FROM items WHERE id=$1', [itemId]);
  const minAmount = maxBid.rows[0].max ? maxBid.rows[0].max + 1 : item.rows[0].start_price;
  if (amount < minAmount) {
    return res.send(`<script>alert("Ставка должна быть выше ${minAmount - 1} руб."); window.history.back();</script>`);
}
  
  if (amount < minAmount) {
    return res.send(`<script>alert("Ставка должна быть не ниже ${minAmount} руб."); window.history.back();</script>`);
  }
  
  await pool.query('INSERT INTO bids (item_id, user_id, amount) VALUES ($1,$2,$3)', [itemId, userId, amount]);
  req.io.to(`item-${itemId}`).emit('new-bid', { amount });
  res.redirect(`/item/${itemId}`);
});
// ---------- Завершить аукцион (админ) ----------
app.post('/item/:id/end', requireAuth, requireRole('admin'), async (req, res) => {
  const itemId = req.params.id;
  
  // Находим победителя (макс ставка)
  const winner = await pool.query(`
    SELECT b.user_id, b.amount, u.full_name
    FROM bids b
    JOIN users u ON b.user_id = u.id
    WHERE b.item_id = $1
    ORDER BY b.amount DESC
    LIMIT 1
  `, [itemId]);
  
  if (winner.rows.length === 0) {
    return res.send('<script>alert("Нет ставок!"); window.history.back();</script>');
  }
  
  const item = await pool.query('SELECT * FROM items WHERE id=$1', [itemId]);
  const win = winner.rows[0];
  
  // Создаём сделку
  await pool.query(`
    INSERT INTO deals (item_id, buyer_id, seller_id, amount, status)
    VALUES ($1,$2,$3,$4,'pending')
  `, [itemId, win.user_id, item.rows[0].creator_id, win.amount]);
  
  // Обновляем предмет
  await pool.query('UPDATE items SET is_ended=TRUE, winner_id=$1 WHERE id=$2', [win.user_id, itemId]);
  
  res.redirect(`/item/${itemId}`);
});

// ---------- Оплатить лот (покупатель) ----------
app.post('/deal/:id/pay', requireAuth, async (req, res) => {
  const dealId = req.params.id;
  const deal = await pool.query('SELECT * FROM deals WHERE id=$1 AND buyer_id=$2', [dealId, req.session.user.id]);
  
  if (deal.rows.length === 0) return res.redirect('/profile');
  
  const d = deal.rows[0];
  const user = await pool.query('SELECT balance FROM users WHERE id=$1', [req.session.user.id]);
  
  if (user.rows[0].balance < d.amount) {
    return res.send('<script>alert("Недостаточно средств!"); window.history.back();</script>');
  }
  
  // Замораживаем деньги
  await pool.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [d.amount, req.session.user.id]);
  await pool.query('UPDATE deals SET status=$1, paid_at=NOW() WHERE id=$2', ['paid', dealId]);
  
  res.redirect('/profile');
});

// ---------- Отправить товар (админ / продавец) ----------
app.post('/deal/:id/ship', requireAuth, async (req, res) => {
  const dealId = req.params.id;
  await pool.query('UPDATE deals SET status=$1, shipped_at=NOW() WHERE id=$2', ['shipped', dealId]);
  res.redirect('/profile');
});

// ---------- Подтвердить получение (покупатель) ----------
app.post('/deal/:id/receive', requireAuth, async (req, res) => {
  const dealId = req.params.id;
  const deal = await pool.query('SELECT * FROM deals WHERE id=$1 AND buyer_id=$2', [dealId, req.session.user.id]);
  
  if (deal.rows.length === 0) return res.redirect('/profile');
  
  await pool.query('UPDATE deals SET status=$1, received_at=NOW() WHERE id=$2', ['received', dealId]);
  
  // Переводим деньги продавцу
  const d = deal.rows[0];
  await pool.query(`
    UPDATE users SET balance = balance + $1 WHERE id = $2
  `, [d.amount, d.seller_id]);
  
  await pool.query('UPDATE deals SET status=$1, done_at=NOW() WHERE id=$2', ['done', dealId]);
  
  res.redirect('/profile');
});
app.route('/admin/auctions/add')
  .get(requireAuth, requireRole('admin'), (req, res) => {
    res.render('add_auction', { message: null });
  })
  .post(requireAuth, requireRole('admin'), async (req, res) => {
    const { name, place, date, specifics } = req.body;
    await pool.query('INSERT INTO auctions (name, place, date, specifics) VALUES ($1,$2,$3,$4)',
      [name, place, date, specifics]);
    res.render('add_auction', { message: 'Аукцион создан!' });
  });
// ---------- Создать лот (пользователь) ----------
app.route('/create-item')
  .get(requireAuth, async (req, res) => {
    const auctions = await pool.query('SELECT * FROM auctions ORDER BY date');
    res.render('create_item', { auctions: auctions.rows, message: null, error: null });
  })
  .post(requireAuth, async (req, res) => {
    const { auction_id, name, description, start_price } = req.body;
    
    const lotRes = await pool.query(
      'SELECT COALESCE(MAX(lot_number),0)+1 AS next_lot FROM items WHERE auction_id=$1',
      [auction_id]
    );
    const nextLot = lotRes.rows[0].next_lot;
    
    await pool.query(`
      INSERT INTO items (auction_id, lot_number, creator_id, name, description, start_price, status)
      VALUES ($1,$2,$3,$4,$5,$6,'pending')
    `, [auction_id, nextLot, req.session.user.id, name, description, start_price]);
    
    const auctions = await pool.query('SELECT * FROM auctions ORDER BY date');
    res.render('create_item', { auctions: auctions.rows, message: 'Лот отправлен на модерацию!', error: null });
  });
app.get('/admin/moderate', requireAuth, requireRole('admin'), async (req, res) => {
  const pending = await pool.query(`
    SELECT i.*, a.name AS auction_name, u.email AS creator_email
    FROM items i
    JOIN auctions a ON i.auction_id = a.id
    JOIN users u ON i.creator_id = u.id
    WHERE i.status = 'pending'
    ORDER BY i.id
  `);
  res.render('admin_moderate', { pending: pending.rows });
});

app.post('/admin/moderate/approve', requireAuth, requireRole('admin'), async (req, res) => {
  await pool.query('UPDATE items SET status=$1 WHERE id=$2', ['approved', req.body.item_id]);
  res.redirect('/admin/moderate');
});

app.post('/admin/moderate/reject', requireAuth, requireRole('admin'), async (req, res) => {
  await pool.query('UPDATE items SET status=$1 WHERE id=$2', ['rejected', req.body.item_id]);
  res.redirect('/admin/moderate');
});
// ---------- Управление аукционами ----------
app.get('/admin/auctions', requireAuth, requireRole('admin'), async (req, res) => {
  const auctions = await pool.query('SELECT * FROM auctions ORDER BY date');
  res.render('admin_auctions', { auctions: auctions.rows, message: req.query.msg || null });
});

app.post('/admin/auctions/delete', requireAuth, requireRole('admin'), async (req, res) => {
  const { auction_id } = req.body;
  await pool.query('DELETE FROM bids WHERE item_id IN (SELECT id FROM items WHERE auction_id=$1)', [auction_id]);
  await pool.query('DELETE FROM deals WHERE item_id IN (SELECT id FROM items WHERE auction_id=$1)', [auction_id]);
  await pool.query('DELETE FROM items WHERE auction_id=$1', [auction_id]);
  await pool.query('DELETE FROM auctions WHERE id=$1', [auction_id]);
  res.redirect('/admin/auctions?msg=Аукцион+удалён');
});
// ---------- Управление лотами (админ) ----------
app.get('/admin/items', requireAuth, requireRole('admin'), async (req, res) => {
  const auction_id = req.query.auction_id || '';
  
  let query = `
    SELECT i.*, a.name AS auction_name, u.email AS creator_email
    FROM items i
    JOIN auctions a ON i.auction_id = a.id
    JOIN users u ON i.creator_id = u.id
  `;
  let params = [];
  
  if (auction_id) {
    query += ' WHERE i.auction_id = $1';
    params.push(auction_id);
  }
  
  query += ' ORDER BY a.date, i.lot_number';
  
  const items = await pool.query(query, params);
  const auctions = await pool.query('SELECT * FROM auctions ORDER BY date');
  
  res.render('admin_items', {
    items: items.rows,
    auctions: auctions.rows,
    selectedAuction: auction_id,
    message: req.query.msg || null
  });
});

app.post('/admin/items/delete', requireAuth, requireRole('admin'), async (req, res) => {
  const { item_id } = req.body;
  await pool.query('DELETE FROM bids WHERE item_id=$1', [item_id]);
  await pool.query('DELETE FROM deals WHERE item_id=$1', [item_id]);
  await pool.query('DELETE FROM items WHERE id=$1', [item_id]);
  res.redirect('/admin/items?msg=Лот+удалён');
});
// ---------- Чат по сделке ----------
app.route('/chat/:dealId')
  .get(requireAuth, async (req, res) => {
    const deal = await pool.query(`
      SELECT d.*, i.name AS item_name
      FROM deals d
      JOIN items i ON d.item_id = i.id
      WHERE d.id = $1 AND (d.buyer_id = $2 OR d.seller_id = $2)
    `, [req.params.dealId, req.session.user.id]);
    
    if (deal.rows.length === 0) return res.redirect('/profile');
    
    const d = deal.rows[0];
    const partnerId = d.buyer_id === req.session.user.id ? d.seller_id : d.buyer_id;
    const partner = await pool.query('SELECT * FROM users WHERE id=$1', [partnerId]);
    
    const messages = await pool.query(`
      SELECT * FROM messages
      WHERE deal_id = $1
      ORDER BY created_at
    `, [req.params.dealId]);
    
    res.render('chat', {
      deal: d,
      partner: partner.rows[0],
      messages: messages.rows
    });
  })
  .post(requireAuth, async (req, res) => {
    const deal = await pool.query('SELECT * FROM deals WHERE id=$1', [req.params.dealId]);
    const d = deal.rows[0];
    const partnerId = d.buyer_id === req.session.user.id ? d.seller_id : d.buyer_id;
    
    await pool.query(`
      INSERT INTO messages (deal_id, sender_id, receiver_id, message)
      VALUES ($1,$2,$3,$4)
    `, [req.params.dealId, req.session.user.id, partnerId, req.body.message]);

        req.io.to(`chat-${req.params.dealId}`).emit('new-message', {
      sender_id: req.session.user.id,
      message: req.body.message,
      created_at: new Date()
    });
    
    res.redirect(`/chat/${req.params.dealId}`);
  });

// ---------- Поддержка ----------
app.route('/support')
  .get(requireAuth, async (req, res) => {
    // Ищем админа
    const admin = await pool.query("SELECT * FROM users WHERE role='admin' LIMIT 1");
    const adminId = admin.rows[0]?.id || 1;
    
    const messages = await pool.query(`
      SELECT m.*, u.full_name AS sender_name
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.deal_id IS NULL AND (m.sender_id = $1 OR m.receiver_id = $1)
      ORDER BY m.created_at
    `, [req.session.user.id]);
    
    res.render('support', { messages: messages.rows });
  })
.post(requireAuth, async (req, res) => {
    const admin = await pool.query("SELECT * FROM users WHERE role='admin' LIMIT 1");
    const adminId = admin.rows[0]?.id || 1;
    
    await pool.query(`
      INSERT INTO messages (deal_id, sender_id, receiver_id, message)
      VALUES (NULL, $1, $2, $3)
    `, [req.session.user.id, adminId, req.body.message]);
    
    req.io.to(`support-${req.session.user.id}`).emit('new-message', {
      sender_id: req.session.user.id,
      sender_name: req.session.user.full_name,
      message: req.body.message,
      created_at: new Date()
    });
    req.io.to('support-admin').emit('new-message', {
      sender_id: req.session.user.id,
      sender_name: req.session.user.full_name,
      message: req.body.message,
      created_at: new Date()
    });
    
    res.redirect('/support');
  });
// Админ видит обращения
app.get('/admin/support', requireAuth, requireRole('admin'), async (req, res) => {
  const users = await pool.query(`
    SELECT DISTINCT u.id, u.full_name, u.email
    FROM messages m
    JOIN users u ON (m.sender_id = u.id OR m.receiver_id = u.id)
    WHERE m.deal_id IS NULL AND u.id != $1
  `, [req.session.user.id]);
  res.render('admin_support_list', { users: users.rows });
});

app.route('/admin/support/:userId')
  .get(requireAuth, requireRole('admin'), async (req, res) => {
    const messages = await pool.query(`
      SELECT m.*, u.full_name AS sender_name
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.deal_id IS NULL AND (m.sender_id = $1 OR m.receiver_id = $1)
      ORDER BY m.created_at
    `, [req.params.userId]);
    const user = await pool.query('SELECT * FROM users WHERE id=$1', [req.params.userId]);
    res.render('admin_support_chat', { messages: messages.rows, chatUser: user.rows[0] });
  })
.post(requireAuth, requireRole('admin'), async (req, res) => {
    await pool.query(`
      INSERT INTO messages (deal_id, sender_id, receiver_id, message)
      VALUES (NULL, $1, $2, $3)
    `, [req.session.user.id, req.params.userId, req.body.message]);
    
    req.io.to(`support-${req.params.userId}`).emit('new-message', {
      sender_id: req.session.user.id,
      sender_name: req.session.user.full_name,
      message: req.body.message,
      created_at: new Date()
    });
    
    res.redirect(`/admin/support/${req.params.userId}`);
  });
// ---------- Страница пополнения через карту ----------
app.get('/profile/topup/card', requireAuth, async (req, res) => {
  const user = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.user.id]);
  res.render('topup', { user: user.rows[0] });
});

// ---------- Обработка пополнения (имитация) ----------
app.post('/profile/topup/card', requireAuth, async (req, res) => {
  const { card_number, card_expiry, card_cvv, amount } = req.body;
  
  // Простая валидация
  const cardClean = card_number.replace(/\s/g, '');
  if (cardClean.length !== 16 || isNaN(cardClean)) {
    return res.send('<script>alert("Неверный номер карты!"); window.history.back();</script>');
  }
  if (!card_expiry.match(/^\d{2}\/\d{2}$/)) {
    return res.send('<script>alert("Неверный срок действия!"); window.history.back();</script>');
  }
  if (card_cvv.length !== 3 || isNaN(card_cvv)) {
    return res.send('<script>alert("Неверный CVV!"); window.history.back();</script>');
  }
  
  const amountNum = parseInt(amount);
  if (!amountNum || amountNum < 50000 || amountNum > 10000000) {
  return res.send('<script>alert("Сумма должна быть от 50 000 до 10 000 000 ₽!"); window.history.back();</script>');
  }
  
  // Имитация задержки "обработки платежа"
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  // Зачисляем на баланс
  await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [amountNum, req.session.user.id]);
  req.session.user.balance += amountNum;
  
  res.send(`
    <script>
      alert("✅ Платёж на сумму ${amountNum} ₽ успешно выполнен!");
      window.location.href = "/profile";
    </script>
  `);
});
// ---------- Редактирование профиля ----------
app.route('/profile/edit')
  .get(requireAuth, async (req, res) => {
    const user = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.user.id]);
    res.render('edit_profile', { profile: user.rows[0], message: null });
  })
  .post(requireAuth, async (req, res) => {
    const { first_name, last_name, middle_name, email, passport, phone, password } = req.body;
    const full_name = [last_name, first_name, middle_name].filter(Boolean).join(' ');
    
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        `UPDATE users SET first_name=$1, last_name=$2, middle_name=$3, full_name=$4, email=$5, passport=$6, phone=$7, password=$8 WHERE id=$9`,
        [first_name, last_name, middle_name || null, full_name, email, passport, phone || null, hash, req.session.user.id]
      );
    } else {
      await pool.query(
        `UPDATE users SET first_name=$1, last_name=$2, middle_name=$3, full_name=$4, email=$5, passport=$6, phone=$7 WHERE id=$8`,
        [first_name, last_name, middle_name || null, full_name, email, passport, phone || null, req.session.user.id]
      );
    }
    
    req.session.user.full_name = full_name;
    req.session.user.email = email;
    res.redirect('/profile');
  });
// ---------- Старт ----------

app.get('/privacy', (req, res) => res.render('privacy'));
app.get('/terms', (req, res) => res.render('terms'));
app.get('/favorites', (req, res) => res.render('favorites'));
app.get('/cart', (req, res) => res.render('cart'));

app.get('/profile', requireAuth, async (req, res) => {
  const user = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.user.id]);
  const myBids = await pool.query(`
    SELECT b.*, i.name AS item_name, i.start_price
    FROM bids b
    JOIN items i ON b.item_id = i.id
    WHERE b.user_id = $1
    ORDER BY b.bid_time DESC
  `, [req.session.user.id]);
  const deals = await pool.query(`
  SELECT d.*, i.name AS item_name
  FROM deals d
  JOIN items i ON d.item_id = i.id
  WHERE d.buyer_id = $1 OR d.seller_id = $1
  ORDER BY d.created_at DESC
`, [req.session.user.id]);
  res.render('profile', { profile: user.rows[0], myBids: myBids.rows, deals: deals.rows });
});

initDB().then(() => {
  server.listen(PORT, () => console.log(`http://localhost:${PORT}`));
});