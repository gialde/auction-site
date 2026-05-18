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
    JOIN items i ON sel.id = i.creator_id
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
    const { auction_id, action, lot_id, creator_id, name, description, start_price } = req.body;

    // Вспомогательная функция для загрузки данных аукциона
    async function loadAuctionData(aid, msg) {
      const aucRes = await pool.query('SELECT * FROM auctions ORDER BY date');
      const selRes = await pool.query('SELECT id, full_name FROM sellers ORDER BY full_name');
      const lotsRes = await pool.query(`
        SELECT i.*, s.full_name AS seller_name,
               CASE WHEN sales.item_id IS NULL THEN FALSE ELSE TRUE END AS is_sold
        FROM items i
        JOIN sellers s ON i.creator_id = s.id
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
      const sid = parseInt(creator_id);
      
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
        INSERT INTO items (auction_id, lot_number, creator_id, name, description, start_price)
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
      JOIN sellers s ON i.creator_id = s.id
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
    WHERE d.buyer_id = $1
    ORDER BY d.created_at DESC
  `, [req.session.user.id]);
  res.render('profile', { profile: user.rows[0], myBids: myBids.rows, deals: deals.rows });
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
});