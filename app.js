const express = require('express');
require('dotenv').config();
const { pool, initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Настройка шаблонизатора
app.set('view engine', 'ejs');
app.set('views', './views');

// Статические файлы (CSS, клиентский JS, картинки)
app.use(express.static('public'));

// Для обработки данных формы (POST)
app.use(express.urlencoded({ extended: true }));

// ---------- Главная ----------
app.get('/', (req, res) => {
  res.render('index');
});

// ---------- Запрос 1 ----------
app.route('/query1')
  .get((req, res) => {
    res.render('query1', { items: undefined }); // без результатов
  })
  .post(async (req, res) => {
    const { date, auction_id } = req.body;
    try {
      const result = await pool.query(`
        SELECT i.id, i.lot_number, i.name, i.start_price, s.full_name AS seller
        FROM items i
        JOIN auctions a ON i.auction_id = a.id
        JOIN sellers s ON i.seller_id = s.id
        WHERE a.date = $1 AND a.id = $2
      `, [date, auction_id]);
      
      res.render('query1', { items: result.rows });
    } catch (err) {
      console.error(err);
      res.status(500).send('Ошибка базы данных');
    }
  });

// (остальные запросы добавим позже)

// ---------- Старт ----------
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
  });
});