-- Таблица продавцов
CREATE TABLE IF NOT EXISTS sellers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(200) NOT NULL,
    passport VARCHAR(20) UNIQUE NOT NULL
);

-- Таблица покупателей
CREATE TABLE IF NOT EXISTS buyers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(200) NOT NULL,
    passport VARCHAR(20) UNIQUE NOT NULL
);

-- Таблица аукционов
CREATE TABLE IF NOT EXISTS auctions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    place VARCHAR(200) NOT NULL,
    date DATE NOT NULL,
    specifics VARCHAR(300)
);

-- Таблица предметов (лотов)
CREATE TABLE IF NOT EXISTS items (
    id SERIAL PRIMARY KEY,
    auction_id INT NOT NULL REFERENCES auctions(id) ON DELETE CASCADE,
    lot_number INT NOT NULL,
    seller_id INT NOT NULL REFERENCES sellers(id),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    start_price NUMERIC(12,2) NOT NULL CHECK(start_price > 0),
    UNIQUE(auction_id, lot_number)
);

-- Таблица продаж (фактов покупки)
CREATE TABLE IF NOT EXISTS sales (
    id SERIAL PRIMARY KEY,
    item_id INT UNIQUE NOT NULL REFERENCES items(id),
    buyer_id INT NOT NULL REFERENCES buyers(id),
    final_price NUMERIC(12,2) NOT NULL CHECK(final_price >= 0)
);