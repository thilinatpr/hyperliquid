// file: db.js
const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(path.resolve(__dirname, '../data/data.db'));

// Drop old tables if exist (optional, for migration)
//db.prepare('DROP TABLE IF EXISTS configs').run();
//db.prepare('DROP TABLE IF EXISTS users').run();

// Create new configs table keyed by ethAddress
db.prepare(`
  CREATE TABLE IF NOT EXISTS configs (
    ethAddress TEXT PRIMARY KEY,
    privateKey TEXT NOT NULL,
    walletAddress TEXT NOT NULL,
    webhookUrl TEXT NOT NULL,
    tokens TEXT,
    minSize REAL,
    is_active INTEGER DEFAULT 0
  )
`).run();

module.exports = db;