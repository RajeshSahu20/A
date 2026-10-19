const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const databaseFolder = path.join(__dirname, "database");

if (!fs.existsSync(databaseFolder)) {
    fs.mkdirSync(databaseFolder, { recursive: true });
}

const dbPath = path.join(databaseFolder, "photovault.db");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(
    "CREATE TABLE IF NOT EXISTS students (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " +
    "email TEXT NOT NULL UNIQUE COLLATE NOCASE, " +
    "pin_hash TEXT NOT NULL, " +
    "status TEXT NOT NULL DEFAULT 'active' " +
    "CHECK(status IN ('active', 'inactive')), " +
    "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP" +
    ")"
);

db.exec(
    "CREATE TABLE IF NOT EXISTS admins (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "username TEXT NOT NULL UNIQUE COLLATE NOCASE, " +
    "password_hash TEXT NOT NULL, " +
    "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP" +
    ")"
);

console.log("PhotoVault database created successfully!");

module.exports = db;

