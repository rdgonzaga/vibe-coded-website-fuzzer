// lib/db.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
// This file sets up a tiny SQLite database and seeds it with demo users
// and products so the vulnerable endpoints have something to attack.

import Database from "better-sqlite3";
import path from "path";

const dbPath = path.join(process.cwd(), "data", "app.db");
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    -- VULNERABILITY: passwords stored in PLAINTEXT.
    -- A real app must hash with bcrypt/argon2 and never store/log raw passwords.
    password TEXT NOT NULL,
    name TEXT,
    address TEXT,
    is_admin INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL
  );
`);

const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
if (userCount === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (email, password, name, address, is_admin) VALUES (?, ?, ?, ?, ?)"
  );
  insertUser.run("alice@example.com", "password123", "Alice Smith", "12 Main St", 0);
  insertUser.run("bob@example.com", "letmein", "Bob Jones", "88 Oak Ave", 0);
  insertUser.run("admin@example.com", "admin123", "Site Admin", "HQ", 1);
}

const productCount = db.prepare("SELECT COUNT(*) AS c FROM products").get().c;
if (productCount === 0) {
  const insertProduct = db.prepare(
    "INSERT INTO products (name, description, price) VALUES (?, ?, ?)"
  );
  insertProduct.run("Wireless Mouse", "Ergonomic 2.4GHz mouse", 19.99);
  insertProduct.run("Mechanical Keyboard", "Hot-swappable, RGB", 89.99);
  insertProduct.run("USB-C Hub", "7-in-1 hub with HDMI", 34.5);
  insertProduct.run("Laptop Stand", "Aluminum, adjustable height", 24.0);
}

export default db;
