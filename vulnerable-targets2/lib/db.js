import Database from "better-sqlite3";

export const db = new Database("payvibe.db");

// VULNERABLE: email interpolated straight into the query string
export function getUser(email) {
  return db.prepare("SELECT * FROM users WHERE email = '" + email + "'").get();
}
