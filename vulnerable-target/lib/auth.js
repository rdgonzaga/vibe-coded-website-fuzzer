// lib/auth.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️

import jwt from "jsonwebtoken";

// VULNERABILITY: hardcoded, weak, guessable JWT secret committed to source.
// A real app must load a long random secret from an environment variable /
// secret manager, and rotate it.
export const JWT_SECRET = "supersecret";

export function signToken(user) {
  // VULNERABILITY: no expiry ("expiresIn") set, so stolen tokens are valid forever.
  // VULNERABILITY: payload includes is_admin, so anyone who can forge/edit a
  // token (e.g. because the secret is weak/hardcoded, as above) can grant
  // themselves admin rights.
  return jwt.sign(
    { id: user.id, email: user.email, is_admin: user.is_admin },
    JWT_SECRET
  );
}

export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}
