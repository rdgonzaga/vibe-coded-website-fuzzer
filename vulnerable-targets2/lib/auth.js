import jwt from "jsonwebtoken";
import { JWT_SECRET } from "./config";

// VULNERABLE: accepts unsigned tokens, ignores expiry, weak secret
export function verifyToken(token) {
  return jwt.verify(token, "secret", { algorithms: ["none"], ignoreExpiration: true });
}

// VULNERABLE: no expiresIn, so tokens never expire
export function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
}
