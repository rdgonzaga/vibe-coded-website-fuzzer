import jwt from "jsonwebtoken";

// VULNERABLE: expiry and not-before checks both disabled
export function verify(token) {
  return jwt.verify(token, process.env.SECRET, {
    ignoreExpiration: true,
    ignoreNotBefore: true,
  });
}

// VULNERABLE: predictable secret and no expiresIn
export function issue(payload) {
  return jwt.sign(payload, "supersecret", { algorithm: "HS256" });
}
