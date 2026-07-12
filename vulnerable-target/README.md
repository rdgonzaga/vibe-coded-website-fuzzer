# ⚠️ Vuln-Shop — Intentionally Vulnerable Next.js App

**This is a deliberately insecure training/testing target, modeled after
projects like OWASP Juice Shop / DVWA. It is NOT a real product. Do not
deploy it to the public internet, reuse this code in a real project, or
store real personal data in it.**

Run it only on `localhost`, in a sandbox/VM, or on an isolated network
you control, for practicing security testing, writing detection rules,
or teaching secure-coding-by-contrast.

## Stack

- Next.js (App Router) for both the frontend pages and the API routes
  (`app/api/**/route.js`), acting as the "backend"
- `better-sqlite3` for a local file-based database (`data/app.db`)
- `jsonwebtoken` for auth tokens

## Setup

```bash
npm install
npm run dev
```

Then visit `http://localhost:3000`.

Seeded demo accounts (see `lib/db.js`):

| email               | password    | role  |
|---------------------|-------------|-------|
| alice@example.com   | password123 | user  |
| bob@example.com     | letmein     | user  |
| admin@example.com   | admin123    | admin |

## Intentional vulnerabilities (by design)

Each is also called out with a `VULNERABILITY:` comment at the relevant
line in source.

1. **No rate limiting / account lockout on login**
   (`app/api/auth/login/route.js`) — unlimited login attempts per
   second, no CAPTCHA, no backoff. Useful for practicing/observing
   credential-stuffing or brute-force detection.
2. **Plaintext password storage & comparison** (`lib/db.js`,
   `app/api/auth/login/route.js`) — passwords are stored as-is and
   compared with `===` instead of hashed with bcrypt/argon2 and
   compared in constant time.
3. **User enumeration** (`app/api/auth/login/route.js`) — "no such
   user" and "wrong password" return different messages.
4. **Hardcoded, weak JWT secret** (`lib/auth.js`) — `"supersecret"`
   committed to source; anyone with the source (or who guesses it)
   can forge tokens, including `is_admin: true`.
5. **JWTs never expire** (`lib/auth.js`) — no `expiresIn`, so a leaked
   token is valid forever and can't be revoked.
6. **Token stored in `localStorage`** (`app/login/page.js`) — readable
   by any XSS on the page, instead of an httpOnly/Secure/SameSite
   cookie.
7. **Broken Object-Level Authorization / IDOR**
   (`app/api/profile/[id]/route.js`) — any logged-in user can read or
   overwrite *any other user's* profile by changing the `id` in the
   URL; the API never checks the id against the token's owner.
8. **Mass assignment** (`app/api/profile/[id]/route.js` `PUT`) — the
   request body's `is_admin` field is written straight to the DB, so a
   user can grant themselves admin.
9. **SQL injection** (`app/api/products/search/route.js`) — the search
   term is concatenated directly into a SQL string instead of using a
   parameterized query. Try `' OR '1'='1` or a `UNION SELECT` against
   the `users` table in the product search box.
10. **No input validation anywhere** (`app/api/auth/register/route.js`,
    etc.) — no email format check, no password strength rules, no
    length limits.
11. **Verbose error responses** (`app/api/auth/register/route.js`) —
    raw exception messages and stack traces are returned to the
    client.

## What a fixed version would do differently

- Hash passwords with bcrypt/argon2; never store plaintext
- Rate-limit and lock out repeated failed logins (e.g. per IP + per
  account, with exponential backoff or CAPTCHA)
- Sign JWTs with a long random secret from an env var / secret
  manager, with a short `expiresIn`, and store them in httpOnly,
  Secure, SameSite cookies
- Check `token.userId === resource.ownerId` (or a role check) on every
  read/write of user-owned resources
- Never accept privileged fields (`is_admin`, etc.) from client input
- Use parameterized queries (`db.prepare("... WHERE name LIKE ?").all(...)`)
  everywhere
- Validate and sanitize all input server-side
- Return generic error messages to clients; log details server-side only
