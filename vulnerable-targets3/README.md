# vulnerable-targets3 — "AdminVibe" (intentionally vulnerable dashboard demo)

A third intentionally-vulnerable sample app for exercising the scanner, themed
as an admin dashboard. **Do not deploy.**

Seeded flaws: hardcoded API token + weak JWT secret, weak JWT config
(ignoreExpiration, ignoreNotBefore, predictable secret, no expiry), missing
route auth on /admin/users and /settings, SQL injection on /admin/users,
plaintext password change on /settings, IDOR on /profile/[id], and insecure
token storage in the dashboard.

Note: /profile/[id] intentionally *does* call an auth helper but still lacks an
ownership check — so the scanner should report only the IDOR risk there, not a
missing-auth finding. That contrast is deliberate.
