# vulnerable-targets2 — "PayVibe" (intentionally vulnerable fintech demo)

A second intentionally-vulnerable sample app used to exercise the scanner.
Themed as a payments/account backend. **Do not deploy.** Every file here
contains deliberate security flaws for testing only.

Seeded flaws: hardcoded secrets + API token, weak JWT config (alg none,
ignoreExpiration, predictable secret, no expiry), plaintext password compare,
missing route auth on /account and /payment, IDOR on /account/[id], SQL
injection via string concatenation, and insecure token storage in the browser.
