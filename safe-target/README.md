# safe-target — "Brew & Bytes" (clean control app)

An intentionally **secure / benign** sample app used as a control when testing
the scanner. It is a purely informational static site — no API routes, no
database, no credentials, no auth or token handling, and no dynamic SQL.

Scanning this directory should produce **zero findings** and an overall risk
level of **MINIMAL**. It exists to confirm the scanner does not raise false
positives on ordinary, well-behaved code.
