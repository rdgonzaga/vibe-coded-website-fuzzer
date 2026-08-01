# VibeCheck

## Description
This tool is a hybrid security scanning and fuzzing suite specifically engineered to audit "vibe-coded" applications like websites and APIs that are rapidly generated using Large Language Models (LLMs) like ChatGPT or Claude. While AI-assisted development produces functional code with zero syntax errors, it notoriously introduces massive architectural blind spots because AI optimizes for immediate functionality rather than defensive security engineering.

## Purpose
The core purpose of this tool is to provide developers and security teams with an automated way to test whether AI-generated codebases have proper security controls and middleware implemented before deployment.

## Features
* **Hardcoded Secrets Detection:** Scans local code repositories using regex matching to find plaintext passwords, API keys, tokens, and placeholders committed by AI models.
* **Missing Endpoint Authorization Auditor:** Parses local backend routing structures to find sensitive API paths missing explicit authentication wrappers or decorators.
* **Weak JWT Validation Checker:** Identifies unsafe configurations in JSON Web Token validation engines (e.g., missing signature verification or generic placeholder secret keys).
* **Automated IDOR-by-Default Tester:** Dynamically fires cross-token requests at local parameters to catch unvalidated numeric endpoint object references.
* **Rate-Limiting & Verbose Error Fuzzer:** Stress-tests local entry forms with concurrent asynchronous payloads to catch missing request throttling and captures 500 Internal Server Errors for leaked server file paths or stack traces.

## System Requirements
* Python 3.8+
* `requests`, `PyJWT` (dynamic fuzzing) and `rich` (pretty terminal report). For more, see `requirements.txt`. The static scan runs on the standard library alone; the dynamic phase and pretty output degrade gracefully if their optional deps are missing.

## Installation
1. Clone the repository.
2. (Optional but recommended) create a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`

## Usage
The whole suite runs from a single entry point, `main.py`.

```bash
# Static scan only (default) — point it at a project directory
python main.py --dir ./my-vibecoded-app

# Write the final risk report to a file (txt, json, or a styled html page)
python main.py --dir ./my-vibecoded-app --format json --output report.json
python main.py --dir ./my-vibecoded-app --format html --output report.html

# Also run the live dynamic fuzzer against a locally running instance
python main.py --dir ./my-vibecoded-app --dynamic --url http://localhost:3000
```

Run `python main.py --help` for the full list of options (login credentials,
endpoint overrides, request count, etc.). The tool prints a color-coded
vulnerability risk report to the terminal and, with `--output`, writes the same
report to disk as human-readable TXT, machine-readable JSON, or a self-contained,
styled HTML page (open `report.html` in any browser, no internet needed). Its
exit code is `1` when any HIGH/CRITICAL finding is present, so it drops straight
into CI.

Every finding is scored with the **CVSS v3.1** Base metric formula (implemented
per the FIRST specification), so each report shows a numeric 0.0–10.0 score, the
official severity band (None/Low/Medium/High/Critical), and the full vector
string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). The overall risk
level is driven by the highest CVSS score present.

## Testing Environment
* **Controlled Lab Setup:** This tool is strictly tested within a local, simulated infrastructure environment.
* **Target Applications:** Three intentionally-vulnerable sample apps ship with the repo for testing — `vulnerable-target` (e-commerce), `vulnerable-targets2` (fintech/payments), and `vulnerable-targets3` (admin dashboard) — each seeded with a different mix of flaws and hosted on loopback addresses (localhost / 127.0.0.1).
* **Isolation:** The application boundaries are isolated completely from public web servers, external cloud services, or production institutional systems.

## Sample Output
```text
--- Vibe-Coded Website Fuzzer ---

[*] Static scan: 13 relevant file(s) found in '.\vulnerable-target\'
[*] Static scan complete: 9 finding(s)
[*] Dynamic scan target: http://localhost:3000
[*] logging in as alice@example.com
[*] sending 100 requests to /api/auth/login
[*] trying token swap on /api/profile/{id} with id=2
[*] fuzzing jwt on /api/profile/1
[*] checking security headers on /
[*] Dynamic scan complete: 47 finding(s)

╭─────────────────────────────────────────────────────────────────────────────────────────────── Vulnerability Risk Report ────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Directory: .\vulnerable-target\                                                                                                                                                                                          │
│ Scans run: static, dynamic                                                                                                                                                                                               │
│ Target URL: http://localhost:3000                                                                                                                                                                                        │
│ Scoring: CVSS v3.1                                                                                                                                                                                                       │
│                                                                                                                                                                                                                          │
│ Overall risk: CRITICAL   (highest CVSS 9.8)                                                                                                                                                                              │
│ Total findings: 56   CRITICAL 2  HIGH 4  MEDIUM 49  LOW 1                                                                                                                                                                │
│                                                                                                                                                                                                                          │
│ Summary: 56 finding(s) across 12 categories; highest severity CRITICAL - Potential SQL Injection (Direct Concatenation) (CVSS 9.8). Static + dynamic scan.                                                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────────────────────────────────────────────── Module Coverage ─────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                                                                                                          │
│   Phase     Module                    Status                                                                                                                                                                             │
│  ────────────────────────────────────────────────                                                                                                                                                                        │
│   static    Secrets scan              1 flag(s)                                                                                                                                                                          │
│   static    Endpoint auth             1 flag(s)                                                                                                                                                                          │
│   static    JWT config                1 flag(s)                                                                                                                                                                          │
│   static    Injection sink            1 flag(s)                                                                                                                                                                          │
│   static    Plaintext passwords       2 flag(s)                                                                                                                                                                          │
│   static    Insecure config           2 flag(s)                                                                                                                                                                          │
│   static    Stub / placeholder code   1 flag(s)                                                                                                                                                                          │
│   dynamic   IDOR swap                 1 flag(s)                                                                                                                                                                          │
│   dynamic   Rate limit                1 flag(s)                                                                                                                                                                          │
│   dynamic   JWT bypass                1 flag(s)                                                                                                                                                                          │
│   dynamic   Info leak                 40 flag(s)                                                                                                                                                                         │
│   dynamic   Security headers          4 flag(s)                                                                                                                                                                          │
│                                                                                                                                                                                                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────────────────────────────────────────────────────────────── Weaknesses ───────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ - SQL injection via string concatenation: 1 finding(s), worst CVSS 9.8 (CRITICAL).                                                                                                                                       │
│ - Live JWT authentication bypass: 1 finding(s), worst CVSS 9.1 (CRITICAL).                                                                                                                                               │
│ - Live IDOR (object-level authorization): 1 finding(s), worst CVSS 8.1 (HIGH).                                                                                                                                           │
│ - Hardcoded secrets & exposed API tokens: 1 finding(s), worst CVSS 7.5 (HIGH).                                                                                                                                           │
│ - Plaintext password handling: 2 finding(s), worst CVSS 7.5 (HIGH).                                                                                                                                                      │
│ - Missing route authentication / IDOR (static): 1 finding(s), worst CVSS 6.5 (MEDIUM).                                                                                                                                   │
│ - Insecure client-side token storage: 2 finding(s), worst CVSS 6.1 (MEDIUM).                                                                                                                                             │
│ - Missing security response headers: 4 finding(s), worst CVSS 6.1 (MEDIUM).                                                                                                                                              │
│ - Weak JWT configuration: 1 finding(s), worst CVSS 5.3 (MEDIUM).                                                                                                                                                         │
│ - Missing rate limiting: 1 finding(s), worst CVSS 5.3 (MEDIUM).                                                                                                                                                          │
│ - Verbose error / information leak: 40 finding(s), worst CVSS 5.3 (MEDIUM).                                                                                                                                              │
│ - Placeholder / stub code left in source: 1 finding(s), worst CVSS 3.1 (LOW).                                                                                                                                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

                                                                                                    Findings by Category                                                                                                    
                                                                                                                                                                                                                            
   #   CVSS   Severity   Type / count                                         Src       Conf     Locations                             Fix                                                                                  
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 
   1    9.8   CRITICAL   Potential SQL Injection (Direct Concatenation)       static    medium   app/api/products/search/route.js:23   Use parameterized queries / prepared statements instead of string interpolation.     
                                                                                                                                                                                                                            
   2    9.1   CRITICAL   JWT Authentication Bypass (Live)                     dynamic   high     -                                     Verify token signatures with a fixed algorithm and a strong server-side secret.      
                                                                                                                                                                                                                            
   3    8.1   HIGH       IDOR Confirmed (Live)                                dynamic   high     -                                     Enforce per-object ownership checks server-side before returning data.               
                                                                                                                                                                                                                            
   4    7.5   HIGH       Predictable Variable Name                            static    medium   lib/auth.js:10                        Move the secret out of source into an environment variable or vault; never commit    
                                                                                                                                       credentials.                                                                         
                                                                                                                                                                                                                            
   5    7.5   HIGH       Unsafe password comparison (Plaintext)  x2           static    medium   app/api/auth/login/route.js:33        Hash passwords with bcrypt/argon2 and compare hashes; never compare plaintext.         
                                                                                                 app/register/page.js:47                                                                                                    
                                                                                                                                                                                                                            
   6    6.5   MEDIUM     Broken Object-Level (IDOR) Risk                      static    medium   app/api/profile//route.js:1           Verify the requester owns the requested id before returning the record.              
                                                                                                                                                                                                                            
   7    6.1   MEDIUM     Insecure token storage (XSS Risk)  x2                static    high     app/login/page.js:41                  Store session tokens in httpOnly cookies instead of localStorage/sessionStorage.     
                                                                                                 app/register/page.js:32                                                                                                    
                                                                                                                                                                                                                            
   8    6.1   MEDIUM     Missing security response headers (Live)  x4         dynamic   high     /                                     Send CSP, X-Frame-Options, X-Content-Type-Options and HSTS headers on responses.     
                                                                                                                                                                                                                            
   9    5.3   MEDIUM     Insecure JWT: Token created without expiresIn flag   static    medium   lib/auth.js:17                        Sign tokens with an explicit expiresIn so sessions cannot live forever.              
                                                                                                                                                                                                                            
  10    5.3   MEDIUM     Missing Rate Limiting                                dynamic   high     -                                     Add rate limiting / lockout on the endpoint to blunt brute-force and abuse.          
                                                                                                                                                                                                                            
  11    5.3   MEDIUM     Verbose Error / Info Leak  x40                       dynamic   high     /api/auth/register (x40)             Return generic error messages and log details server-side only.                      
                                                                                                                                                                                                                            
  12    3.1   LOW        Placeholder / stub code left in source               static    low      app/products/page.js:36               Replace the TODO/stub with a real implementation before shipping to production.      
```

## Limitations
* **Framework Heuristics:** The static scanner relies on AST/regex pattern matching tailored primarily for JavaScript/Node.js (Next.js, Express) and Python (Flask, FastAPI). Non-standard routing architectures or heavily obfuscated source code may lead to false positives or missed findings.
* **REST/HTTP Scope:** Dynamic fuzzing targets standard HTTP REST API endpoints, JSON authentication, JWT signatures, and numeric ID parameters. It does not perform full client-side browser rendering, DOM-based XSS execution (e.g., via Playwright/Puppeteer), or binary memory corruption testing.
* **Sandbox Requirement:** Dynamic tests require the target application to be actively running on `localhost` or a designated test server.

## Future Improvements
* **AI-Assisted Remediation:** Automated generation of secure code patches and pull request diffs for detected vulnerabilities.
* **OpenAPI / Swagger Auto-Parsing:** Automatic endpoint discovery and payload schema generation directly from `openapi.json` or Postman collection files.
* **Headless Browser Integration:** Playwright / Puppeteer integration for dynamic Client-Side DOM XSS and Single Page Application (SPA) state fuzzing.
* **Expanded Multi-Language SAST:** Native static analysis rule sets for Go, Java (Spring Boot), and PHP.

## Ethical Disclaimer
This tool was developed for educational purposes only. It must only be used in authorized and controlled testing environments. Unauthorized testing against real systems, public websites, or third-party services is strictly prohibited.

## Group Members and Roles

**NSSECU02 S04 Group 9:**
* **Kristopher Lance Chiu** - Dynamic Application Security Testing (DAST) Developer
* **Andrea Gayle Garcia** - Static Application Security Testing (SAST) Developer
* **Rainer Gonzaga** - Dynamic Application Security Testing (DAST) Developer
* **Sky Hannah Parado** - Vulnerable Target Application Developer
* **Jeroen Ralph Tenorio** - Static Application Security Testing (SAST) Developer

## Original Contribution
* **Tailored for AI ("Vibe-Coded") Vulnerability Patterns:** Specifically engineered to detect architectural blind spots common in LLM-assisted codebases (e.g., fallback secrets like `"supersecret"`, missing route authorization wrappers, unvalidated sequential numeric IDs).
* **Native Standard-Compliant CVSS v3.1 Engine:** Built-in formula implementation adhering to the FIRST CVSS v3.1 specification without relying on external scoring packages.
* **Unified SAST + DAST Pipeline:** Bridges static code analysis (extracting routes & auth patterns) directly with live HTTP dynamic fuzzing.
* **Zero-Dependency Core & Graceful Degradation:** The static scanner operates using Python's standard library alone, while optional dependencies (`rich`, `requests`, `PyJWT`) seamlessly unlock styled terminal output, live HTTP fuzzing, and interactive HTML reports.
