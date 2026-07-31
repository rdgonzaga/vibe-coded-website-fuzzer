"""
Vibe-Coded Website Fuzzer - unified entry point.

Combines the two phases of the suite into a single tool:

  * Phase 2 (SAST) - a static scanner that walks a project directory and
    greps the source for hardcoded secrets, weak JWT config, missing route
    auth, plaintext password checks, insecure token storage and SQL injection.

  * Phase 3 (DAST) - a dynamic fuzzer that drives a locally running instance
    of the same app to confirm IDOR, JWT bypass, missing rate limiting and
    verbose error leaks.

Everything funnels into one normalized list of findings and a final
vulnerability risk report that can be printed and/or written to disk as
either a human-readable TXT file or machine-readable JSON.

Example:
    python main.py --dir ./vulnerable-target
    python main.py --dir ./vulnerable-target --format json --output report.json
    python main.py --dir ./vulnerable-target --dynamic --url http://localhost:3000
"""

import argparse
import json
import os
import re
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

try:
    import jwt
    warnings.filterwarnings("ignore", category=jwt.InsecureKeyLengthWarning)
except ImportError:
    jwt = None

try:
    import requests
except ImportError:
    requests = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _console = Console()
    RICH = True
except ImportError:
    _console = None
    RICH = False


DEFAULT_TIMEOUT = 5
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "tool", "scanner_config.json")

SEVERITY_MAP = {
    "Exposed API Token (sk- format)": "CRITICAL",
    "Predictable Variable Name": "HIGH",
    "Insecure JWT: ignoreExpiration = true": "HIGH",
    "Insecure JWT: ignoreNotBefore = true": "MEDIUM",
    "Insecure JWT: 'none' algorithm accepted": "CRITICAL",
    "Insecure JWT: predictable secret key is hardcoded": "CRITICAL",
    "Insecure JWT: Token created without expiresIn flag": "MEDIUM",
    "Missing Route Authentication for Sensitive Endpoints": "HIGH",
    "Broken Object-Level (IDOR) Risk": "HIGH",
    "Unsafe password comparison (Plaintext)": "HIGH",
    "Insecure token storage (XSS Risk)": "MEDIUM",
    "Potential SQL Injection (Direct Concatenation)": "CRITICAL",
    "Missing Rate Limiting": "MEDIUM",
    "IDOR Confirmed (Live)": "CRITICAL",
    "JWT Authentication Bypass (Live)": "CRITICAL",
    "Verbose Error / Info Leak": "MEDIUM",
}

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


def severity_of(finding_type: str) -> str:
    return SEVERITY_MAP.get(finding_type, "MEDIUM")


def make_finding(scanner, category, ftype, detail, file=None, line=None):
    """Normalize every detector's output into one common finding shape."""
    return {
        "scanner": scanner,
        "category": category,
        "type": ftype,
        "severity": severity_of(ftype),
        "file": file,
        "line": line,
        "detail": detail,
    }


def load_config(config_path=DEFAULT_CONFIG_PATH):
    """Read the JSON config for target extensions and ignored directories."""
    try:
        with open(config_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {
            "target_extensions": [".js", ".ts", ".tsx", ".jsx", ".env", ".env.local"],
            "ignore_dirs": ["node_modules", ".git", ".next", "dist", "build"],
        }


def get_files_to_scan(target_dir, config):
    """Walk target_dir and return files matching the configured extensions."""
    target_extensions = config.get("target_extensions", [])
    ignore_dirs = config.get("ignore_dirs", [])

    files_to_scan = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if any(file.endswith(ext) for ext in target_extensions):
                files_to_scan.append(os.path.join(root, file))
    return files_to_scan


def scan_for_secrets(file_path):
    """Regex the file for hardcoded secrets / exposed API tokens."""
    context_regex = re.compile(
        r'(?i)(password|secret|api_key|apikey|token)\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
    )
    format_regex = re.compile(r"sk-[a-zA-Z0-9]{32}")

    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                if context_regex.search(line):
                    findings.append(make_finding(
                        "static", "Hardcoded Secret", "Predictable Variable Name",
                        line.strip()[:100], file=file_path, line=line_number,
                    ))
                if format_regex.search(line):
                    findings.append(make_finding(
                        "static", "Hardcoded Secret", "Exposed API Token (sk- format)",
                        line.strip()[:100], file=file_path, line=line_number,
                    ))
    except Exception:
        pass
    return findings


def scan_jwt_config(file_path):
    """Check the file for weak JWT configurations."""
    ignore_exp_regex = re.compile(r"(?i)ignoreExpiration\s*:\s*true")
    ignore_nb4_regex = re.compile(r"(?i)ignoreNotBefore\s*:\s*true")
    alg_none_regex = re.compile(r'(?i)algorithms\s*:\s*\[?[\'"]none[\'"]\]?')
    weak_placeholder_regex = re.compile(
        r'jwt\.(verify|sign)\s*\([^,]+,\s*[\'"](supersecret|secret|changeme|123456|default)[\'"]'
    )

    checks = [
        (ignore_exp_regex, "Insecure JWT: ignoreExpiration = true"),
        (ignore_nb4_regex, "Insecure JWT: ignoreNotBefore = true"),
        (alg_none_regex, "Insecure JWT: 'none' algorithm accepted"),
        (weak_placeholder_regex, "Insecure JWT: predictable secret key is hardcoded"),
    ]

    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                for regex, ftype in checks:
                    if regex.search(line):
                        findings.append(make_finding(
                            "static", "Weak JWT Config", ftype,
                            line.strip()[:100], file=file_path, line=line_number,
                        ))
                if "jwt.sign" in line and "expiresIn" not in line:
                    findings.append(make_finding(
                        "static", "Weak JWT Config",
                        "Insecure JWT: Token created without expiresIn flag",
                        line.strip()[:100], file=file_path, line=line_number,
                    ))
    except Exception:
        pass
    return findings


def scan_route_logic(file_path):
    """Flag sensitive API routes missing auth middleware or ownership checks."""
    if "api" not in file_path.lower():
        return []

    sensitive_keywords = ["user", "admin", "profile", "account", "settings", "payment", "billing"]
    auth_keywords = ["middleware", "isauthenticated", "requireauth",
                     "verifytoken", "getserversession", "jwt.verify"]
    ownership_keywords = ["!== decoded.id", "!= user.id", "!== req.user.id",
                          "token.id ===", "user.id ==="]

    if not any(word in file_path.lower() for word in sensitive_keywords):
        return []

    findings = []
    has_auth = False
    has_owner_check = False
    is_parameterized = "[id]" in file_path.lower()

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read().lower()
            has_auth = any(word in content for word in auth_keywords)
            has_owner_check = any(word in content for word in ownership_keywords)

        if not has_auth:
            findings.append(make_finding(
                "static", "Missing Authorization",
                "Missing Route Authentication for Sensitive Endpoints",
                f"File '{os.path.basename(file_path)}' lacks recognized auth checks.",
                file=file_path, line=1,
            ))
        if is_parameterized and not has_owner_check:
            findings.append(make_finding(
                "static", "Missing Authorization", "Broken Object-Level (IDOR) Risk",
                f"File '{os.path.basename(file_path)}' takes [id] parameter but lacks explicit ownership validation.",
                file=file_path, line=1,
            ))
    except Exception:
        pass
    return findings


def scan_plaintext_passwords(file_path):
    """Flag password comparisons done with == / === instead of a hash compare."""
    if file_path.endswith((".json", ".env", ".md")):
        return []

    password_keywords = ["password", "passwd", "pwd"]
    crypto_keywords = ["bcrypt", "argon2", "scrypt", "hash", "compare"]
    equality_regex = re.compile(r"===|==|!==|!=")

    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                lower_line = line.lower()
                if equality_regex.search(line):
                    if any(pwd in lower_line for pwd in password_keywords):
                        if not any(crypto in lower_line for crypto in crypto_keywords):
                            findings.append(make_finding(
                                "static", "Plaintext Password",
                                "Unsafe password comparison (Plaintext)",
                                line.strip()[:100], file=file_path, line=line_number,
                            ))
    except Exception:
        pass
    return findings


def scan_insecure_storage(file_path):
    """Flag auth tokens being written to localStorage / sessionStorage."""
    if not file_path.endswith((".js", ".jsx", ".ts", ".tsx")):
        return []

    storage_keywords = ["localstorage.setitem", "sessionstorage.setitem"]
    auth_keywords = ["token", "jwt", "auth", "session"]

    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                lower_line = line.lower()
                if any(s in lower_line for s in storage_keywords):
                    if any(a in lower_line for a in auth_keywords):
                        findings.append(make_finding(
                            "static", "Insecure Storage", "Insecure token storage (XSS Risk)",
                            line.strip()[:100], file=file_path, line=line_number,
                        ))
    except Exception:
        pass
    return findings


def scan_sql_injection(file_path):
    """Flag SQL queries built with direct string concatenation / interpolation."""
    if not file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
        return []

    sql_keywords = ["select *", "select ", "insert into ", "update ", "delete from "]

    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, 1):
                lower_line = line.lower()
                if any(sql in lower_line for sql in sql_keywords):
                    if "${" in line or "+" in line:
                        if "?" not in line and "$1" not in line:
                            findings.append(make_finding(
                                "static", "SQL Injection",
                                "Potential SQL Injection (Direct Concatenation)",
                                line.strip()[:100], file=file_path, line=line_number,
                            ))
    except Exception:
        pass
    return findings


STATIC_DETECTORS = [
    scan_for_secrets,
    scan_jwt_config,
    scan_route_logic,
    scan_plaintext_passwords,
    scan_insecure_storage,
    scan_sql_injection,
]


def run_static_scan(target_dir, config, log=print):
    """Run every static detector over the directory; return a flat findings list."""
    files = get_files_to_scan(target_dir, config)
    log(f"[*] Static scan: {len(files)} relevant file(s) found in '{target_dir}'")

    findings = []
    for file_path in files:
        for detector in STATIC_DETECTORS:
            findings.extend(detector(file_path))
    log(f"[*] Static scan complete: {len(findings)} finding(s)")
    return findings


class DynamicFuzzer:

    _TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "authToken")
    _DYNAMIC_ROUTE = re.compile(r"\[(?:\.\.\.)?[^\]]+\]|\{[^}]+\}|(?<=/):[^/]+")

    _LEAK_PATTERNS = {
        "Windows file path": re.compile(r"[A-Za-z]:\\+(?:[^\\\s\"']+\\+)*[^\\\s\"']+"),
        "Unix file path": re.compile(r"/(?:usr|home|etc|var|root)/[^\s\"']+"),
        "node_modules path": re.compile(r"[\w./\\-]*node_modules[/\\]+[^\s\"']+"),
        "JS stack trace frame": re.compile(r"at\s+[\w.$<>]+\s*\(?[^\s)\"']+:\d+:\d+\)?"),
        "Database error": re.compile(
            r"(?i)(SQLITE_[A-Z]+|SqliteError|SqlException|psycopg2\.\w+|"
            r"pymysql\.\w+|MongoServerError|syntax error at or near|ORA-\d{5})"
        ),
        "Python traceback frame": re.compile(r'File "[^"]+", line \d+'),
    }

    def __init__(self, base_url="http://localhost:3000", log=print):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.log = log

    def login(self, email, password, endpoint="/api/auth/login",
              email_field="email", password_field="password"):
        """Log in and return the token, or None on failure."""
        url = f"{self.base_url}{endpoint}"
        self.log(f"[*] logging in as {email}")
        try:
            response = self.session.post(
                url, json={email_field: email, password_field: password},
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            self.log(f"[!] login request failed: {e}")
            return None

        if response.status_code != 200:
            self.log(f"[!] login failed ({response.status_code}): {response.text[:200]}")
            return None
        try:
            body = response.json()
        except ValueError:
            self.log("[!] login succeeded but response wasn't JSON (cookie-based auth?)")
            return None

        for key in self._TOKEN_KEYS:
            if body.get(key):
                return body[key]
        self.log(f"[!] login succeeded but no recognizable token field ({', '.join(self._TOKEN_KEYS)})")
        return None

    def map_endpoints_to_localhost(self, endpoints):
        """Turn discovered route patterns into concrete localhost URLs."""
        mapped = []
        for endpoint in endpoints:
            endpoint = endpoint.strip()
            if not endpoint:
                continue
            endpoint = self._DYNAMIC_ROUTE.sub("1", endpoint)
            if not endpoint.startswith("/"):
                endpoint = f"/{endpoint}"
            url = f"{self.base_url}{endpoint}"
            if url not in mapped:
                mapped.append(url)
        return mapped

    def discover_nextjs_endpoints(self, target_dir):
        """Extract API route paths from Next.js app/api and pages/api folders."""
        endpoints = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [name for name in dirs if name not in {".git", ".next", "node_modules"}]
            for filename in files:
                relative_path = os.path.relpath(os.path.join(root, filename), target_dir)
                relative_path = relative_path.replace("\\", "/")

                app_route = re.fullmatch(r"(?:src/)?app/(api/.+)/route\.(?:js|ts|jsx|tsx)", relative_path)
                pages_route = re.fullmatch(r"(?:src/)?pages/(api/.+)\.(?:js|ts|jsx|tsx)", relative_path)

                if app_route:
                    endpoint = f"/{app_route.group(1)}"
                elif pages_route:
                    endpoint = f"/{pages_route.group(1)}"
                    endpoint = re.sub(r"/index$", "", endpoint)
                else:
                    continue
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        return endpoints

    def test_rate_limiting(self, endpoint, request_count=100,
                           email="test@example.com", password="wrong-password-on-purpose",
                           email_field="email", password_field="password"):
        """Fire concurrent requests and count HTTP 429s; also grab any 5xx leaks."""
        url = f"{self.base_url}{endpoint}"
        self.log(f"[*] sending {request_count} requests to {endpoint}")
        payload = {email_field: email, password_field: password}

        def fire_one(_):
            try:
                response = self.session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
                return response.status_code, response.text
            except requests.RequestException as e:
                self.log(f"[!] request failed: {e}")
                return None, None

        with ThreadPoolExecutor(max_workers=20) as pool:
            responses = list(pool.map(fire_one, range(request_count)))

        status_codes = [code for code, _ in responses if code is not None]
        requests_sent = len(status_codes)
        rate_limited_count = sum(1 for code in status_codes if code == 429)

        leaks = []
        seen = set()
        for code, text in responses:
            if code is None or code < 500:
                continue
            for leak in self.check_error_leaks(code, text):
                key = (leak["type"], leak["match"])
                if key not in seen:
                    seen.add(key)
                    leaks.append(leak)

        return {
            "endpoint": endpoint,
            "requests_sent": requests_sent,
            "rate_limited": rate_limited_count > 0,
            "rate_limited_count": rate_limited_count,
            "leaks_found": leaks,
            "notes": (
                f"got {rate_limited_count} HTTP 429 response(s) out of {requests_sent}"
                if rate_limited_count > 0
                else "no 429s seen - endpoint does not appear to be rate-limited"
            ),
        }

    def test_idor_token_swap(self, endpoint_pattern, session_token, target_id):
        """Use our own token to fetch another user's object; a 2xx is an IDOR."""
        self.log(f"[*] trying token swap on {endpoint_pattern} with id={target_id}")
        results = {
            "endpoint_pattern": endpoint_pattern,
            "target_id": target_id,
            "idor_detected": False,
            "status_code": None,
            "notes": "",
        }

        if not self._DYNAMIC_ROUTE.search(endpoint_pattern):
            results["notes"] = "endpoint pattern has no dynamic ID placeholder"
            return results

        try:
            payload = jwt.decode(session_token, options={"verify_signature": False})
            logged_in_id = payload.get("id") or payload.get("userId") or payload.get("sub")
        except jwt.PyJWTError:
            logged_in_id = None

        if logged_in_id is not None and str(logged_in_id) == str(target_id):
            results["notes"] = "target ID belongs to the logged-in user; choose a different ID"
            return results

        endpoint = self._DYNAMIC_ROUTE.sub(str(target_id), endpoint_pattern)
        url = endpoint if endpoint.startswith(("http://", "https://")) else f"{self.base_url}{endpoint}"

        try:
            response = self.session.get(
                url, headers={"Authorization": f"Bearer {session_token}"}, timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            results["notes"] = f"request failed: {e}"
            return results

        results["status_code"] = response.status_code
        results["idor_detected"] = 200 <= response.status_code < 300
        results["notes"] = (
            "another user's endpoint accepted the logged-in user's token"
            if results["idor_detected"]
            else "cross-user request was rejected or the target record was not found"
        )
        return results

    def fuzz_jwt_auth(self, endpoint, original_token):
        """Try alg=none and weak-secret re-signing to bypass JWT auth."""
        self.log(f"[*] fuzzing jwt on {endpoint}")
        results = {
            "endpoint": endpoint,
            "bypass_successful": False,
            "bypass_method": None,
            "attempts": [],
            "notes": "",
        }

        try:
            payload = jwt.decode(original_token, options={"verify_signature": False})
        except jwt.PyJWTError as e:
            results["notes"] = f"token is not a valid JWT: {e}"
            return results

        url = endpoint if endpoint.startswith(("http://", "https://")) else f"{self.base_url}{endpoint}"

        def try_token(name, token):
            try:
                response = self.session.get(
                    url, headers={"Authorization": f"Bearer {token}"}, timeout=DEFAULT_TIMEOUT,
                )
                accepted = 200 <= response.status_code < 300
                results["attempts"].append(
                    {"method": name, "status_code": response.status_code, "accepted": accepted}
                )
                return accepted
            except requests.RequestException as e:
                results["attempts"].append({"method": name, "error": str(e), "accepted": False})
                return False

        token_parts = original_token.split(".")
        if len(token_parts) != 3:
            results["notes"] = "token is not a three-part JWT"
            return results

        none_header = jwt.utils.base64url_encode(
            json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
        ).decode()
        none_token = f"{none_header}.{token_parts[1]}."

        attempts = [("alg=none", none_token)]
        for secret in ("secret", "supersecret", "password", "changeme", "jwtsecret"):
            attempts.append((f"weak secret: {secret}", jwt.encode(payload, secret, algorithm="HS256")))

        for method, token in attempts:
            if try_token(method, token):
                results["bypass_successful"] = True
                results["bypass_method"] = method
                results["notes"] = f"endpoint accepted a token forged with {method}"
                break

        if not results["bypass_successful"]:
            results["notes"] = "none of the forged JWTs were accepted"
        return results

    def check_error_leaks(self, response_code, response_content):
        """Scan an error response for leaked paths, stack traces or DB errors."""
        leaks = []
        if response_code < 400:
            return leaks
        seen = set()
        for leak_type, pattern in self._LEAK_PATTERNS.items():
            for match in pattern.findall(response_content):
                key = (leak_type, match)
                if key in seen:
                    continue
                seen.add(key)
                leaks.append({"type": leak_type, "match": match})
        return leaks


def run_dynamic_scan(args, log=print):
    """Drive the running app and translate raw DAST results into findings."""
    if requests is None or jwt is None:
        log("[!] dynamic scan needs 'requests' and 'PyJWT' installed - skipping. "
            "Run: pip install -r requirements.txt")
        return []

    log(f"[*] Dynamic scan target: {args.url}")
    fuzzer = DynamicFuzzer(base_url=args.url, log=log)
    findings = []

    token = fuzzer.login(
        args.email, args.password, endpoint=args.login_endpoint,
        email_field=args.email_field, password_field=args.password_field,
    )

    rl = fuzzer.test_rate_limiting(
        args.login_endpoint, args.request_count, email=args.email,
        email_field=args.email_field, password_field=args.password_field,
    )
    if rl["requests_sent"] and not rl["rate_limited"]:
        findings.append(make_finding(
            "dynamic", "Rate Limiting", "Missing Rate Limiting",
            f"{args.login_endpoint}: {rl['notes']}",
        ))

    for leak in rl.get("leaks_found", []):
        findings.append(make_finding(
            "dynamic", "Info Leak", "Verbose Error / Info Leak",
            f"{leak['type']}: {leak['match']}", file=args.login_endpoint,
        ))

    if token:
        idor = fuzzer.test_idor_token_swap(args.profile_endpoint, token, args.other_user_id)
        if idor["idor_detected"]:
            findings.append(make_finding(
                "dynamic", "IDOR", "IDOR Confirmed (Live)",
                f"{args.profile_endpoint} (id={args.other_user_id}): {idor['notes']}",
            ))

        own_profile_endpoint = fuzzer._DYNAMIC_ROUTE.sub("1", args.profile_endpoint)
        jwt_res = fuzzer.fuzz_jwt_auth(own_profile_endpoint, token)
        if jwt_res["bypass_successful"]:
            findings.append(make_finding(
                "dynamic", "JWT Bypass", "JWT Authentication Bypass (Live)",
                f"{own_profile_endpoint}: {jwt_res['notes']}",
            ))
    else:
        log("[!] skipping IDOR/JWT tests - no valid login token")

    if args.register_endpoint:
        try:
            probe = fuzzer.session.post(
                f"{fuzzer.base_url}{args.register_endpoint}",
                json={args.email_field: args.email, args.password_field: "x", "name": "x", "address": "x"},
                timeout=DEFAULT_TIMEOUT,
            )
            for leak in fuzzer.check_error_leaks(probe.status_code, probe.text):
                findings.append(make_finding(
                    "dynamic", "Info Leak", "Verbose Error / Info Leak",
                    f"{leak['type']}: {leak['match']}", file=args.register_endpoint,
                ))
        except requests.RequestException as e:
            log(f"[!] register-endpoint probe failed: {e}")

    log(f"[*] Dynamic scan complete: {len(findings)} finding(s)")
    return findings


def build_report(findings, target_dir, url=None, ran_dynamic=False):
    """Aggregate findings into a structured risk report dict."""
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)

    if counts["CRITICAL"]:
        level = "CRITICAL"
    elif counts["HIGH"]:
        level = "HIGH"
    elif counts["MEDIUM"]:
        level = "MEDIUM"
    elif counts["LOW"]:
        level = "LOW"
    else:
        level = "MINIMAL"

    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["scanner"], f["file"] or "", f["line"] or 0),
    )

    return {
        "tool": "Vibe-Coded Website Fuzzer",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target_directory": target_dir,
        "target_url": url if ran_dynamic else None,
        "scans_run": ["static"] + (["dynamic"] if ran_dynamic else []),
        "summary": {
            "total_findings": len(findings),
            "risk_level": level,
            "risk_score": score,
            "by_severity": counts,
        },
        "findings": ordered,
    }


def render_report_text(report):
    """Human-readable plain-text version of the report."""
    s = report["summary"]
    lines = []
    lines.append("=" * 70)
    lines.append("  VIBE-CODED WEBSITE FUZZER - VULNERABILITY RISK REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated : {report['generated_at']}")
    lines.append(f"Directory : {report['target_directory']}")
    if report["target_url"]:
        lines.append(f"Target URL: {report['target_url']}")
    lines.append(f"Scans run : {', '.join(report['scans_run'])}")
    lines.append("")
    lines.append(f"OVERALL RISK LEVEL : {s['risk_level']}   (risk score: {s['risk_score']})")
    lines.append(f"TOTAL FINDINGS     : {s['total_findings']}")
    lines.append("  " + "  ".join(f"{sev}: {s['by_severity'][sev]}" for sev in SEVERITY_ORDER))
    lines.append("")
    lines.append("-" * 70)
    lines.append("  FINDINGS")
    lines.append("-" * 70)

    if not report["findings"]:
        lines.append("No vulnerabilities detected. Nice.")
    for i, f in enumerate(report["findings"], 1):
        loc = f["file"] or "-"
        if f["line"]:
            loc = f"{loc}:{f['line']}"
        lines.append(f"[{i}] {f['severity']:<8} {f['type']}")
        lines.append(f"      scanner : {f['scanner']}  |  category: {f['category']}")
        lines.append(f"      location: {loc}")
        lines.append(f"      detail  : {f['detail']}")
        lines.append("")
    return "\n".join(lines)


def print_report_terminal(report):
    """Pretty terminal output via rich, or plain text if rich isn't installed."""
    if not RICH:
        print(render_report_text(report))
        return

    s = report["summary"]
    level = s["risk_level"]
    level_color = SEVERITY_COLOR.get(level, "green")

    header = (
        f"[bold]Directory:[/bold] {report['target_directory']}\n"
        f"[bold]Scans run:[/bold] {', '.join(report['scans_run'])}"
    )
    if report["target_url"]:
        header += f"\n[bold]Target URL:[/bold] {report['target_url']}"
    header += (
        f"\n\n[bold]Overall risk:[/bold] [{level_color}]{level}[/{level_color}]"
        f"   [dim](score {s['risk_score']})[/dim]\n"
        f"[bold]Total findings:[/bold] {s['total_findings']}   "
        + "  ".join(
            f"[{SEVERITY_COLOR.get(sev, 'white')}]{sev} {s['by_severity'][sev]}[/{SEVERITY_COLOR.get(sev, 'white')}]"
            for sev in SEVERITY_ORDER
        )
    )
    _console.print(Panel(header, title="Vulnerability Risk Report", border_style=level_color, box=box.ROUNDED))

    if not report["findings"]:
        _console.print("[green]No vulnerabilities detected.[/green]")
        return

    table = Table(box=box.SIMPLE_HEAVY, show_lines=False, header_style="bold")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type")
    table.add_column("Location")
    table.add_column("Detail", overflow="fold")

    for i, f in enumerate(report["findings"], 1):
        loc = f["file"] or "-"
        if f["line"]:
            loc = f"{loc}:{f['line']}"
        color = SEVERITY_COLOR.get(f["severity"], "white")
        table.add_row(
            str(i),
            f"[{color}]{f['severity']}[/{color}]",
            f["type"],
            loc,
            f["detail"],
        )
    _console.print(table)


def write_report_file(report, output_path, fmt):
    """Persist the report to disk as json or txt."""
    with open(output_path, "w", encoding="utf-8") as fh:
        if fmt == "json":
            json.dump(report, fh, indent=2)
        else:
            fh.write(render_report_text(report))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Vibe-Coded Website Fuzzer - static + dynamic security scanner for AI-generated apps.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--dir", required=True,
                        help="Path to the application directory to scan (e.g. ./my-vibecoded-app)")

    out = parser.add_argument_group("report output")
    out.add_argument("--format", choices=["txt", "json"], default="txt",
                     help="Format for the report written with --output")
    out.add_argument("--output", "-o", metavar="FILE",
                     help="Write the final report to this file (in addition to the terminal)")
    out.add_argument("--quiet", action="store_true",
                     help="Suppress progress logging; only show the final report")

    dyn = parser.add_argument_group("dynamic fuzzing (requires the app running on localhost)")
    dyn.add_argument("--dynamic", action="store_true",
                     help="Also run the live DAST fuzzer against --url")
    dyn.add_argument("--url", default="http://localhost:3000",
                     help="Base URL of the running app")
    dyn.add_argument("--email", default="alice@example.com", help="Account to log in as")
    dyn.add_argument("--password", default="password123", help="Password for --email")
    dyn.add_argument("--email-field", default="email",
                     help="JSON field name for the login identifier (some sites use 'username')")
    dyn.add_argument("--password-field", default="password")
    dyn.add_argument("--login-endpoint", default="/api/auth/login")
    dyn.add_argument("--profile-endpoint", default="/api/profile/{id}",
                     help="Use {id} (or [id]) as the dynamic placeholder")
    dyn.add_argument("--other-user-id", default="2", help="A different user's id, for the IDOR test")
    dyn.add_argument("--request-count", type=int, default=100,
                     help="Requests to fire for the rate-limit test")
    dyn.add_argument("--register-endpoint", default="/api/auth/register",
                     help="Endpoint probed for error leaks; pass '' to skip")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    def log(msg):
        if not args.quiet:
            print(msg)

    if not os.path.isdir(args.dir):
        print(f"Error: directory '{args.dir}' does not exist.", file=sys.stderr)
        return 2

    log("--- Vibe-Coded Website Fuzzer ---\n")

    config = load_config()
    findings = run_static_scan(args.dir, config, log=log)

    ran_dynamic = False
    if args.dynamic:
        ran_dynamic = True
        findings += run_dynamic_scan(args, log=log)

    report = build_report(findings, args.dir, url=args.url, ran_dynamic=ran_dynamic)

    log("")
    print_report_terminal(report)

    if args.output:
        write_report_file(report, args.output, args.format)
        log(f"\n[*] Report written to {args.output} ({args.format})")

    return 1 if report["summary"]["risk_level"] in ("CRITICAL", "HIGH") else 0


if __name__ == "__main__":
    sys.exit(main())
