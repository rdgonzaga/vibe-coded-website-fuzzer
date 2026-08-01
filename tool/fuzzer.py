import argparse
import json
import os
import re
import warnings
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

import jwt
import requests

warnings.filterwarnings("ignore", category=jwt.InsecureKeyLengthWarning)

DEFAULT_TIMEOUT = 5  # seconds


class DynamicFuzzer:

    def __init__(self, base_url: str = "http://localhost:3000", log=print):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.log = log

    # common field names other vibe-coded sites use for a returned token
    _TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "authToken")
    _DYNAMIC_ROUTE = re.compile(r"\[(?:\.\.\.)?[^\]]+\]|\{[^}]+\}|(?<=/):[^/]+")

    def login(
        self,
        email: str,
        password: str,
        endpoint: str = "/api/auth/login",
        email_field: str = "email",
        password_field: str = "password",
    ) -> Optional[str]:
        """Log in and return the token, or None on failure."""
        url = f"{self.base_url}{endpoint}"
        self.log(f"[*] logging in as {email}")

        try:
            response = self.session.post(
                url, json={email_field: email, password_field: password}, timeout=DEFAULT_TIMEOUT
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

    def map_endpoints_to_localhost(self, endpoints: list) -> list:
        """
        take the list of endpoints phase 2 found (like /api/profile/[id])
        and turns them into real URLs we can actually send requests to.

        example: /api/profile/[id] -> http://localhost:3000/api/profile/1
        (replace [id] with some number like 1 for now)
        """
        self.log(f"[*] mapping {len(endpoints)} endpoint(s) to localhost urls")
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

    def discover_nextjs_endpoints(self, target_dir: str) -> list:
        """Extract API route paths from Next.js app/api and pages/api folders."""
        endpoints = []

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [name for name in dirs if name not in {".git", ".next", "node_modules"}]

            for filename in files:
                relative_path = os.path.relpath(os.path.join(root, filename), target_dir)
                relative_path = relative_path.replace("\\", "/")

                app_route = re.fullmatch(
                    r"(?:src/)?app/(api/.+)/route\.(?:js|ts|jsx|tsx)", relative_path
                )
                pages_route = re.fullmatch(
                    r"(?:src/)?pages/(api/.+)\.(?:js|ts|jsx|tsx)", relative_path
                )

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

    def test_rate_limiting(
        self,
        endpoint: str,
        request_count: int = 100,
        email: str = "test@example.com",
        password: str = "wrong-password-on-purpose",
        email_field: str = "email",
        password_field: str = "password",
    ) -> dict:
        """Fire concurrent requests at endpoint and count HTTP 429s."""
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

        # a target crashing under load is itself a finding worth catching
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

        results = {
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
        return results

    def test_idor_token_swap(self, endpoint_pattern: str, session_token: str, target_id: str) -> dict:
        """
        this is the IDOR test. log in as user a, then use user a's token
        to try to grab user b's data by just changing the id in the url.

        example: we're logged in as user 1, but we send a request to
        /api/profile/2 using our token. if it works and gives us user 2's
        info, that's an IDOR bug.
        """
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
                url,
                headers={"Authorization": f"Bearer {session_token}"},
                timeout=DEFAULT_TIMEOUT,
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

    def fuzz_jwt_auth(self, endpoint: str, original_token: str) -> dict:
        """
        try to break the JWT auth. two things to try:
        1. change "alg" to "none" in the token header and strip the signature
        2. try re-signing the token with common weak secrets (like "secret",
           "supersecret", etc.) and see if the server accepts it

        if either one works and we get let in, that's a real vulnerability.
        """
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

        def try_token(name: str, token: str) -> bool:
            try:
                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=DEFAULT_TIMEOUT,
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

    # response bodies are raw JSON text, so backslashes come back doubled
    # ("C:\\Users\\...") - path separators use \\+, not \\, to match that
    _LEAK_PATTERNS = {
        "Windows file path": re.compile(r"[A-Za-z]:\\+(?:[^\\\\s\"']+\\+)*[^\\\s\"']+"),
        "Unix file path": re.compile(r"/(?:usr|home|etc|var|root)/[^\s\"']+"),
        "node_modules path": re.compile(r"[\w./\\-]*node_modules[/\\]+[^\s\"']+"),
        "JS stack trace frame": re.compile(r"at\s+[\w.$<>]+\s*\(?[^\s)\"']+:\d+:\d+\)?"),
        "Database error": re.compile(
            r"(?i)(SQLITE_[A-Z]+|SqliteError|SqlException|psycopg2\.\w+|"
            r"pymysql\.\w+|MongoServerError|syntax error at or near|ORA-\d{5})"
        ),
        "Python traceback frame": re.compile(r'File "[^"]+", line \d+'),
    }

    _SECURITY_HEADERS = {
        "Content-Security-Policy": "no CSP - page is exposed to injected-script / XSS",
        "X-Frame-Options": "no anti-clickjacking header",
        "X-Content-Type-Options": "MIME-sniffing not disabled",
        "Strict-Transport-Security": "no HSTS - connection can be downgraded",
    }

    def check_security_headers(self, path: str = "/") -> dict:
        """GET the app root and report any missing standard security headers."""
        url = f"{self.base_url}{path}"
        self.log(f"[*] checking security headers on {path}")
        try:
            response = self.session.get(url, timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            self.log(f"[!] security-header probe failed: {e}")
            return None
        present = {k.lower() for k in response.headers.keys()}
        missing = [(name, why) for name, why in self._SECURITY_HEADERS.items()
                   if name.lower() not in present]
        return {"path": path, "status_code": response.status_code, "missing": missing}

    def check_error_leaks(self, response_code: int, response_content: str) -> list:
        """Scan an error response for leaked paths, stack traces, or DB errors."""
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

    # common field names other vibe-coded sites use for a returned token
    _TOKEN_KEYS = ("token", "access_token", "accessToken", "jwt", "authToken")
    _DYNAMIC_ROUTE = re.compile(r"\[(?:\.\.\.)?[^\]]+\]|\{[^}]+\}|(?<=/):[^/]+")

    def login(
        self,
        email: str,
        password: str,
        endpoint: str = "/api/auth/login",
        email_field: str = "email",
        password_field: str = "password",
    ) -> Optional[str]:
        """Log in and return the token, or None on failure."""
        url = f"{self.base_url}{endpoint}"
        print(f"[*] logging in as {email}")

        try:
            response = self.session.post(
                url, json={email_field: email, password_field: password}, timeout=DEFAULT_TIMEOUT
            )
        except requests.RequestException as e:
            print(f"[!] login request failed: {e}")
            return None

        if response.status_code != 200:
            print(f"[!] login failed ({response.status_code}): {response.text[:200]}")
            return None

        try:
            body = response.json()
        except ValueError:
            print("[!] login succeeded but response wasn't JSON (cookie-based auth?)")
            return None

        for key in self._TOKEN_KEYS:
            if body.get(key):
                return body[key]

        print(f"[!] login succeeded but no recognizable token field ({', '.join(self._TOKEN_KEYS)})")
        return None

    def map_endpoints_to_localhost(self, endpoints: list) -> list:
        """
        take the list of endpoints phase 2 found (like /api/profile/[id])
        and turns them into real URLs we can actually send requests to.

        example: /api/profile/[id] -> http://localhost:3000/api/profile/1
        (js replace [id] with some number like 1 for now)
        """
        print(f"[*] mapping {len(endpoints)} endpoint(s) to localhost urls")
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

    def discover_nextjs_endpoints(self, target_dir: str) -> list:
        """Extract API route paths from Next.js app/api and pages/api folders."""
        endpoints = []

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [name for name in dirs if name not in {".git", ".next", "node_modules"}]

            for filename in files:
                relative_path = os.path.relpath(os.path.join(root, filename), target_dir)
                relative_path = relative_path.replace("\\", "/")

                app_route = re.fullmatch(
                    r"(?:src/)?app/(api/.+)/route\.(?:js|ts|jsx|tsx)", relative_path
                )
                pages_route = re.fullmatch(
                    r"(?:src/)?pages/(api/.+)\.(?:js|ts|jsx|tsx)", relative_path
                )

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

    def test_rate_limiting(
        self,
        endpoint: str,
        request_count: int = 100,
        email: str = "test@example.com",
        password: str = "wrong-password-on-purpose",
        email_field: str = "email",
        password_field: str = "password",
    ) -> dict:
        """Fire concurrent requests at endpoint and count HTTP 429s."""
        url = f"{self.base_url}{endpoint}"
        print(f"[*] sending {request_count} requests to {endpoint}")

        payload = {email_field: email, password_field: password}

        def fire_one(_):
            try:
                response = self.session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
                return response.status_code, response.text
            except requests.RequestException as e:
                print(f"[!] request failed: {e}")
                return None, None

        with ThreadPoolExecutor(max_workers=20) as pool:
            responses = list(pool.map(fire_one, range(request_count)))

        status_codes = [code for code, _ in responses if code is not None]
        requests_sent = len(status_codes)
        rate_limited_count = sum(1 for code in status_codes if code == 429)

        # a target crashing under load is itself a finding worth catching,
        # on any site - not just this one
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

        results = {
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
        return results

    def test_idor_token_swap(self, endpoint_pattern: str, session_token: str, target_id: str) -> dict:
        """
        this is the IDOR test. log in as user a, then use user a's token
        to try to grab user b's data by just changing the id in the url.

        example: we're logged in as user 1, but we send a request to
        /api/profile/2 using our token. if it works and gives us user 2's
        info, that's an IDOR bug.
        """
        print(f"[*] trying token swap on {endpoint_pattern} with id={target_id}")
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
                url,
                headers={"Authorization": f"Bearer {session_token}"},
                timeout=DEFAULT_TIMEOUT,
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

    def fuzz_jwt_auth(self, endpoint: str, original_token: str) -> dict:
        """
        try to break the JWT auth. two things to try:
        1. change "alg" to "none" in the token header and strip the signature
        2. try re-signing the token with common weak secrets (like "secret",
           "supersecret", etc.) and see if the server accepts it

        if either one works and we get let in, that's a real vulnerability.
        """
        print(f"[*] fuzzing jwt on {endpoint}")
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

        def try_token(name: str, token: str) -> bool:
            try:
                response = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=DEFAULT_TIMEOUT,
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

    # response bodies are raw JSON text, so backslashes come back doubled
    # ("C:\\Users\\...") - path separators use \\+, not \\, to match that
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

    def check_error_leaks(self, response_code: int, response_content: str) -> list:
        """Scan an error response for leaked paths, stack traces, or DB errors."""
        print("[*] checking response for leaked info")
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

        if leaks:
            print(f"[!] found {len(leaks)} unique potential leak(s) in response")

        return leaks


def main():
    parser = argparse.ArgumentParser(description="Phase 3 - Dynamic Fuzzer (DAST)")
    parser.add_argument("--dir", type=str, help="path to the app we scanned in Phase 2", required=False)
    parser.add_argument("--url", type=str, default="http://localhost:3000", help="local url of the running app")
    parser.add_argument("--email", type=str, default="alice@example.com", help="account to log in as")
    parser.add_argument("--password", type=str, default="password123", help="password for --email")
    parser.add_argument("--email-field", type=str, default="email", help="JSON field name for the login identifier (some sites use 'username')")
    parser.add_argument("--password-field", type=str, default="password")
    parser.add_argument("--login-endpoint", type=str, default="/api/auth/login")
    parser.add_argument("--profile-endpoint", type=str, default="/api/profile/{id}", help="use {id} as a placeholder")
    parser.add_argument("--other-user-id", type=str, default="2", help="a different user's id, for the IDOR test")
    parser.add_argument("--request-count", type=int, default=100, help="requests to fire for the rate-limit test")
    parser.add_argument(
        "--register-endpoint",
        type=str,
        default="/api/auth/register",
        help="endpoint to probe for error leaks; pass '' to skip if the target has no register route",
    )
    parser.add_argument("--report", type=str, help="write the full JSON results to this file")
    args = parser.parse_args()

    print("--- DAST Fuzzer ---")
    print(f"Target URL: {args.url}\n")

    fuzzer = DynamicFuzzer(base_url=args.url)
    report = {}

    if args.dir:
        if os.path.isdir(args.dir):
            endpoints = fuzzer.discover_nextjs_endpoints(args.dir)
            report["endpoint_mapping"] = {
                "discovered": endpoints,
                "localhost_urls": fuzzer.map_endpoints_to_localhost(endpoints),
            }
        else:
            print(f"[!] directory not found: {args.dir}")
            report["endpoint_mapping"] = {
                "discovered": [],
                "localhost_urls": [],
                "notes": "directory not found",
            }

    token = fuzzer.login(
        args.email, args.password, endpoint=args.login_endpoint,
        email_field=args.email_field, password_field=args.password_field,
    )
    report["login"] = {"email": args.email, "token_obtained": token is not None}

    report["rate_limiting"] = fuzzer.test_rate_limiting(
        args.login_endpoint, args.request_count, email=args.email,
        email_field=args.email_field, password_field=args.password_field,
    )

    if token:
        own_profile_endpoint = fuzzer._DYNAMIC_ROUTE.sub("1", args.profile_endpoint)
        report["idor"] = fuzzer.test_idor_token_swap(args.profile_endpoint, token, args.other_user_id)
        report["jwt_fuzz"] = fuzzer.fuzz_jwt_auth(own_profile_endpoint, token)
    else:
        print("[!] skipping IDOR/JWT tests - no valid login token")

    # leaks turned up during the rate-limit burst apply to any target
    report["error_leaks"] = list(report["rate_limiting"].get("leaks_found", []))

    # optionally also probe a specific endpoint (e.g. a register route that
    # echoes raw errors) - opt out with --register-endpoint '' on sites
    # that don't have one, or that use a different request shape
    if args.register_endpoint:
        try:
            probe = fuzzer.session.post(
                f"{fuzzer.base_url}{args.register_endpoint}",
                json={args.email_field: args.email, args.password_field: "x", "name": "x", "address": "x"},
                timeout=DEFAULT_TIMEOUT,
            )
            report["error_leaks"] += fuzzer.check_error_leaks(probe.status_code, probe.text)
        except requests.RequestException as e:
            print(f"[!] register-endpoint probe failed: {e}")

    print("\n--- Summary ---")
    print(json.dumps(report, indent=2))

    if args.report:
        with open(args.report, "w") as report_file:
            json.dump(report, report_file, indent=2)
        print(f"\n[*] full report written to {args.report}")


if __name__ == "__main__":
    main()
