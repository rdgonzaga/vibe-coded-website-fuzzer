"""
this is just a skeleton / template idk how to do this yet
"""

import argparse
import json


class DynamicFuzzer:

    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url.rstrip("/")

    def map_endpoints_to_localhost(self, endpoints: list) -> list:
        """
        take the list of endpoints phase 2 found (like /api/profile/[id])
        and turns them into real URLs we can actually send requests to.

        example: /api/profile/[id] -> http://localhost:3000/api/profile/1
        (js replace [id] with some number like 1 for now)
        """
        print(f"[*] mapping {len(endpoints)} endpoint(s) to localhost urls")
        mapped = []
        # TODO: loop through endpoints, swap out [id] / [something] for a number
        # TODO: stick self.base_url in front of the route to make a full url
        pass
        return mapped

    def test_rate_limiting(self, endpoint: str, request_count: int = 100) -> dict:
        """
        spam the login endpoint a bunch of times and see if it ever blocks us

        if the site has rate limiting, we should start getting 429 errors
        after a while. 
        """
        print(f"[*] sending {request_count} requests to {endpoint}")
        results = {
            "endpoint": endpoint,
            "requests_sent": 0,
            "rate_limited": False,
            "notes": "not implemented yet",
        }
        # TODO: send a bunch of requests in a loop (requests or aiohttp)
        # TODO: count how many times we get a 429 back
        pass
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
            "notes": "not implemented yet",
        }
        # TODO: send request to endpoint_pattern (with target_id in it) using session_token
        # TODO: if we get a 200 back with someone else's data, mark idor_detected = True
        pass
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
            "notes": "not implemented yet",
        }
        # TODO: split original_token into header.payload.signature
        # TODO: build an alg=none version and try it
        # TODO: try re-signing with a list of common weak secrets
        pass
        return results

    def check_error_leaks(self, response_code: int, response_content: str) -> list:
        """
        look at error responses (mainly 500s) and check if they're leaking
        stuff they shouldn't, like file paths or stack traces.
        """
        print("[*] checking response for leaked info")
        leaks = []
        # TODO: use regex to look for things like C:\, /usr/, node_modules,
        # "at Object.<anonymous>", sql error messages, etc.
        pass
        return leaks


def main():
    parser = argparse.ArgumentParser(description="Phase 3 - Dynamic Fuzzer (DAST)")
    parser.add_argument("--dir", type=str, help="path to the app we scanned in Phase 2", required=False)
    parser.add_argument("--url", type=str, default="http://localhost:3000", help="local url of the running app")
    args = parser.parse_args()

    print("--- DAST Fuzzer ---")
    print(f"Target URL: {args.url}")

    fuzzer = DynamicFuzzer(base_url=args.url)

    # once the methods above are implemented, try calling them like this:
    # fuzzer.map_endpoints_to_localhost([{"method": "GET", "route": "/api/profile/[id]"}])
    # fuzzer.test_rate_limiting("/api/auth/login")
    # fuzzer.test_idor_token_swap("/api/profile/{id}", "dummy_token_user_1", "2")
    # fuzzer.fuzz_jwt_auth("/api/profile/1", "header.payload.signature")


if __name__ == "__main__":
    main()
