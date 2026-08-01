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
import html
import json
import math
import os
import re
import sys
import warnings
from datetime import datetime

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

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}

CVSS_VECTORS = {
    "Exposed API Token (sk- format)": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Predictable Variable Name": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Insecure JWT: ignoreExpiration = true": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "Insecure JWT: ignoreNotBefore = true": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Insecure JWT: 'none' algorithm accepted": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Insecure JWT: predictable secret key is hardcoded": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Insecure JWT: Token created without expiresIn flag": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "Missing Route Authentication for Sensitive Endpoints": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "Broken Object-Level (IDOR) Risk": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "Unsafe password comparison (Plaintext)": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Insecure token storage (XSS Risk)": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "Potential SQL Injection (Direct Concatenation)": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Missing Rate Limiting": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "IDOR Confirmed (Live)": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "JWT Authentication Bypass (Live)": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "Verbose Error / Info Leak": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Placeholder / stub code left in source": "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
    "Missing security response headers (Live)": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
}
DEFAULT_VECTOR = "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

REMEDIATION = {
    "Exposed API Token (sk- format)": "Revoke and rotate the exposed key, then load it from an environment variable or secrets manager.",
    "Predictable Variable Name": "Move the secret out of source into an environment variable or vault; never commit credentials.",
    "Insecure JWT: ignoreExpiration = true": "Remove ignoreExpiration so expired tokens are rejected on verify.",
    "Insecure JWT: ignoreNotBefore = true": "Remove ignoreNotBefore so tokens are only honored after their nbf time.",
    "Insecure JWT: 'none' algorithm accepted": "Pin verification to a strong algorithm (e.g. HS256/RS256) and never accept 'none'.",
    "Insecure JWT: predictable secret key is hardcoded": "Replace the guessable secret with a long random key loaded from the environment.",
    "Insecure JWT: Token created without expiresIn flag": "Sign tokens with an explicit expiresIn so sessions cannot live forever.",
    "Missing Route Authentication for Sensitive Endpoints": "Require an auth/session check (middleware or getServerSession) before the handler runs.",
    "Broken Object-Level (IDOR) Risk": "Verify the requester owns the requested id before returning the record.",
    "Unsafe password comparison (Plaintext)": "Hash passwords with bcrypt/argon2 and compare hashes; never compare plaintext.",
    "Insecure token storage (XSS Risk)": "Store session tokens in httpOnly cookies instead of localStorage/sessionStorage.",
    "Potential SQL Injection (Direct Concatenation)": "Use parameterized queries / prepared statements instead of string interpolation.",
    "Missing Rate Limiting": "Add rate limiting / lockout on the endpoint to blunt brute-force and abuse.",
    "IDOR Confirmed (Live)": "Enforce per-object ownership checks server-side before returning data.",
    "JWT Authentication Bypass (Live)": "Verify token signatures with a fixed algorithm and a strong server-side secret.",
    "Verbose Error / Info Leak": "Return generic error messages and log details server-side only.",
    "Placeholder / stub code left in source": "Replace the TODO/stub with a real implementation before shipping to production.",
    "Missing security response headers (Live)": "Send CSP, X-Frame-Options, X-Content-Type-Options and HSTS headers on responses.",
}

CONFIDENCE = {
    "Exposed API Token (sk- format)": "high",
    "Predictable Variable Name": "medium",
    "Insecure JWT: ignoreExpiration = true": "high",
    "Insecure JWT: ignoreNotBefore = true": "high",
    "Insecure JWT: 'none' algorithm accepted": "high",
    "Insecure JWT: predictable secret key is hardcoded": "high",
    "Insecure JWT: Token created without expiresIn flag": "medium",
    "Missing Route Authentication for Sensitive Endpoints": "medium",
    "Broken Object-Level (IDOR) Risk": "medium",
    "Unsafe password comparison (Plaintext)": "medium",
    "Insecure token storage (XSS Risk)": "high",
    "Potential SQL Injection (Direct Concatenation)": "medium",
    "Missing Rate Limiting": "high",
    "IDOR Confirmed (Live)": "high",
    "JWT Authentication Bypass (Live)": "high",
    "Verbose Error / Info Leak": "high",
    "Placeholder / stub code left in source": "low",
    "Missing security response headers (Live)": "high",
}
DEFAULT_REMEDIATION = "Review this finding and apply the standard secure-coding fix for its class."
DEFAULT_CONFIDENCE = "medium"

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def _cvss_roundup(value):
    """Official CVSS v3.1 roundup: round up to the nearest 0.1."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss31_base_score(vector):
    """Compute the CVSS v3.1 Base score (0.0-10.0) from a metric vector string."""
    metrics = dict(p.split(":") for p in vector.split("/") if ":" in p and p.split(":")[0] != "CVSS")
    scope_changed = metrics["S"] == "C"

    av = _AV[metrics["AV"]]
    ac = _AC[metrics["AC"]]
    ui = _UI[metrics["UI"]]
    pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
    c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = 1.08 * (impact + exploitability) if scope_changed else (impact + exploitability)
    return _cvss_roundup(min(raw, 10.0))


def cvss31_severity(score):
    """Map a CVSS v3.1 Base score to its qualitative severity band."""
    if score == 0.0:
        return "MINIMAL"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def cvss_for(finding_type):
    """Return (severity_band, base_score, full_vector_string) for a finding type."""
    vector = CVSS_VECTORS.get(finding_type, DEFAULT_VECTOR)
    score = cvss31_base_score(vector)
    return cvss31_severity(score), score, f"CVSS:3.1/{vector}"


def make_finding(scanner, category, ftype, detail, file=None, line=None):
    """Normalize every detector's output into one common finding shape."""
    severity, score, vector = cvss_for(ftype)
    return {
        "scanner": scanner,
        "scan_source": scanner,
        "category": category,
        "type": ftype,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "confidence": CONFIDENCE.get(ftype, DEFAULT_CONFIDENCE),
        "remediation": REMEDIATION.get(ftype, DEFAULT_REMEDIATION),
        "file": file,
        "line": line,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Static Analysis Security Testing (SAST) — scanner module
# ---------------------------------------------------------------------------
# Import the raw detection functions written by the SAST developer.
# These return simple {"type", "line", "content"} dicts; run_static_scan
# adapts them into the normalized make_finding() shape used by the report engine.
from tool.scanner import (
    load_config,
    get_files_to_scan,
    scan_for_secrets,
    scan_jwt_config,
    scan_route_logic,
    scan_plaintext_passwords,
    scan_insecure_storage,
    scan_sql_injection,
    scan_stub_code,
)

# Maps each raw finding type string to the internal category used by the report.
_TYPE_TO_CATEGORY = {
    "Predictable Variable Name":                            "Hardcoded Secret",
    "Exposed API Token (sk- format)":                       "Hardcoded Secret",
    "Insecure JWT: ignoreExpiration = true":                "Weak JWT Config",
    "Insecure JWT: ignoreNotBefore = true":                 "Weak JWT Config",
    "Insecure JWT: 'none' algorithm accepted":              "Weak JWT Config",
    "Insecure JWT: predictable secret key is hardcoded":   "Weak JWT Config",
    "Insecure JWT: Token created without expiresIn flag":  "Weak JWT Config",
    "Missing Route Authentication for Sensitive Endpoints": "Missing Authorization",
    "Broken Object-Level (IDOR) Risk":                     "Missing Authorization",
    "Unsafe password comparison (Plaintext)":               "Plaintext Password",
    "Insecure token storage (XSS Risk)":                   "Insecure Storage",
    "Potential SQL Injection (Direct Concatenation)":       "SQL Injection",
    "Placeholder / stub code left in source":              "Stub / Placeholder Code",
}

_RAW_DETECTORS = [
    scan_for_secrets,
    scan_jwt_config,
    scan_route_logic,
    scan_plaintext_passwords,
    scan_insecure_storage,
    scan_sql_injection,
    scan_stub_code,
]


def run_static_scan(target_dir, config, log=print):
    """Run every SAST detector over the directory; return a normalized findings list."""
    files = get_files_to_scan(target_dir, config)
    log(f"[*] Static scan: {len(files)} relevant file(s) found in '{target_dir}'")

    findings = []
    for file_path in files:
        try:
            rel = os.path.relpath(file_path, target_dir)
        except ValueError:
            rel = os.path.basename(file_path)
        rel = rel.replace("\\", "/")
        for detector in _RAW_DETECTORS:
            for rf in detector(file_path):
                ftype = rf["type"]
                category = _TYPE_TO_CATEGORY.get(ftype, "General")
                findings.append(make_finding(
                    "static", category, ftype,
                    rf.get("content", ""),
                    file=rel, line=rf.get("line"),
                ))
    log(f"[*] Static scan complete: {len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------------------
# Dynamic Application Security Testing (DAST) — fuzzer module
# ---------------------------------------------------------------------------
# DynamicFuzzer is imported lazily inside run_dynamic_scan() so that missing
# optional dependencies (requests, PyJWT) fail gracefully with a clear message
# rather than crashing at import time.


def run_dynamic_scan(args, log=print):
    """Drive the running app and translate raw DAST results into findings."""
    if requests is None or jwt is None:
        log("[!] dynamic scan needs 'requests' and 'PyJWT' installed - skipping. "
            "Run: pip install -r requirements.txt")
        return []

    log(f"[*] Dynamic scan target: {args.url}")
    from tool.fuzzer import DynamicFuzzer  # safe: deps confirmed present above
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

    sh = fuzzer.check_security_headers("/")
    if sh:
        for name, why in sh["missing"]:
            findings.append(make_finding(
                "dynamic", "Security Headers", "Missing security response headers (Live)",
                f"{name}: {why}", file=sh["path"],
            ))

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


STATIC_CHECKS = [
    ("Hardcoded Secret", "Hardcoded secrets & exposed API tokens"),
    ("Weak JWT Config", "Weak JWT configuration"),
    ("Missing Authorization", "Missing route authentication / IDOR (static)"),
    ("Plaintext Password", "Plaintext password handling"),
    ("Insecure Storage", "Insecure client-side token storage"),
    ("SQL Injection", "SQL injection via string concatenation"),
    ("Stub / Placeholder Code", "Placeholder / stub code left in source"),
]
DYNAMIC_CHECKS = [
    ("Rate Limiting", "Missing rate limiting"),
    ("IDOR", "Live IDOR (object-level authorization)"),
    ("JWT Bypass", "Live JWT authentication bypass"),
    ("Info Leak", "Verbose error / information leak"),
    ("Security Headers", "Missing security response headers"),
]
CLEAN_STRENGTH = {
    "Hardcoded Secret": "No hardcoded secrets or API tokens found in source.",
    "Weak JWT Config": "No weak JWT configuration detected.",
    "Missing Authorization": "No sensitive endpoints missing authorization were found.",
    "Plaintext Password": "No plaintext password comparisons found.",
    "Insecure Storage": "No auth tokens written to insecure browser storage.",
    "SQL Injection": "Database queries show no unsafe string concatenation.",
    "Stub / Placeholder Code": "No TODO/stub placeholder code left in source.",
    "Rate Limiting": "Endpoints appear to enforce rate limiting.",
    "IDOR": "Cross-user object access was rejected (no live IDOR).",
    "JWT Bypass": "Forged JWTs were rejected (auth withstood tampering).",
    "Info Leak": "No verbose errors or leaked internals observed.",
    "Security Headers": "Standard security response headers are present.",
}

MODULE_CATALOG = [
    ("Secrets scan", "static", "Hardcoded Secret"),
    ("Endpoint auth", "static", "Missing Authorization"),
    ("JWT config", "static", "Weak JWT Config"),
    ("Injection sink", "static", "SQL Injection"),
    ("Plaintext passwords", "static", "Plaintext Password"),
    ("Insecure config", "static", "Insecure Storage"),
    ("Stub / placeholder code", "static", "Stub / Placeholder Code"),
    ("IDOR swap", "dynamic", "IDOR"),
    ("Rate limit", "dynamic", "Rate Limiting"),
    ("JWT bypass", "dynamic", "JWT Bypass"),
    ("Info leak", "dynamic", "Info Leak"),
    ("Security headers", "dynamic", "Security Headers"),
]


def build_module_coverage(findings, scans_run):
    """Report every planned detection module and whether it ran, with its finding count.

    Modules whose phase has not executed (e.g. dynamic modules before the DAST
    phase runs) are listed explicitly as 'not run', never silently omitted.
    """
    per_cat = {}
    for f in findings:
        per_cat[f["category"]] = per_cat.get(f["category"], 0) + 1

    coverage = []
    for label, phase, category in MODULE_CATALOG:
        ran = phase in scans_run
        count = per_cat.get(category, 0)
        if not ran:
            status = "not_run"
        elif count:
            status = "flagged"
        else:
            status = "clean"
        coverage.append({
            "module": label,
            "phase": phase,
            "category": category,
            "ran": ran,
            "status": status,
            "finding_count": count if ran else 0,
        })
    return coverage


def build_grouped_findings(findings):
    """Collapse findings by type: one entry per type with a combined count and locations."""
    groups = {}
    order = []
    for f in findings:
        key = f["type"]
        if key not in groups:
            order.append(key)
            groups[key] = {
                "type": f["type"],
                "category": f["category"],
                "severity": f["severity"],
                "cvss_score": f["cvss_score"],
                "cvss_vector": f["cvss_vector"],
                "scan_source": f.get("scan_source", f["scanner"]),
                "confidence": f.get("confidence", DEFAULT_CONFIDENCE),
                "remediation": f.get("remediation", DEFAULT_REMEDIATION),
                "count": 0,
                "locations": [],
                "instances": [],
            }
        g = groups[key]
        g["count"] += 1
        loc = f["file"] or "-"
        if f["line"]:
            loc = f"{loc}:{f['line']}"
        g["locations"].append(loc)
        g["instances"].append({"location": loc, "detail": f["detail"]})

    grouped = [groups[k] for k in order]
    grouped.sort(key=lambda g: (-g["cvss_score"], g["type"]))
    return grouped


def build_executive_summary(total, category_count, findings, ran_dynamic):
    """One-sentence headline: finding count, category count, and the worst single issue."""
    phase = "static + dynamic scan" if ran_dynamic else "static-only scan (dynamic not yet run)"
    if not total:
        return f"No findings recorded - subject passed every executed check ({phase})."
    worst = max(findings, key=lambda f: f["cvss_score"])
    return (
        f"{total} finding(s) across {category_count} categor"
        f"{'y' if category_count == 1 else 'ies'}; highest severity "
        f"{worst['severity']} - {worst['type']} (CVSS {worst['cvss_score']}). {phase.capitalize()}."
    )


def build_assessment(findings, ran_dynamic, counts):
    """Derive 'not vulnerable to', strengths and weaknesses from the findings."""
    checks = list(STATIC_CHECKS) + (list(DYNAMIC_CHECKS) if ran_dynamic else [])

    by_cat = {}
    for f in findings:
        c = by_cat.setdefault(f["category"], {"count": 0, "worst": 0.0, "band": "LOW"})
        c["count"] += 1
        if f["cvss_score"] >= c["worst"]:
            c["worst"] = f["cvss_score"]
            c["band"] = f["severity"]

    checks_performed = []
    safe_from = []
    for cat, label in checks:
        hit = by_cat.get(cat)
        if hit:
            checks_performed.append({
                "category": cat, "label": label, "status": "fail",
                "finding_count": hit["count"], "worst_cvss": hit["worst"],
                "worst_severity": hit["band"],
            })
        else:
            checks_performed.append({
                "category": cat, "label": label, "status": "pass",
                "finding_count": 0, "worst_cvss": 0.0, "worst_severity": None,
            })
            safe_from.append(label)

    weaknesses = [
        f"{c['label']}: {c['finding_count']} finding(s), worst CVSS {c['worst_cvss']} ({c['worst_severity']})."
        for c in sorted(
            (c for c in checks_performed if c["status"] == "fail"),
            key=lambda c: -c["worst_cvss"],
        )
    ]

    total, clean = len(checks), len(safe_from)
    strengths = []
    if total and clean == total:
        strengths.append(f"Clean scan - all {total} checked vulnerability classes passed with no findings.")
    elif clean:
        strengths.append(f"{clean} of {total} checked vulnerability classes are clean.")
    if counts["CRITICAL"] == 0 and (counts["HIGH"] or counts["MEDIUM"] or counts["LOW"]):
        strengths.append("No critical-severity vulnerabilities detected.")
    if counts["CRITICAL"] == 0 and counts["HIGH"] == 0 and (counts["MEDIUM"] or counts["LOW"]):
        strengths.append("No high- or critical-severity issues detected.")
    for cat, label in checks:
        if label in safe_from and cat in CLEAN_STRENGTH:
            strengths.append(CLEAN_STRENGTH[cat])

    if not weaknesses:
        weaknesses = ["None - no vulnerabilities were detected."]

    return {
        "checks_performed": checks_performed,
        "safe_from": safe_from,
        "strengths": strengths,
        "weaknesses": weaknesses,
    }


def build_report(findings, target_dir, url=None, ran_dynamic=False):
    """Aggregate findings into a structured risk report dict."""
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    highest_cvss = max((f["cvss_score"] for f in findings), default=0.0)

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
        key=lambda f: (-f["cvss_score"], f["scanner"], f["file"] or "", f["line"] or 0),
    )

    scans_run = ["static"] + (["dynamic"] if ran_dynamic else [])
    category_count = len({f["category"] for f in findings})

    return {
        "tool": "VibeCheck by Prompt Patrol",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scoring_standard": "CVSS v3.1",
        "target_directory": target_dir,
        "target_url": url if ran_dynamic else None,
        "scans_run": scans_run,
        "summary": {
            "total_findings": len(findings),
            "category_count": category_count,
            "risk_level": level,
            "highest_cvss": highest_cvss,
            "by_severity": counts,
            "executive_summary": build_executive_summary(
                len(findings), category_count, findings, ran_dynamic),
        },
        "module_coverage": build_module_coverage(findings, scans_run),
        "assessment": build_assessment(findings, ran_dynamic, counts),
        "grouped_findings": build_grouped_findings(findings),
        "findings": ordered,
    }


def _severity_bar_text(summary):
    """A thin ASCII severity-distribution bar (proportional to counts)."""
    total = summary["total_findings"]
    width = 50
    if not total:
        return "SEVERITY  [" + "-" * width + "]  (no findings)"
    marks = {"CRITICAL": "#", "HIGH": "=", "MEDIUM": "+", "LOW": "."}
    bar = ""
    for sev in SEVERITY_ORDER:
        n = summary["by_severity"][sev]
        if n:
            bar += marks[sev] * max(1, round(width * n / total))
    bar = (bar + "-" * width)[:width]
    legend = "  ".join(f"{marks[sev]}={sev[0]}{summary['by_severity'][sev]}" for sev in SEVERITY_ORDER)
    return f"SEVERITY  [{bar}]\n          {legend}"


def render_report_text(report):
    """Human-readable plain-text version of the report."""
    s = report["summary"]
    lines = []
    lines.append("=" * 70)
    lines.append("  VIBECHECK by PROMPT PATROL - VULNERABILITY RISK REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated : {report['generated_at']}")
    lines.append(f"Directory : {report['target_directory']}")
    if report["target_url"]:
        lines.append(f"Target URL: {report['target_url']}")
    lines.append(f"Scans run : {', '.join(report['scans_run'])}")
    lines.append("")
    lines.append(f"Scoring   : {report.get('scoring_standard', 'CVSS v3.1')}")
    lines.append("")
    lines.append(f"OVERALL RISK LEVEL : {s['risk_level']}   (highest CVSS: {s['highest_cvss']})")
    lines.append(f"TOTAL FINDINGS     : {s['total_findings']}")
    lines.append("  " + "  ".join(f"{sev}: {s['by_severity'][sev]}" for sev in SEVERITY_ORDER))
    lines.append("")
    lines.append("EXECUTIVE SUMMARY:")
    lines.append(f"  {s.get('executive_summary', '')}")
    lines.append("")
    lines.append(_severity_bar_text(s))
    lines.append("")

    lines.append("-" * 70)
    lines.append("  MODULE COVERAGE")
    lines.append("-" * 70)
    for m in report.get("module_coverage", []):
        if m["status"] == "not_run":
            tag = "not run"
        elif m["status"] == "flagged":
            tag = f"{m['finding_count']} flag(s)"
        else:
            tag = "clean"
        lines.append(f"  [{m['phase']:<7}] {m['module']:<26} {tag}")
    lines.append("")

    a = report.get("assessment", {})
    lines.append("-" * 70)
    lines.append("  SECURITY ASSESSMENT")
    lines.append("-" * 70)
    lines.append("STRENGTHS:")
    for item in a.get("strengths", []) or ["(none)"]:
        lines.append(f"  + {item}")
    lines.append("")
    lines.append("WEAKNESSES:")
    for item in a.get("weaknesses", []) or ["(none)"]:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("NOT VULNERABLE TO (checked, no findings):")
    safe = a.get("safe_from", [])
    if safe:
        for item in safe:
            lines.append(f"  [OK] {item}")
    else:
        lines.append("  (every checked class had at least one finding)")
    lines.append("")
    lines.append("-" * 70)
    lines.append("  FINDINGS BY CATEGORY")
    lines.append("-" * 70)

    grouped = report.get("grouped_findings", [])
    if not grouped:
        lines.append("No vulnerabilities detected. Nice.")
    for i, g in enumerate(grouped, 1):
        title = g["type"] + (f" ({g['count']})" if g["count"] > 1 else "")
        lines.append(f"[{i}] CVSS {g['cvss_score']:<4} {g['severity']:<8} {title}")
        lines.append(f"      category  : {g['category']}")
        lines.append(f"      scan_source: {g['scan_source']}   confidence: {g['confidence']}")
        lines.append(f"      vector    : {g['cvss_vector']}")
        lines.append(f"      locations : {', '.join(g['locations'])}")
        for inst in g["instances"]:
            lines.append(f"        - {inst['location']}: {inst['detail']}")
        lines.append(f"      remediation: {g['remediation']}")
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
        f"\n[bold]Scoring:[/bold] {report.get('scoring_standard', 'CVSS v3.1')}"
        f"\n\n[bold]Overall risk:[/bold] [{level_color}]{level}[/{level_color}]"
        f"   [dim](highest CVSS {s['highest_cvss']})[/dim]\n"
        f"[bold]Total findings:[/bold] {s['total_findings']}   "
        + "  ".join(
            f"[{SEVERITY_COLOR.get(sev, 'white')}]{sev} {s['by_severity'][sev]}[/{SEVERITY_COLOR.get(sev, 'white')}]"
            for sev in SEVERITY_ORDER
        )
        + f"\n\n[bold]Summary:[/bold] {s.get('executive_summary', '')}"
    )
    _console.print(Panel(header, title="Vulnerability Risk Report", border_style=level_color, box=box.ROUNDED))

    coverage = report.get("module_coverage", [])
    if coverage:
        cov_table = Table(box=box.SIMPLE, show_lines=False, header_style="bold", expand=False)
        cov_table.add_column("Phase", style="dim", no_wrap=True)
        cov_table.add_column("Module", no_wrap=True)
        cov_table.add_column("Status")
        for m in coverage:
            if m["status"] == "not_run":
                status = "[dim]not run[/dim]"
            elif m["status"] == "flagged":
                status = f"[red]{m['finding_count']} flag(s)[/red]"
            else:
                status = "[green]clean[/green]"
            cov_table.add_row(m["phase"], m["module"], status)
        _console.print(Panel(cov_table, title="Module Coverage", border_style="cyan", box=box.ROUNDED))

    a = report.get("assessment", {})
    strengths = "\n".join(f"[green]+[/green] {x}" for x in a.get("strengths", [])) or "[dim](none)[/dim]"
    weaknesses = "\n".join(f"[red]-[/red] {x}" for x in a.get("weaknesses", [])) or "[dim](none)[/dim]"
    safe = "\n".join(f"[green]OK[/green] {x}" for x in a.get("safe_from", [])) \
        or "[dim](every checked class had a finding)[/dim]"
    _console.print(Panel(strengths, title="Strengths", border_style="green", box=box.ROUNDED))
    _console.print(Panel(weaknesses, title="Weaknesses", border_style="red", box=box.ROUNDED))
    _console.print(Panel(safe, title="Not Vulnerable To (checked, clean)", border_style="cyan", box=box.ROUNDED))

    grouped = report.get("grouped_findings", [])
    if not grouped:
        _console.print("[green]No vulnerabilities detected.[/green]")
        return

    table = Table(box=box.SIMPLE_HEAVY, show_lines=True, header_style="bold",
                  title="Findings by Category")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("CVSS", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type / count")
    table.add_column("Src", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("Locations", overflow="fold")
    table.add_column("Fix", overflow="fold")

    for i, g in enumerate(grouped, 1):
        color = SEVERITY_COLOR.get(g["severity"], "white")
        title = g["type"] + (f"  x{g['count']}" if g["count"] > 1 else "")
        table.add_row(
            str(i),
            f"[{color}]{g['cvss_score']}[/{color}]",
            f"[{color}]{g['severity']}[/{color}]",
            title,
            g["scan_source"],
            g["confidence"],
            "\n".join(g["locations"]),
            g["remediation"],
        )
    _console.print(table)


SEVERITY_HEX = {
    "CRITICAL": "#d21f3c",
    "HIGH": "#e2680f",
    "MEDIUM": "#b0850f",
    "LOW": "#0e7490",
    "MINIMAL": "#1a7f37",
}

# Shared light/dark theme: structural colors as CSS variables. Default is the
# dark "dossier" palette; a light "manila paper" palette applies when the OS
# prefers light, or when the user toggles (data-theme on <html>, persisted).
THEME_CSS = """
  :root{
    --page:#0c0b09;--paper:#14120d;--panel:#100e0a;--code:#080706;--codeink:#b7cf9a;
    --ink:#c9c0aa;--strong:#e7dcc0;--mute:#8a8064;--faint:#6a6455;
    --line:#2c281f;--line2:#26221a;--dot:#33301f;--gold:#c9a86a;--edge:#0a0906;
    --stripe1:#1c1a14;--stripe0:#000000;--tagbg:#c9c0aa;--tagink:#0c0b09;
    --grain:rgba(255,255,255,.014);--vig:rgba(0,0,0,.55);--shadow:0 24px 60px rgba(0,0,0,.5);
  }
  @media (prefers-color-scheme:light){
    :root:not([data-theme="dark"]){
      --page:#c8bb95;--paper:#f4edda;--panel:#fbf6e6;--code:#e8dec2;--codeink:#2f5d1e;
      --ink:#3a3221;--strong:#1c170d;--mute:#6f6444;--faint:#8f8362;
      --line:#c1b58d;--line2:#c9bd97;--dot:#c4b88f;--gold:#7d5f26;--edge:#b6a87d;
      --stripe1:#d6caac;--stripe0:#2a251b;--tagbg:#2a251b;--tagink:#f4edda;
      --grain:rgba(0,0,0,.022);--vig:rgba(74,56,20,.14);--shadow:0 20px 46px rgba(90,70,30,.28);
    }
  }
  :root[data-theme="light"]{
    --page:#c8bb95;--paper:#f4edda;--panel:#fbf6e6;--code:#e8dec2;--codeink:#2f5d1e;
    --ink:#3a3221;--strong:#1c170d;--mute:#6f6444;--faint:#8f8362;
    --line:#c1b58d;--line2:#c9bd97;--dot:#c4b88f;--gold:#7d5f26;--edge:#b6a87d;
    --stripe1:#d6caac;--stripe0:#2a251b;--tagbg:#2a251b;--tagink:#f4edda;
    --grain:rgba(0,0,0,.022);--vig:rgba(74,56,20,.14);--shadow:0 20px 46px rgba(90,70,30,.28);
  }
  .themebtn{position:fixed;top:14px;right:14px;z-index:60;width:36px;height:36px;
    border:1px solid var(--line);background:var(--paper);color:var(--ink);border-radius:50%;
    cursor:pointer;font-size:1rem;line-height:1;font-family:inherit;box-shadow:0 4px 14px rgba(0,0,0,.3);}
  .themebtn:hover{border-color:var(--gold);color:var(--gold);}
"""

THEME_BTN = ('<button id="themebtn" class="themebtn" title="Toggle light / dark"'
             ' aria-label="Toggle light or dark mode">◐</button>')

THEME_JS = """<script>
(function(){var r=document.documentElement,K="vf-theme";
function ap(t){if(t){r.setAttribute("data-theme",t);}else{r.removeAttribute("data-theme");}}
try{ap(localStorage.getItem(K));}catch(e){}
document.addEventListener("click",function(e){var t=e.target;if(!t||t.id!=="themebtn")return;
var cur=r.getAttribute("data-theme");
var sysDark=!(window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches);
var nx=cur?(cur==="light"?"dark":"light"):(sysDark?"light":"dark");
ap(nx);try{localStorage.setItem(K,nx);}catch(e){}});})();
</script>"""

FILTER_JS = """<script>
(function(){
 var chips=document.querySelectorAll('.wchip'),finds=document.querySelectorAll('.finding');
 var bar=document.getElementById('filterbar'),fname=document.getElementById('filtname'),
     fcount=document.getElementById('fcount'),clearb=document.getElementById('clearf'),active=null;
 function apply(cat){var n=0;
   finds.forEach(function(f){var m=!cat||f.getAttribute('data-cat')===cat;f.style.display=m?'':'none';if(m)n++;});
   chips.forEach(function(c){c.classList.toggle('on',!!cat&&c.getAttribute('data-cat')===cat);});
   if(fcount)fcount.textContent=cat?n:finds.length;
   if(bar)bar.hidden=!cat;if(cat&&fname)fname.textContent=cat;}
 chips.forEach(function(c){c.addEventListener('click',function(){var cat=c.getAttribute('data-cat');active=(active===cat)?null:cat;apply(active);});});
 if(clearb)clearb.addEventListener('click',function(){active=null;apply(null);});
})();
</script>"""


def render_report_html(report):
    """Self-contained, styled HTML version of the report (opens in any browser)."""
    s = report["summary"]
    level = s["risk_level"]
    accent = SEVERITY_HEX.get(level, "#16a34a")

    def esc(value):
        return html.escape(str(value), quote=True)

    def live_badge(scan_source):
        return ' <span class="live">LIVE</span>' if scan_source == "dynamic" else ""

    def evidence_block(g):
        if g["count"] == 1:
            return f"<code>{esc(g['instances'][0]['detail'])}</code>"
        rows = "".join(
            f"<code>{esc(inst['location'])} &rarr; {esc(inst['detail'])}</code>"
            for inst in g["instances"]
        )
        return rows

    grouped = report.get("grouped_findings", [])
    if grouped:
        findings_block = "".join(
            f'''<div class="finding" data-cat="{esc(g['category'])}" style="--c:{SEVERITY_HEX.get(g['severity'], '#8a8172')}">
                  <div class="fbar">
                    <span class="fno">{esc(g['type'])}{f' &times;{g["count"]}' if g['count'] > 1 else ''}</span>
                    <span class="fdots"></span>
                    <span class="fsev">[ {esc(g['severity'])} &middot; CVSS {g['cvss_score']} ]{live_badge(g['scan_source'])}</span>
                  </div>
                  <div class="fgrid">
                    <span class="k">Category</span><span class="v">{esc(g['category'])} &mdash; {esc(g['scan_source'])} scan</span>
                    <span class="k">Confidence</span><span class="v"><span class="conf c-{esc(g['confidence'])}">{esc(g['confidence'].upper())}</span></span>
                    <span class="k">Vector</span><span class="v vvec">{esc(g['cvss_vector'].replace('CVSS:3.1/', ''))}</span>
                    <span class="k">Location{'s' if g['count'] > 1 else ''}</span><span class="v vl">{esc(', '.join(g['locations']))}</span>
                    <span class="k">Evidence</span><span class="v">{evidence_block(g)}</span>
                    <span class="k">Fix</span><span class="v vfix">{esc(g['remediation'])}</span>
                  </div>
                </div>'''
            for g in grouped
        )
    else:
        findings_block = '<div class="clean">NO ADVERSE FINDINGS ON RECORD &mdash; SUBJECT CLEARED.</div>'

    def _sevbar_html(summary):
        total = summary["total_findings"]
        if not total:
            return f'<i style="width:100%;background:{SEVERITY_HEX["MINIMAL"]}" title="no findings"></i>'
        seg = []
        for sev in SEVERITY_ORDER:
            n = summary["by_severity"][sev]
            if n:
                seg.append(f'<i style="width:{100 * n / total:.1f}%;background:{SEVERITY_HEX[sev]}"'
                           f' title="{sev}: {n}"></i>')
        return "".join(seg)

    sevbar = _sevbar_html(s)

    def _mod_marker(m):
        if m["status"] == "not_run":
            return ('<span class="mk mk-idle">&mdash;</span>', "mod-idle",
                    "not run")
        if m["status"] == "flagged":
            return ('<span class="mk mk-flag">&#10007;</span>', "mod-flag",
                    f"{m['finding_count']} flag" + ("s" if m["finding_count"] != 1 else ""))
        return ('<span class="mk mk-ok">&#10003;</span>', "mod-ok", "clean")

    modules_block = "".join(
        (lambda mk: f'''<div class="mod {mk[1]}">
              {mk[0]}<span class="mn">{esc(m['module'])}</span>
              <span class="ms">{mk[2]}</span>
            </div>''')(_mod_marker(m))
        for m in report.get("module_coverage", [])
    )

    url_row = (
        f'<div class="field"><span class="fk">Live Target</span><span class="fv">{esc(report["target_url"])}</span></div>'
        if report["target_url"] else ""
    )

    a = report.get("assessment", {})

    def _items(items, empty):
        if not items:
            return f'<li class="empty">{empty}</li>'
        return "".join(f"<li>{esc(x)}</li>" for x in items)

    strengths = _items(a.get("strengths", []), "None noted.")
    cp = a.get("checks_performed", [])
    cleared = _items([c["label"] for c in cp if c["status"] == "pass"], "Every checked class had a finding.")
    weak = sorted([c for c in cp if c["status"] == "fail"], key=lambda c: -c["worst_cvss"])
    weak_chips = "".join(
        f'''<button class="wchip" data-cat="{esc(c['category'])}" style="--c:{SEVERITY_HEX.get(c['worst_severity'], '#8a8172')}">
              <span class="wt">{esc(c['label'])}</span>
              <span class="wm">{c['finding_count']} finding(s) &middot; CVSS {c['worst_cvss']} &middot; {esc(c['worst_severity'])}</span>
            </button>'''
        for c in weak
    ) or '<div class="empty2">None &mdash; subject is clean.</div>'

    clean = s["total_findings"] == 0
    verdict = "SECURE" if clean else "BREACHED"
    classification = "UNCLASSIFIED" if clean else "TOP SECRET"
    raw_target = report["target_url"] or report["target_directory"]
    case_no = (sum(ord(ch) * (i + 3) for i, ch in enumerate(raw_target)) % 9000) + 1000
    file_ref = f"VC-{case_no}-{esc(report['generated_at'][:4])}"
    bs = s["by_severity"]

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CASE {file_ref} :: {esc(level)} :: VIBECHECK DOSSIER</title>
<style>
  * {{ box-sizing:border-box; }}
  :root {{ --acc:{accent}; }}
{THEME_CSS}
  html {{ background:var(--page); font-size:112.5%; }}
  body {{ margin:0; color:var(--ink); line-height:1.6;
          font-family:"Cascadia Mono","JetBrains Mono","Consolas","Courier New",ui-monospace,monospace;
          background:
            radial-gradient(130% 120% at 50% -5%, rgba(0,0,0,0) 55%, var(--vig)),
            repeating-linear-gradient(0deg, var(--grain) 0 1px, transparent 1px 5px),
            var(--page); }}
  .wrap {{ max-width:940px; margin:0 auto; padding:34px 18px 60px; }}
  a {{ color:var(--gold); }}
  .file {{ position:relative; background:var(--paper); border:1px solid var(--line);
           box-shadow:0 0 0 1px var(--edge), var(--shadow); }}
  .strip {{ height:22px; background:repeating-linear-gradient(45deg, var(--stripe1) 0 14px, var(--stripe0) 14px 28px);
            border-bottom:1px solid var(--line); display:flex; align-items:center; overflow:hidden; }}
  .strip.acc {{ background:repeating-linear-gradient(45deg, var(--acc) 0 14px, var(--page) 14px 28px);
               opacity:.8; border-bottom:0; border-top:1px solid var(--line); }}
  .strip span {{ font-size:.66rem; letter-spacing:.3em; color:var(--tagink); font-weight:800;
                 background:var(--tagbg); padding:2px 10px; margin-left:14px; }}
  .cover {{ position:relative; padding:26px 30px 22px; border-bottom:1px dashed var(--line); }}
  .doctitle {{ font-size:.72rem; letter-spacing:.28em; color:var(--mute); }}
  .agency {{ font-size:1.75rem; font-weight:800; letter-spacing:.16em; color:var(--strong); margin:3px 0 2px; }}
  .agency b {{ color:var(--acc); }}
  .subtitle {{ font-size:.72rem; letter-spacing:.2em; color:var(--faint); text-transform:uppercase; }}
  .fields {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:5px 40px;
             margin:20px 0 4px; font-size:.78rem; max-width:640px; }}
  .field {{ display:flex; gap:10px; border-bottom:1px dotted var(--dot); padding-bottom:3px; }}
  .fk {{ color:var(--mute); min-width:112px; text-transform:uppercase; letter-spacing:.08em; font-size:.66rem; padding-top:2px; }}
  .fv {{ color:var(--strong); word-break:break-all; }}
  .redact {{ background:#000; color:#000; padding:0 8px; border-radius:1px; user-select:none;
             white-space:nowrap; box-shadow:inset 0 0 0 1px #000; }}
  .stamp {{ position:absolute; top:22px; right:26px; transform:rotate(-8deg); text-align:center;
            border:3px double var(--acc); color:var(--acc); border-radius:6px; padding:8px 16px 6px;
            opacity:.92; box-shadow:inset 0 0 0 2px color-mix(in srgb, var(--acc) 26%, transparent); }}
  .stamp b {{ display:block; font-size:1.7rem; font-weight:800; letter-spacing:4px; line-height:1; }}
  .stamp small {{ display:block; font-size:.55rem; letter-spacing:3px; margin-top:5px; opacity:.85; }}
  .disp {{ padding:15px 30px; border-bottom:1px dashed var(--line); }}
  .disp .lbl {{ color:var(--mute); letter-spacing:.15em; font-size:.64rem; text-transform:uppercase; }}
  .tallies {{ display:flex; gap:26px; margin-top:8px; flex-wrap:wrap; }}
  .tally {{ font-size:.72rem; letter-spacing:.1em; color:var(--mute); }}
  .tally b {{ font-size:1.5rem; font-weight:800; margin-right:5px; }}
  .tCRIT b {{ color:{SEVERITY_HEX['CRITICAL']}; }} .tHIGH b {{ color:{SEVERITY_HEX['HIGH']}; }}
  .tMED b {{ color:{SEVERITY_HEX['MEDIUM']}; }} .tLOW b {{ color:{SEVERITY_HEX['LOW']}; }}
  .body {{ padding:22px 30px 28px; }}
  .sect {{ font-size:.78rem; letter-spacing:.22em; color:var(--mute); text-transform:uppercase;
           margin:26px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }}
  .sect:first-child {{ margin-top:2px; }}
  .assess {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:16px; }}
  .acol h4 {{ margin:0 0 8px; font-size:.7rem; letter-spacing:.2em; }}
  .acol.p h4 {{ color:{SEVERITY_HEX['MINIMAL']}; }} .acol.n h4 {{ color:{SEVERITY_HEX['CRITICAL']}; }} .acol.c h4 {{ color:{SEVERITY_HEX['LOW']}; }}
  .acol ul {{ list-style:none; margin:0; padding:0; }}
  .acol li {{ font-size:.75rem; padding:4px 0 4px 20px; position:relative; color:var(--ink);
              border-bottom:1px dotted var(--dot); }}
  .acol.p li::before {{ content:"+"; position:absolute; left:2px; color:{SEVERITY_HEX['MINIMAL']}; font-weight:800; }}
  .acol.n li::before {{ content:"!"; position:absolute; left:4px; color:{SEVERITY_HEX['CRITICAL']}; font-weight:800; }}
  .acol.c li::before {{ content:"\\2713"; position:absolute; left:2px; color:{SEVERITY_HEX['LOW']}; }}
  .acol li.empty {{ color:var(--faint); font-style:italic; }}
  .acol li.empty::before {{ content:""; }}
  .assess2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  @media (max-width:620px){{ .assess2 {{ grid-template-columns:1fr; }} }}
  .wtitle {{ margin:22px 0 10px; font-size:.72rem; letter-spacing:.2em; color:var(--mute); text-transform:uppercase; }}
  .wtitle .wtip {{ color:var(--faint); text-transform:none; letter-spacing:.02em; }}
  .wchips {{ display:flex; flex-wrap:wrap; gap:9px; }}
  .wchip {{ display:flex; flex-direction:column; align-items:flex-start; gap:3px; cursor:pointer;
            background:var(--panel); border:1px solid var(--line2); border-left:3px solid var(--c);
            border-radius:5px; padding:9px 13px; font-family:inherit; text-align:left; }}
  .wchip:hover {{ border-color:var(--c); }}
  .wchip.on {{ background:color-mix(in srgb, var(--c) 15%, var(--panel)); box-shadow:0 0 0 1px var(--c); }}
  .wchip .wt {{ font-weight:800; color:var(--strong); font-size:.8rem; }}
  .wchip .wm {{ color:var(--c); font-size:.66rem; letter-spacing:.03em; }}
  .empty2 {{ color:var(--faint); font-style:italic; font-size:.8rem; }}
  .fbararea {{ margin:0 0 12px; font-size:.76rem; color:var(--mute); }}
  .fbararea b {{ color:var(--strong); }}
  .clearf {{ margin-left:8px; background:transparent; border:1px solid var(--line); color:var(--gold);
             cursor:pointer; font-family:inherit; font-size:.7rem; padding:2px 9px; border-radius:3px; }}
  .clearf:hover {{ border-color:var(--gold); }}
  .finding {{ background:var(--panel); border:1px solid var(--line2); border-left:3px solid var(--c);
              padding:12px 16px; margin-bottom:12px; }}
  .fbar {{ display:flex; align-items:center; }}
  .fno {{ color:var(--strong); font-weight:800; letter-spacing:.1em; font-size:.8rem; white-space:nowrap; }}
  .fdots {{ flex:1; border-bottom:1px dotted var(--dot); margin:0 12px; height:.7em; }}
  .fsev {{ color:var(--c); font-weight:800; font-size:.74rem; letter-spacing:.04em; white-space:nowrap; }}
  .live {{ font-size:.54rem; font-weight:800; color:{SEVERITY_HEX['CRITICAL']}; border:1px solid {SEVERITY_HEX['CRITICAL']}; border-radius:2px;
           padding:0 5px; margin-left:6px; letter-spacing:.1em; }}
  .fgrid {{ display:grid; grid-template-columns:92px 1fr; gap:3px 12px; margin-top:9px; font-size:.74rem; }}
  .fgrid .k {{ color:var(--mute); text-transform:uppercase; letter-spacing:.06em; font-size:.64rem; padding-top:2px; }}
  .fgrid .v {{ color:var(--ink); word-break:break-all; }}
  .fgrid .v.vt {{ color:var(--strong); font-weight:700; }}
  .fgrid .v.vl {{ color:var(--gold); }}
  .fgrid .v.vvec {{ color:var(--mute); }}
  code {{ font-family:inherit; font-size:.72rem; color:var(--codeink); background:var(--code);
          padding:7px 10px; border-radius:3px; border:1px solid var(--line); border-left:2px solid var(--mute);
          display:block; margin-top:2px; white-space:pre-wrap; word-break:break-word; line-height:1.5; }}
  .exec {{ font-size:.84rem; color:var(--strong); line-height:1.55; margin:6px 0 0; }}
  .sevbar {{ display:flex; height:9px; margin:14px 0 4px; border:1px solid var(--line);
             background:var(--code); overflow:hidden; border-radius:2px; }}
  .sevbar i {{ display:block; height:100%; }}
  .sevleg {{ font-size:.62rem; color:var(--mute); letter-spacing:.06em; }}
  .modules {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:2px 24px; }}
  .mod {{ display:flex; align-items:baseline; gap:9px; font-size:.78rem;
          border-bottom:1px dotted var(--dot); padding:5px 0; }}
  .mod .mk {{ font-weight:800; width:1em; text-align:center; }}
  .mod .mn {{ color:var(--strong); flex:1; }}
  .mod .ms {{ font-size:.62rem; letter-spacing:.08em; text-transform:uppercase; white-space:nowrap; }}
  .mk-ok {{ color:{SEVERITY_HEX['MINIMAL']}; }} .mod-ok .ms {{ color:{SEVERITY_HEX['MINIMAL']}; }}
  .mk-flag {{ color:{SEVERITY_HEX['CRITICAL']}; }} .mod-flag .ms {{ color:{SEVERITY_HEX['CRITICAL']}; }}
  .mk-idle {{ color:var(--faint); }} .mod-idle .mn {{ color:var(--mute); }} .mod-idle .ms {{ color:var(--faint); }}
  .conf {{ font-weight:800; font-size:.62rem; letter-spacing:.1em; padding:1px 7px; border-radius:2px; border:1px solid var(--line); }}
  .c-high {{ color:var(--strong); border-color:var(--gold); }}
  .c-medium {{ color:var(--mute); }}
  .c-low {{ color:var(--faint); }}
  .vfix {{ color:var(--strong); }}
  .vfix::before {{ content:"FIX: "; color:{SEVERITY_HEX['MINIMAL']}; font-weight:800; }}
  .clean {{ color:{SEVERITY_HEX['MINIMAL']}; font-size:.95rem; letter-spacing:.12em; padding:18px;
            border:1px dashed {SEVERITY_HEX['MINIMAL']}; background:var(--panel); }}
  footer {{ text-align:center; font-size:.64rem; color:var(--faint); margin-top:10px; letter-spacing:.2em; }}
</style>
{THEME_JS}
</head>
<body>
{THEME_BTN}
<div class="wrap">
  <div class="file">
    <div class="strip"><span>CONFIDENTIAL &mdash; AUTHORIZED PERSONNEL ONLY</span></div>
    <div class="cover">
      <div class="stamp"><b>{verdict}</b><small>RISK: {esc(level)}</small></div>
      <div class="doctitle">PROMPT PATROL &mdash; SECURITY INVESTIGATION DOSSIER</div>
      <div class="agency">VIBE<b>CHECK</b></div>
      <div class="subtitle">by Prompt Patrol</div>
      <div class="fields">
        <div class="field"><span class="fk">File Ref</span><span class="fv">{file_ref}</span></div>
        <div class="field"><span class="fk">Classification</span><span class="fv"><span class="redact">{esc(classification)}</span></span></div>
        <div class="field"><span class="fk">Date Filed</span><span class="fv">{esc(report["generated_at"])}</span></div>
        <div class="field"><span class="fk">Scoring Std</span><span class="fv">{esc(report.get("scoring_standard", "CVSS v3.1"))}</span></div>
        <div class="field"><span class="fk">Subject</span><span class="fv">{esc(report["target_directory"])}</span></div>
        <div class="field"><span class="fk">Scans Run</span><span class="fv">{esc(", ".join(report["scans_run"]))}</span></div>
        {url_row}
        <div class="field"><span class="fk">Peak CVSS</span><span class="fv">{s["highest_cvss"]}</span></div>
      </div>
    </div>
    <div class="disp">
      <div class="lbl">Threat Disposition &mdash; {s["total_findings"]} finding(s) on record</div>
      <div class="tallies">
        <div class="tally tCRIT"><b>{bs["CRITICAL"]}</b>CRITICAL</div>
        <div class="tally tHIGH"><b>{bs["HIGH"]}</b>HIGH</div>
        <div class="tally tMED"><b>{bs["MEDIUM"]}</b>MEDIUM</div>
        <div class="tally tLOW"><b>{bs["LOW"]}</b>LOW</div>
      </div>
      <div class="sevbar">{sevbar}</div>
      <div class="sevleg">Severity distribution &mdash; CRITICAL / HIGH / MEDIUM / LOW, sized by finding count</div>
      <div class="exec">{esc(s.get("executive_summary", ""))}</div>
    </div>
    <div class="body">
      <div class="sect">Section I &mdash; Module Coverage</div>
      <div class="modules">{modules_block}</div>

      <div class="sect">Section II &mdash; Security Assessment</div>
      <div class="assess2">
        <div class="acol p"><h4>STRENGTHS</h4><ul>{strengths}</ul></div>
        <div class="acol c"><h4>EXPOSURES CLEARED</h4><ul>{cleared}</ul></div>
      </div>
      <div class="wtitle">WEAKNESSES <span class="wtip">&mdash; click a category to filter the findings below</span></div>
      <div class="wchips">{weak_chips}</div>

      <div class="sect">Section III &mdash; Logged Findings (<span id="fcount">{s["total_findings"]}</span>)</div>
      <div class="fbararea" id="filterbar" hidden>Filtering by: <b id="filtname"></b> <button id="clearf" class="clearf">show all</button></div>
      {findings_block}
    </div>
    <div class="strip acc"></div>
  </div>
  <footer>END OF FILE &mdash; {esc(report["tool"])} &mdash; for authorized, educational testing only.</footer>
</div>
{FILTER_JS}
</body>
</html>'''



def write_report_file(report, output_path, fmt):
    """Persist the report to disk as json, html or txt."""
    with open(output_path, "w", encoding="utf-8") as fh:
        if fmt == "json":
            json.dump(report, fh, indent=2)
        elif fmt == "html":
            fh.write(render_report_html(report))
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
    out.add_argument("--format", choices=["txt", "json", "html"], default="txt",
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
