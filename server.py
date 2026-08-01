"""
Local web UI for the Vibe-Coded Website Fuzzer.

Serves a dashboard with the four bundled sample targets (each runs the static
scanner on its folder) plus a box to enter any URL and run the dynamic fuzzer
against it. Everything reuses main.py's scanners, CVSS scoring and HTML report.

Run:  python server.py            (then open http://localhost:8000)
"""

import html
import os
import sys
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import main

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8000

SAMPLES = [
    ("vulnerable-target", "E-commerce backend (original demo)"),
    ("vulnerable-targets2", "PayVibe - fintech / payments"),
    ("vulnerable-targets3", "AdminVibe - admin dashboard"),
    ("safe-target", "Brew & Bytes - clean control app"),
]
SAMPLE_NAMES = {name for name, _ in SAMPLES}


def dynamic_args(url):
    """Build the argument bundle run_dynamic_scan expects, from a target URL."""
    return SimpleNamespace(
        url=url.rstrip("/"),
        email="alice@example.com",
        password="password123",
        email_field="email",
        password_field="password",
        login_endpoint="/api/auth/login",
        profile_endpoint="/api/profile/{id}",
        other_user_id="2",
        request_count=30,
        register_endpoint="/api/auth/register",
    )


def scan_sample(name):
    """Run the static scanner on a bundled sample folder and return report HTML."""
    target_dir = os.path.join(HERE, name)
    config = main.load_config()
    findings = main.run_static_scan(target_dir, config, log=lambda m: None)
    report = main.build_report(findings, f"./{name}", ran_dynamic=False)
    return with_back_bar(main.render_report_html(report))


def scan_url(url):
    """Run the dynamic fuzzer against a URL and return report HTML."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if main.requests is None or main.jwt is None:
        return error_page("The dynamic scanner needs 'requests' and 'PyJWT' installed.")

    # reachability pre-check so an unreachable host is not reported as "clean"
    try:
        main.requests.get(url, timeout=6)
    except main.requests.RequestException as exc:
        return error_page(f"Could not reach <code>{html.escape(url)}</code>.<br>{html.escape(str(exc))}")

    findings = main.run_dynamic_scan(dynamic_args(url), log=lambda m: None)
    report = main.build_report(findings, url, url=url, ran_dynamic=True)
    return with_back_bar(main.render_report_html(report))


def with_back_bar(page):
    """Inject a small 'back to registry' bar into a rendered report page."""
    bar = ("<div style=\"max-width:940px;margin:0 auto;padding:18px 18px 0;"
           "font-family:'Cascadia Mono',Consolas,monospace\">"
           "<a href=\"/\" style=\"color:var(--strong);text-decoration:none;font-size:.82rem;"
           "font-weight:700;letter-spacing:.1em;border-bottom:1px solid var(--gold);padding-bottom:2px\">"
           "&larr; RETURN TO CASE REGISTRY</a></div>")
    return page.replace("<body>", "<body>" + bar, 1)


def error_page(message):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>CASE ERROR</title></head>
<body style="font-family:'Courier New',monospace;background:#0c0b09;color:#c9c0aa;padding:44px">
<div style="max-width:640px;margin:0 auto">
  <a href="/" style="color:#c9a86a;text-decoration:none;letter-spacing:.12em">&larr; RETURN TO CASE REGISTRY</a>
  <h1 style="color:#ff3b30;letter-spacing:.14em;font-size:1.3rem">INVESTIGATION HALTED</h1>
  <p style="line-height:1.7">{message}</p>
</div></body></html>"""


def sample_status(name):
    """Quick static scan of a sample folder -> (risk_level, findings, highest_cvss)."""
    try:
        target_dir = os.path.join(HERE, name)
        config = main.load_config()
        findings = main.run_static_scan(target_dir, config, log=lambda m: None)
        report = main.build_report(findings, f"./{name}", ran_dynamic=False)
        s = report["summary"]
        return s["risk_level"], s["total_findings"], s["highest_cvss"]
    except Exception:
        return "MINIMAL", 0, 0.0


def dashboard():
    cards = ""
    for name, desc in SAMPLES:
        level, total, top = sample_status(name)
        color = main.SEVERITY_HEX.get(level, "#8a8172")
        ref = "VC-" + str((sum(ord(c) * (i + 3) for i, c in enumerate(name)) % 9000) + 1000)
        cards += f'''<a class="case" href="/report?target={urllib.parse.quote(name)}" style="--c:{color}">
              <div class="casetop"><span class="cref">FILE {ref}</span>
                <span class="cstamp">{html.escape(level)}</span></div>
              <div class="cname">{html.escape(name)}</div>
              <div class="cdesc">{html.escape(desc)}</div>
              <div class="cfoot"><span class="cnt">{total} finding(s)</span>
                <span class="cvss">PEAK CVSS {top}</span></div>
            </a>'''

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VIBECHECK :: PROMPT PATROL CASE REGISTRY</title>
<style>
  * {{ box-sizing:border-box; }}
{main.THEME_CSS}
  html {{ background:var(--page); font-size:112.5%; }}
  body {{ margin:0; color:var(--ink); line-height:1.6;
         font-family:"Cascadia Mono","JetBrains Mono","Consolas","Courier New",ui-monospace,monospace;
         background:
           radial-gradient(130% 120% at 50% -5%, rgba(0,0,0,0) 55%, var(--vig)),
           repeating-linear-gradient(0deg, var(--grain) 0 1px, transparent 1px 5px),
           var(--page); }}
  .wrap {{ max-width:940px; margin:0 auto; padding:34px 18px 60px; }}
  .file {{ background:var(--paper); border:1px solid var(--line); box-shadow:0 0 0 1px var(--edge), var(--shadow); }}
  .strip {{ height:22px; background:repeating-linear-gradient(45deg, var(--stripe1) 0 14px, var(--stripe0) 14px 28px);
            border-bottom:1px solid var(--line); display:flex; align-items:center; overflow:hidden; }}
  .strip span {{ font-size:.66rem; letter-spacing:.3em; color:var(--tagink); font-weight:800;
                 background:var(--tagbg); padding:2px 10px; margin-left:14px; }}
  .cover {{ padding:24px 30px 20px; }}
  .doctitle {{ font-size:.72rem; letter-spacing:.28em; color:var(--mute); }}
  .agency {{ font-size:1.7rem; font-weight:800; letter-spacing:.16em; color:var(--strong); margin:3px 0 2px; }}
  .agency b {{ color:{main.SEVERITY_HEX['MINIMAL']}; }}
  .subtitle {{ font-size:.72rem; letter-spacing:.2em; color:var(--faint); text-transform:uppercase; }}
  .body {{ padding:6px 30px 30px; }}
  h2 {{ font-size:.78rem; letter-spacing:.22em; color:var(--mute); text-transform:uppercase;
       margin:26px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--line); }}
  .grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }}
  @media (max-width:560px){{ .grid {{ grid-template-columns:1fr; }} }}
  a.case {{ display:block; text-decoration:none; color:inherit; background:var(--panel);
           border:1px solid var(--line2); border-left:3px solid var(--c); padding:15px 17px;
           transition:transform .12s, box-shadow .12s; position:relative; }}
  a.case:hover {{ transform:translateY(-2px); box-shadow:0 8px 24px rgba(0,0,0,.35); }}
  .casetop {{ display:flex; justify-content:space-between; align-items:center; gap:8px; }}
  .cref {{ font-size:.72rem; letter-spacing:.12em; color:var(--mute); }}
  .cstamp {{ font-size:.64rem; font-weight:800; letter-spacing:.1em; color:var(--c);
            border:1.5px solid var(--c); border-radius:3px; padding:1px 7px; transform:rotate(-3deg); }}
  .cname {{ font-size:.96rem; font-weight:800; color:var(--strong); letter-spacing:.04em; margin:9px 0 4px; }}
  .cdesc {{ font-size:.73rem; color:var(--mute); margin-bottom:12px; }}
  .cfoot {{ display:flex; justify-content:space-between; font-size:.7rem; border-top:1px dotted var(--dot); padding-top:8px; }}
  .cnt {{ color:var(--c); font-weight:700; }}
  .cvss {{ color:var(--faint); }}
  .invest {{ background:var(--panel); border:1px solid var(--line2); padding:20px 22px; }}
  .invest .pl {{ color:var(--mute); font-size:.72rem; letter-spacing:.1em; margin-bottom:12px; text-transform:uppercase; }}
  .invest form {{ display:flex; gap:10px; flex-wrap:wrap; }}
  .invest input {{ flex:1; min-width:240px; padding:11px 14px; border:1px solid var(--line);
                  background:var(--code); color:var(--strong); font-family:inherit; font-size:.82rem; outline:none;
                  letter-spacing:.03em; }}
  .invest input:focus {{ border-color:var(--gold); box-shadow:0 0 0 2px color-mix(in srgb, var(--gold) 22%, transparent); }}
  .invest button {{ padding:11px 20px; border:1px solid var(--gold); background:transparent; color:var(--strong);
                   cursor:pointer; font-family:inherit; font-size:.78rem; font-weight:800; letter-spacing:.14em; }}
  .invest button:hover {{ background:var(--gold); color:var(--paper); }}
  .notice {{ margin-top:14px; font-size:.72rem; color:var(--ink);
            background:color-mix(in srgb, {main.SEVERITY_HEX['HIGH']} 9%, transparent);
            border:1px solid color-mix(in srgb, {main.SEVERITY_HEX['HIGH']} 42%, transparent); padding:10px 14px; }}
  .notice b {{ letter-spacing:.15em; color:{main.SEVERITY_HEX['HIGH']}; }}
  .memo {{ font-size:.71rem; color:var(--faint); margin-top:10px; }}
  footer {{ text-align:center; font-size:.64rem; color:var(--faint); margin-top:12px; letter-spacing:.2em; }}
</style>
{main.THEME_JS}
</head>
<body>
{main.THEME_BTN}
<div class="wrap">
  <div class="file">
    <div class="strip"><span>CONFIDENTIAL &mdash; AUTHORIZED PERSONNEL ONLY</span></div>
    <div class="cover">
      <div class="doctitle">PROMPT PATROL &mdash; CENTRAL CASE REGISTRY</div>
      <div class="agency">VIBE<b>CHECK</b></div>
      <div class="subtitle">by Prompt Patrol</div>
    </div>
    <div class="body">
      <h2>Open Case Files &mdash; Sample Targets (static)</h2>
      <div class="grid">{cards}</div>

      <h2>Open New Investigation &mdash; Scan a URL (dynamic)</h2>
      <div class="invest">
        <div class="pl">&gt; assign target for live field investigation</div>
        <form action="/scan" method="get">
          <input type="text" name="url" placeholder="http://localhost:3000" autofocus spellcheck="false">
          <button type="submit">OPEN CASE</button>
        </form>
        <div class="notice"><b>&#9888; NOTICE:</b> Investigate only systems you own or are explicitly
          authorized to test. The dynamic scan actively sends login floods and forged tokens &mdash;
          running it against others' sites without permission is illegal.</div>
        <div class="memo">Field tests: login, rate-limit, IDOR and JWT-bypass. Default credentials:
          alice@example.com / password123.</div>
      </div>
    </div>
    <div class="strip"><span>END REGISTRY &mdash; FOR AUTHORIZED, EDUCATIONAL TESTING ONLY</span></div>
  </div>
  <footer>VIBECHECK &middot; PROMPT PATROL &middot; case management console</footer>
</div>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if route == "/":
                self._send(dashboard())
            elif route == "/favicon.ico":
                self._send("", status=204)
            elif route == "/report":
                target = (query.get("target") or [""])[0]
                if target not in SAMPLE_NAMES:
                    self._send(error_page("Unknown sample target."), status=404)
                else:
                    self._send(scan_sample(target))
            elif route == "/scan":
                url = (query.get("url") or [""])[0].strip()
                if not url:
                    self._send(error_page("Please enter a URL to scan."), status=400)
                else:
                    self._send(scan_url(url))
            else:
                self._send(error_page("Not found."), status=404)
        except Exception:
            self._send(error_page("<pre>" + html.escape(traceback.format_exc()) + "</pre>"), status=500)


def main_server():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[*] Vibe-Coded Website Fuzzer UI serving at http://localhost:{PORT}")
    print("[*] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    sys.exit(main_server())
