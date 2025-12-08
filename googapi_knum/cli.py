#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google API key access checker.

Features:
- Tests a Google API key against multiple Google services.
- Maps JavaScript API is checked using a real headless browser:
  * Build HTML page
  * Serve it from localhost
  * Load it in Chromium via Playwright
  * Check if the map actually initializes (MAPS_LOADED) or logs an error.
- Other APIs are checked with HTTP GETs (requests), with optional Origin/Referer.
- Colorful console table + optional output file in text / JSON / CSV formats.

Dependencies:
    pip install requests playwright
    python -m playwright install chromium
"""

import argparse
import http.server
import os
import socketserver
import tempfile
import threading
import json
import csv
import sys
import subprocess
import random
import socket
from datetime import datetime
from textwrap import shorten, dedent


import requests

# Try to import Playwright for headless Maps JS testing
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

    class PlaywrightTimeoutError(Exception):
        pass


TIMEOUT = 6  # seconds for HTTP APIs

# ANSI colors
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"

# HTML page used for the Maps JS browser test
HTML_TEMPLATE = """\
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Maps JS Key Test</title>
    <style>
      #map {{
        height: 300px;
        width: 400px;
      }}
    </style>
    <script>
      window.MAPS_LOADED = false;
      function initMap() {{
        try {{
          var map = new google.maps.Map(document.getElementById('map'), {{
            zoom: 8,
            center: {{ lat: 40.689247, lng: -74.044502 }}
          }});
          window.MAPS_LOADED = true;
          console.log('MAP_INIT_SUCCESS');
        }} catch (e) {{
          console.error('MAP_INIT_EXCEPTION', e);
        }}
      }}
    </script>
    <script src="https://maps.googleapis.com/maps/api/js?key={api_key}&callback=initMap" async defer></script>
  </head>
  <body>
    <h1>Maps JS Key Test</h1>
    <div id="map"></div>
  </body>
</html>
"""

SERVICES = [
    # --- MAPS PLATFORM (HTTP-based) ---
    {
        "name": "Maps Geocoding API",
        "url": (
            "https://maps.googleapis.com/maps/api/geocode/json"
            "?address=New+York&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Directions API",
        "url": (
            "https://maps.googleapis.com/maps/api/directions/json"
            "?origin=Toronto&destination=Montreal&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Distance Matrix API",
        "url": (
            "https://maps.googleapis.com/maps/api/distancematrix/json"
            "?origins=Seattle&destinations=Portland&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Elevation API",
        "url": (
            "https://maps.googleapis.com/maps/api/elevation/json"
            "?locations=40.714728,-73.998672&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Time Zone API",
        "url": (
            "https://maps.googleapis.com/maps/api/timezone/json"
            "?location=40.689247,-74.044502&timestamp=1609459200&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Places Text Search API",
        "url": (
            "https://maps.googleapis.com/maps/api/place/textsearch/json"
            "?query=Googleplex&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Places Details API",
        "url": (
            "https://maps.googleapis.com/maps/api/place/details/json"
            "?place_id=ChIJE9on3F3HwoAR9AhGJW_fL-I&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Maps Static API",
        "url": (
            "https://maps.googleapis.com/maps/api/staticmap"
            "?center=New+York,NY&zoom=13&size=600x300&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Street View Static API",
        "url": (
            "https://maps.googleapis.com/maps/api/streetview"
            "?size=600x300&location=40.689247,-74.044502&key={key}"
        ),
        "type": "http",
    },

    # --- MAPS JS (headless browser test) ---
    {
        "name": "Maps JavaScript API",
        "url": (
            "https://maps.googleapis.com/maps/api/js"
            "?key={key}&callback=initMap"
        ),
        "type": "maps_js",  # special case
    },

    # --- PUBLIC DATA APIS ---
    {
        "name": "YouTube Data API v3",
        "url": (
            "https://www.googleapis.com/youtube/v3/search"
            "?part=snippet&q=test&type=video&maxResults=1&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Google Books API",
        "url": (
            "https://www.googleapis.com/books/v1/volumes"
            "?q=harry+potter&maxResults=1&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Civic Information API",
        "url": "https://www.googleapis.com/civicinfo/v2/elections?key={key}",
        "type": "http",
    },
    {
        "name": "Safe Browsing API",
        "url": "https://safebrowsing.googleapis.com/v4/threatLists?key={key}",
        "type": "http",
    },
    {
        "name": "Knowledge Graph Search API",
        "url": (
            "https://kgsearch.googleapis.com/v1/entities:search"
            "?query=Taylor+Swift&limit=1&indent=True&key={key}"
        ),
        "type": "http",
    },
    {
        "name": "Google Fonts API",
        "url": (
            "https://www.googleapis.com/webfonts/v1/webfonts"
            "?sort=popularity&key={key}"
        ),
        "type": "http",
    },

    # --- MACHINE LEARNING / TRANSLATION ---
    {
        "name": "Cloud Translation API v2",
        "url": (
            "https://translation.googleapis.com/language/translate/v2"
            "?q=Hello+world&target=es&format=text&key={key}"
        ),
        "type": "http",
    },
]


# ------------- Helper functions ------------- #

def build_headers(origin=None, referer=None):
    headers = {
        "User-Agent": "Google-API-Key-Access-Checker/1.0",
    }
    if origin:
        headers["Origin"] = origin
    if referer:
        headers["Referer"] = referer
    return headers


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def start_http_server(root_dir, max_tries=20):
    """
    Start a simple HTTP server serving 'root_dir' on localhost.

    - Tries random unprivileged ports in [1024, 65535].
    - Skips ports that are already in use.
    - As a last resort, uses port 0 (OS-chosen ephemeral port).

    Returns (httpd, port).
    """
    handler_class = http.server.SimpleHTTPRequestHandler
    cwd = os.getcwd()

    def try_bind(port):
        # helper to attempt binding to a specific port
        try:
            httpd = ReusableTCPServer(("127.0.0.1", port), handler_class)
            return httpd
        except OSError:
            return None

    # Change dir to serve from root_dir
    os.chdir(root_dir)

    httpd = None
    port = None

    # Try random unprivileged ports first
    for _ in range(max_tries):
        candidate = random.randint(1024, 65535)
        httpd = try_bind(candidate)
        if httpd is not None:
            port = candidate
            break

    # Fallback: let OS choose any free port
    if httpd is None:
        httpd = ReusableTCPServer(("127.0.0.1", 0), handler_class)
        port = httpd.server_address[1]

    def _serve():
        try:
            httpd.serve_forever()
        finally:
            # restore working directory when server shuts down
            os.chdir(cwd)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return httpd, port


def check_maps_js_in_browser(api_key, timeout_ms=15000):
    """
    Use headless Chromium via Playwright to actually load Maps JS and see
    whether it initializes a map (MAPS_LOADED) or logs an error.

    Returns:
      (classification, detail)
    """
    if not HAS_PLAYWRIGHT:
        return (
            "UNKNOWN (Playwright not available)",
            "Playwright or Chromium is not available; Maps JS check skipped.",
        )

    # Build temporary HTML
    tmp_dir = tempfile.mkdtemp(prefix="mapsjs_test_")
    html_path = os.path.join(tmp_dir, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(HTML_TEMPLATE.format(api_key=api_key))

    # Start HTTP server
    httpd, port = start_http_server(tmp_dir)
    url = f"http://127.0.0.1:{port}/index.html"

    console_messages = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            def on_console(msg):
                # msg.text is a property in Playwright's sync API
                try:
                    console_messages.append(msg.text)
                except Exception as e:
                    console_messages.append(f"[console-handler-error] {e!r}")

            page.on("console", on_console)

            try:
                # 'networkidle' is brittle; use 'domcontentloaded' + explicit wait
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PlaywrightTimeoutError as e:
                console_messages.append(f"[goto-timeout] {e}")
                maps_loaded = False
            else:
                # Give the map some extra time to initialize
                page.wait_for_timeout(5000)
                maps_loaded = page.evaluate("window.MAPS_LOADED === true")

            browser.close()
    finally:
        httpd.shutdown()
        httpd.server_close()

    joined = "\n".join(console_messages)
    lower = joined.lower()

    # Look for Maps JS error markers in the console
    if "google maps javascript api error:" in lower:
        if "referernotallowedmaperror" in lower:
            return (
                "ACCEPTED (blocked by referrer ACL)",
                joined or "Google Maps JavaScript API error: RefererNotAllowedMapError",
            )
        if "invalidkeymaperror" in lower:
            return "REJECTED (invalid key)", joined
        if "missingkeymaperror" in lower:
            return "REJECTED (missing key)", joined
        if "billingnotenabledmaperror" in lower:
            return "ACCEPTED (billing not enabled)", joined
        return "ERROR (Maps JS error)", joined

    # No explicit error markers
    if maps_loaded:
        return "ACCEPTED (Maps JS OK)", "Map initialized successfully (MAPS_LOADED = true)"

    if any("[goto-timeout]" in m for m in console_messages):
        return "UNKNOWN (timeout loading Maps JS)", joined or "Navigation timeout exceeded."

    if console_messages:
        return "UNKNOWN", f"Map did not initialize. Console:\n{joined}"
    return "UNKNOWN", "Map did not initialize and no console messages were captured."


def interpret_http_response(resp):
    """
    Interpret non-JS HTTP-based Google API responses, based on status code
    and common Google error JSON formats.
    """
    status = resp.status_code
    text = resp.text or ""
    text_flat = text.replace("\n", " ")
    short = shorten(text_flat, width=200, placeholder="...")

    try:
        data = resp.json()
    except ValueError:
        data = None

    # Maps-style JSON (status + error_message)
    if isinstance(data, dict) and "status" in data:
        g_status = data.get("status")
        err_msg = data.get("error_message", "") or ""

        if g_status == "OK":
            return "ACCEPTED", "OK"
        if g_status == "OVER_QUERY_LIMIT":
            return "ACCEPTED (quota exceeded)", err_msg or short
        if g_status == "REQUEST_DENIED":
            em = err_msg.lower()
            if "api key is invalid" in em or "invalid" in em:
                return "REJECTED (invalid key)", err_msg or short
            if "ip address" in em or "referer" in em or "origin" in em:
                return "ACCEPTED (blocked by key restrictions)", err_msg or short
            return "ERROR (request denied)", err_msg or short
        if g_status == "INVALID_REQUEST":
            return "ACCEPTED (bad params, key ok)", err_msg or short

        return f"ERROR (status={g_status})", err_msg or short

    # Generic Google JSON error object
    if isinstance(data, dict) and "error" in data:
        err = data.get("error", {})
        msg = err.get("message", "")
        errors = err.get("errors") or []
        reason = errors[0].get("reason") if errors and isinstance(errors[0], dict) else None
        msg_lower = msg.lower()

        if reason == "keyInvalid" or "api key not valid" in msg_lower:
            return "REJECTED (invalid key)", msg or short
        if reason in (
            "ipRefererBlocked",
            "forbidden",
            "dailyLimitExceeded",
            "userRateLimitExceeded",
            "rateLimitExceeded",
        ) or "ip address" in msg_lower or "referrer" in msg_lower or "origin" in msg_lower:
            return "ACCEPTED (blocked / quota / ACL)", msg or short
        if reason in ("accessNotConfigured", "projectNotFound"):
            return "ACCEPTED (API not enabled)", msg or short

        return f"ERROR ({reason or 'unknown reason'})", msg or short

    if 200 <= status < 300:
        return "ACCEPTED (HTTP 2xx)", f"HTTP {status}"

    return "UNKNOWN", f"HTTP {status}: {short}"


def color_for_classification(classification):
    c = classification.upper()
    if "REJECTED" in c:
        return RED
    if "ERROR" in c or "UNKNOWN" in c:
        return MAGENTA
    if "ACCEPTED" in c and (
        "BLOCKED" in c or "QUOTA" in c or "NOT ENABLED" in c or "ACL" in c or "BILLING" in c
    ):
        return YELLOW
    if "ACCEPTED" in c:
        return GREEN
    return CYAN


def print_table(results):
    print()
    print(BOLD + "Results Table" + RESET)
    print("-" * 140)
    print(
        f"{BOLD}{'ID':<3} {'Service':<32} {'Result':<32} {'HTTP':<6} Manual check URL{RESET}"
    )
    print("-" * 140)

    for r in results:
        idx = r["index"]
        name = (r["name"] or "")[:32]
        classification = r["classification"] or ""
        http_code = str(r["http_code"])
        manual_url = r.get("manual_url") or ""
        manual_short = shorten(manual_url, width=80, placeholder="...")

        color = color_for_classification(classification)
        result_colored = f"{color}{classification}{RESET}"

        print(
            f"{idx:<3} "
            f"{name:<32} "
            f"{result_colored:<32} "
            f"{http_code:<6} "
            f"{manual_short}"
        )

    print("-" * 140)
    print()


# ---------- Output file writers ---------- #

def write_output_text(path, results, origin=None, referer=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write("Google API Key Comprehensive Access Check\n")
        f.write("=========================================\n\n")
        f.write(f"Generated at         : {datetime.utcnow().isoformat()}Z\n")
        f.write(f"Origin header used   : {origin or '(none)'}\n")
        f.write(f"Referer header used  : {referer or '(none)'}\n")
        f.write(f"Maps JS via headless : {'yes' if HAS_PLAYWRIGHT else 'no'}\n\n")

        for r in results:
            f.write(f"[{r['index']}] {r['name']}\n")
            f.write(f"  Result : {r['classification']}\n")
            f.write(f"  HTTP   : {r['http_code']}\n")
            f.write(f"  Detail : {r['detail']}\n")
            f.write(f"  Manual : {r['manual_url']}\n")
            f.write("\n")


def write_output_json(path, results, origin=None, referer=None):
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "origin": origin,
        "referer": referer,
        "maps_js_headless": HAS_PLAYWRIGHT,
        "results": [
            {
                "index": r["index"],
                "service": r["name"],
                "result": r["classification"],
                "http_code": r["http_code"],
                "detail": r["detail"],
                "manual_url": r["manual_url"],
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_output_csv(path, results, origin=None, referer=None):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("# Google API Key Comprehensive Access Check\n")
        f.write(f"# Generated at: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# Origin: {origin or '(none)'}\n")
        f.write(f"# Referer: {referer or '(none)'}\n")
        f.write(f"# Maps JS via headless: {'yes' if HAS_PLAYWRIGHT else 'no'}\n")
        writer = csv.writer(f)
        writer.writerow(["index", "service", "result", "http_code", "detail", "manual_url"])
        for r in results:
            writer.writerow([
                r["index"],
                r["name"],
                r["classification"],
                r["http_code"],
                r["detail"],
                r["manual_url"],
            ])


def write_output_file(path, results, origin=None, referer=None, fmt="text"):
    fmt = (fmt or "text").lower()
    if fmt == "json":
        write_output_json(path, results, origin=origin, referer=referer)
    elif fmt == "csv":
        write_output_csv(path, results, origin=origin, referer=referer)
    else:
        write_output_text(path, results, origin=origin, referer=referer)


def ensure_playwright_browsers():
    """
    Ensure that Playwright + Chromium are available.

    - If Playwright isn't installed -> disable Maps JS checks.
    - If Chromium isn't installed -> run `python -m playwright install chromium`.
    - If install still fails -> disable Maps JS checks and continue gracefully.
    """
    global HAS_PLAYWRIGHT

    # First: is the Python package even there?
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        print("[!] Playwright Python package not installed; Maps JS checks will be disabled.")
        HAS_PLAYWRIGHT = False
        return

    # Try to launch Chromium once; if it works, we're done.
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        HAS_PLAYWRIGHT = True
        return
    except Exception as e:
        print("[*] Playwright is installed, but Chromium is missing or broken.")
        print("    Attempting automatic installation... (%s)" % e)

    # Try to run: python -m playwright install chromium
    try:
        cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
        print("[*] Running: %s" % " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate()
        out = out.decode("utf-8", "ignore")
        err = err.decode("utf-8", "ignore")

        if out.strip():
            print(out.strip())
        if err.strip():
            print(err.strip())

        if proc.returncode != 0:
            raise RuntimeError("playwright install chromium failed with exit code %s" % proc.returncode)

        print("[+] Playwright Chromium installed successfully. Verifying...")

        # Verify again
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        HAS_PLAYWRIGHT = True
        print("[+] Playwright Chromium verification succeeded.")

    except Exception as e2:
        print(f"[!] Failed to install or verify Playwright Chromium automatically: {e2}")
        print("[!] Maps JS checks will be disabled.")
        HAS_PLAYWRIGHT = False



# ------------- Main ------------- #

def main():
    parser = argparse.ArgumentParser(
        prog="google_api_key_checker.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=dedent(
            f"""{BOLD}Google API key access checker{RESET}

Tests a Google API key against multiple Google services, including:
  - Google Maps Platform (Geocoding, Directions, Static, Places, etc.)
  - Maps JavaScript API (via real headless Chromium execution)
  - YouTube Data API, Books, Civic, Safe Browsing, Fonts, Translation

For Maps JS, it actually builds a temporary HTML page, serves it from
localhost and runs it in Chromium to see if the map really loads or if
Google prints a console error like 'RefererNotAllowedMapError'."""
        ),
        epilog=dedent(
            """\
Examples:
  Basic check (no file output):
    python google_api_key_checker.py AIzaSyYourKeyGoesHere

  Save detailed human-readable results to a text file:
    python google_api_key_checker.py AIzaSyYourKeyGoesHere -o results.txt

  Save machine-readable JSON:
    python google_api_key_checker.py AIzaSyYourKeyGoesHere -o results.json -f json

  Simulate an attacker Origin/Referer for HTTP-based APIs:
    python google_api_key_checker.py AIzaSyYourKeyGoesHere \\
      -O https://evil.example \\
      -R https://evil.example/page.html \\
      -o results.csv -f csv
"""
        ),
    )

    parser.add_argument(
        "api_key",
        help="Google API key to test (typically starts with 'AIza')",
    )
    parser.add_argument(
        "-O", "--origin",
        help="Origin header to send with HTTP-based requests "
             "(e.g. https://evil.example)",
    )
    parser.add_argument(
        "-R", "--referer",
        help="Referer header to send with HTTP-based requests "
             "(e.g. https://evil.example/page.html)",
    )
    parser.add_argument(
        "-o", "--out",
        help="Optional file path to save detailed results",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format for --out file (default: text)",
    )

    args = parser.parse_args()
    api_key = args.api_key.strip()
    origin = args.origin
    referer = args.referer
    out_format = args.format

    headers = build_headers(origin=origin, referer=referer)

    print(f"{BOLD}[+] Checking Google API key against {len(SERVICES)} services...{RESET}")
    if origin or referer:
        print(
            f"{DIM}    Using Origin={origin or '(none)'} | "
            f"Referer={referer or '(none)'} for HTTP-based checks{RESET}"
        )
    if HAS_PLAYWRIGHT:
        print(f"{DIM}    Maps JS will be tested in a real headless browser.{RESET}")
    else:
        print(
            f"{YELLOW}    WARNING: Playwright not installed; Maps JS check will be 'UNKNOWN'.{RESET}"
        )
    print()

    results = []

    for idx, svc in enumerate(SERVICES, start=1):
        name = svc["name"]
        url = svc["url"].format(key=api_key)
        manual_url = url  # includes the real key

        print(f"{DIM}[{idx}/{len(SERVICES)}] {name}...{RESET}", end="", flush=True)

        svc_type = svc.get("type", "http")

        if svc_type == "maps_js":
            classification, detail = check_maps_js_in_browser(api_key)
            http_code = "n/a"
        else:
            try:
                resp = requests.get(url, headers=headers, timeout=TIMEOUT)
                classification, detail = interpret_http_response(resp)
                http_code = resp.status_code
            except Exception as e:
                classification = "NETWORK ERROR"
                detail = str(e)
                http_code = "N/A"

        color = color_for_classification(classification)
        print(f" {color}{classification}{RESET}")

        results.append(
            {
                "index": idx,
                "name": name,
                "classification": classification,
                "http_code": http_code,
                "detail": detail,
                "manual_url": manual_url,
            }
        )

    print_table(results)

    print(
        f"{DIM}Note: 'ACCEPTED (Maps JS OK)' means the map actually initialized "
        f"for origin 'http://127.0.0.1:<random_port>'. If your key is supposed "
        f"to be restricted, that’s a red flag. 'ACCEPTED (blocked by referrer ACL)' "
        f"means Maps JS correctly rejected the key for that origin. Timeouts are "
        f"classified as UNKNOWN rather than crashing.{RESET}\n"
    )

    if args.out:
        write_output_file(args.out, results, origin=origin, referer=referer, fmt=out_format)
        print(f"{GREEN}[+] Results saved to {args.out} (format: {out_format}){RESET}\n")


def run():
    # Make sure Playwright + Chromium are ready (or disable Maps JS gracefully)
    ensure_playwright_browsers()
    main()


if __name__ == "__main__":
    run()