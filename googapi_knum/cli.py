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
    {"name": "Maps Geocoding API", "url": "https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key={key}", "type": "http"},
    {"name": "Maps Directions API", "url": "https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key={key}", "type": "http"},
    {"name": "Maps Distance Matrix API", "url": "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Seattle&destinations=Portland&key={key}", "type": "http"},
    {"name": "Maps Elevation API", "url": "https://maps.googleapis.com/maps/api/elevation/json?locations=40.714728,-73.998672&key={key}", "type": "http"},
    {"name": "Maps Time Zone API", "url": "https://maps.googleapis.com/maps/api/timezone/json?location=40.689247,-74.044502&timestamp=1609459200&key={key}", "type": "http"},
    {"name": "Maps Places Text Search API", "url": "https://maps.googleapis.com/maps/api/place/textsearch/json?query=Googleplex&key={key}", "type": "http"},
    {"name": "Maps Places Details API", "url": "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJE9on3F3HwoAR9AhGJW_fL-I&key={key}", "type": "http"},
    {"name": "Maps Static API", "url": "https://maps.googleapis.com/maps/api/staticmap?center=New+York,NY&zoom=13&size=600x300&key={key}", "type": "http"},
    {"name": "Street View Static API", "url": "https://maps.googleapis.com/maps/api/streetview?size=600x300&location=40.689247,-74.044502&key={key}", "type": "http"},
    {"name": "Map Tiles API", "url": "https://tile.googleapis.com/v1/tiles/z/x/y?key={key}", "type": "http"},
    {"name": "Routes API (Compute Routes)", "url": "https://routes.googleapis.com/directions/v2:computeRoutes?key={key}", "type": "http"},
    {"name": "Routes API (Route Matrix)", "url": "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={key}", "type": "http"},
    {"name": "Geolocation API", "url": "https://www.googleapis.com/geolocation/v1/geolocate?key={key}", "type": "http"},
    {"name": "Roads API", "url": "https://roads.googleapis.com/v1/snapToRoads?path=40.714728,-73.998672|40.714728,-73.998672&key={key}", "type": "http"},
    {"name": "Elevation API", "url": "https://maps.googleapis.com/maps/api/elevation/json?locations=40.714728,-73.998672&key={key}", "type": "http"},
    {"name": "Address Validation API", "url": "https://addressvalidation.googleapis.com/v1:validateAddress?key={key}", "type": "http"},

    # --- MAPS JS (headless browser test) ---
    {"name": "Maps JavaScript API", "url": "https://maps.googleapis.com/maps/api/js?key={key}&callback=initMap", "type": "maps_js"},

    # --- PLACES (New) ---
    {"name": "Places API (New) - Nearby Search", "url": "https://places.googleapis.com/v1/places:searchNearby?key={key}", "type": "http"},
    {"name": "Places API (New) - Text Search", "url": "https://places.googleapis.com/v1/places:searchText?key={key}", "type": "http"},
    {"name": "Places API (New) - Place Details", "url": "https://places.googleapis.com/v1/places/ChIJN1t_tDeuEmsRUsoyG83frY4?key={key}", "type": "http"},
    {"name": "Place Autocomplete API", "url": "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Googleplex&key={key}", "type": "http"},
    {"name": "Reverse Geocoding API", "url": "https://maps.googleapis.com/maps/api/geocode/json?latlng=40.714728,-73.998672&key={key}", "type": "http"},

    # --- YOUTUBE & SEARCH ---
    {"name": "YouTube Data API v3", "url": "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&type=video&maxResults=1&key={key}", "type": "http"},
    {"name": "Custom Search JSON API", "url": "https://www.googleapis.com/customsearch/v1?q=test&key={key}", "type": "http"},
    {"name": "Programmable Search Engine API", "url": "https://cse.googleapis.com/cse/v1?key={key}", "type": "http"},

    # --- FIREBASE ---
    # These require custom POST logic and response parsing for security checks
    {"name": "Firebase Identity Toolkit API", "url": "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}", "type": "firebase_identity_toolkit"},
    {"name": "Firebase Installations API", "url": "https://firebaseinstallations.googleapis.com/v1/projects/-/installations?key={key}", "type": "firebase_installations"},
    {"name": "Firebase Authentication REST API", "url": "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={key}", "type": "firebase_auth_rest"},
    {"name": "Firebase Cloud Messaging (legacy HTTP API)", "url": "https://fcm.googleapis.com/fcm/send?key={key}", "type": "firebase_fcm"},
    {"name": "Firebase App Check API", "url": "https://firebaseappcheck.googleapis.com/v1/projects/-/apps/-:exchangeDebugToken?key={key}", "type": "firebase_app_check"},

    # --- GEMINI & VERTEX AI ---
    {"name": "Gemini API (Google AI Studio)", "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={key}", "type": "gemini"},
    {"name": "Vertex AI (public inference)", "url": "https://us-central1-aiplatform.googleapis.com/v1/projects/vertex-ai/locations/us-central1/publishers/google/models/text-bison:predict?key={key}", "type": "vertex_ai"},

    # --- CLOUD AI/ML APIs ---
    {"name": "Cloud Vision API", "url": "https://vision.googleapis.com/v1/images:annotate?key={key}", "type": "cloud_vision"},
    {"name": "Cloud Translation API v2", "url": "https://translation.googleapis.com/language/translate/v2?q=Hello+world&target=es&format=text&key={key}", "type": "http"},
    {"name": "Cloud Speech-to-Text API", "url": "https://speech.googleapis.com/v1/speech:recognize?key={key}", "type": "cloud_speech"},
    {"name": "Cloud Text-to-Speech API", "url": "https://texttospeech.googleapis.com/v1/text:synthesize?key={key}", "type": "cloud_tts"},
    {"name": "Cloud Natural Language API", "url": "https://language.googleapis.com/v1/documents:analyzeEntities?key={key}", "type": "cloud_nlp"},

    # --- OTHER PUBLIC DATA APIS ---
    {"name": "Google Books API", "url": "https://www.googleapis.com/books/v1/volumes?q=harry+potter&maxResults=1&key={key}", "type": "http"},
    {"name": "Civic Information API", "url": "https://www.googleapis.com/civicinfo/v2/elections?key={key}", "type": "http"},
    {"name": "Safe Browsing API", "url": "https://safebrowsing.googleapis.com/v4/threatLists?key={key}", "type": "http"},
    {"name": "Knowledge Graph Search API", "url": "https://kgsearch.googleapis.com/v1/entities:search?query=Taylor+Swift&limit=1&indent=True&key={key}", "type": "http"},
    {"name": "Google Fonts API", "url": "https://www.googleapis.com/webfonts/v1/webfonts?sort=popularity&key={key}", "type": "http"},
]


# ------------- Helper functions ------------- #

def generate_random_domain():
    """
    Generate a random 24-character .com domain.
    Format: <20 random chars>.com (20 + 4 = 24 chars total)
    """
    import string
    chars = string.ascii_lowercase + string.digits
    random_part = ''.join(random.choice(chars) for _ in range(20))
    return f"{random_part}.com"


def verbose_print(verbose, msg):
    if verbose:
        print(f"{DIM}[VERBOSE]{RESET} {msg}")


def build_headers(origin=None, referer=None):
    headers = {
        "User-Agent": "Google-API-Key-Access-Checker/1.0",
    }
    if origin:
        headers["Origin"] = origin
    if referer:
        headers["Referer"] = referer
    return headers


def send_request(
    method,
    url,
    headers,
    proxies=None,
    json=None,
    timeout=TIMEOUT,
    verbose=False,
    verify=True,
):
    verbose_print(verbose, f"Request: {method} {url}")
    verbose_print(verbose, f"Headers: {headers}")
    if proxy := proxies and (proxies.get("http") or proxies.get("https")):
        verbose_print(verbose, f"Proxy: {proxy}")
    if json is not None:
        verbose_print(verbose, f"JSON payload: {json}")

    verbose_print(verbose, f"TLS verify: {verify}")

    def do_request(active_verify):
        if method == "GET":
            return requests.get(
                url,
                headers=headers,
                timeout=timeout,
                proxies=proxies,
                verify=active_verify,
            )
        return requests.post(
            url,
            headers=headers,
            json=json,
            timeout=timeout,
            proxies=proxies,
            verify=active_verify,
        )

    try:
        resp = do_request(verify)
    except requests.exceptions.SSLError:
        if not proxies or verify is not True:
            raise
        verbose_print(verbose, "TLS verification failed through proxy; retrying with TLS verification disabled.")
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        resp = do_request(False)

    verbose_print(verbose, f"Response: {resp.status_code} {resp.reason}")
    content = resp.text or ""
    if verbose and content:
        verbose_print(verbose, f"Response body: {content[:1000]}")
    return resp


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


def check_maps_js_in_browser(api_key, timeout_ms=15000, proxy=None, verbose=False, ignore_https_errors=False):
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
            verbose_print(verbose, f"Launching Playwright Chromium with proxy={proxy}")
            browser = p.chromium.launch(headless=True, proxy={"server": proxy} if proxy else None)
            context = browser.new_context(ignore_https_errors=ignore_https_errors)
            page = context.new_page()

            def on_console(msg):
                # msg.text is a property in Playwright's sync API
                try:
                    console_messages.append(msg.text)
                except Exception as e:
                    console_messages.append(f"[console-handler-error] {e!r}")

            page.on("console", on_console)

            try:
                # 'networkidle' is brittle; use 'domcontentloaded' + explicit wait
                verbose_print(verbose, f"Opening browser URL: {url}")
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PlaywrightTimeoutError as e:
                console_messages.append(f"[goto-timeout] {e}")
                maps_loaded = False
            else:
                # Give the map some extra time to initialize
                page.wait_for_timeout(5000)
                maps_loaded = page.evaluate("window.MAPS_LOADED === true")

            context.close()
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
    print("-" * 80)
    print(f"{BOLD}{'ID':<3} {'Service':<42} {'Result':<28} {'HTTP':<6}{RESET}")
    print("-" * 80)

    for r in results:
        idx = r["index"]
        name = (r["name"] or "")[:42]
        classification = r["classification"] or ""
        http_code = str(r["http_code"])

        color = color_for_classification(classification)
        result_padded = classification.ljust(28)
        result_colored = f"{color}{result_padded}{RESET}"

        print(
            f"{idx:<3} "
            f"{name:<42} "
            f"{result_colored} "
            f"{http_code:<6}"
        )

    print("-" * 80)
    print()


# ---------- Output file writers ---------- #

def write_output_text(path, results, origin=None, referer=None, proxy=None):
    with open(path, "w", encoding="utf-8") as f:
        f.write("Google API Key Comprehensive Access Check\n")
        f.write("=========================================\n\n")
        f.write(f"Generated at         : {datetime.utcnow().isoformat()}Z\n")
        f.write(f"Origin header used   : {origin or '(none)'}\n")
        f.write(f"Referer header used  : {referer or '(none)'}\n")
        f.write(f"Proxy used           : {proxy or '(none)'}\n")
        for r in results:
            f.write(f"[{r['index']}] {r['name']}\n")
            f.write(f"  Result : {r['classification']}\n")
            f.write(f"  HTTP   : {r['http_code']}\n")
            f.write(f"  Detail : {r['detail']}\n")
            f.write(f"  Manual : {r['manual_url']}\n")
            f.write("\n")


def write_output_json(path, results, origin=None, referer=None, proxy=None):
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "origin": origin,
        "referer": referer,
        "proxy": proxy,
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


def write_output_csv(path, results, origin=None, referer=None, proxy=None):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("# Google API Key Comprehensive Access Check\n")
        f.write(f"# Generated at: {datetime.utcnow().isoformat()}Z\n")
        f.write(f"# Origin: {origin or '(none)'}\n")
        f.write(f"# Referer: {referer or '(none)'}\n")
        f.write(f"# Proxy: {proxy or '(none)'}\n")
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


def write_output_file(path, results, origin=None, referer=None, proxy=None, fmt="text"):
    fmt = (fmt or "text").lower()
    if fmt == "json":
        write_output_json(path, results, origin=origin, referer=referer, proxy=proxy)
    elif fmt == "csv":
        write_output_csv(path, results, origin=origin, referer=referer, proxy=proxy)
    else:
        write_output_text(path, results, origin=origin, referer=referer, proxy=proxy)


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

  Route traffic through an HTTP proxy:
    python google_api_key_checker.py AIzaSyYourKeyGoesHere \
      --proxy http://127.0.0.1:8080 \
      -o results.txt

  Route traffic through an intercepting proxy such as Burp:
    python google_api_key_checker.py AIzaSyYourKeyGoesHere \
      --proxy http://127.0.0.1:8080 \
      -v

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
    parser.add_argument(
        "--proxy",
        help="Proxy URL to route HTTP and browser traffic through (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable HTTPS certificate verification for all HTTP checks.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging for requests, responses, and proxy diagnostics.",
    )

    args = parser.parse_args()
    api_key = args.api_key.strip()
    origin = args.origin
    referer = args.referer
    proxy = args.proxy
    insecure = args.insecure
    verbose = args.verbose
    out_format = args.format

    # If neither origin nor referer provided, generate a random domain for both
    if not origin and not referer:
        random_domain = f"https://{generate_random_domain()}"
        origin = random_domain
        referer = random_domain

    headers = build_headers(origin=origin, referer=referer)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    tls_verify = not insecure
    if insecure:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )

    print(f"{BOLD}[+] Checking Google API key against {len(SERVICES)} services...{RESET}")
    if origin or referer or proxy:
        print(
            f"{DIM}    Using Origin={origin or '(none)'} | "
            f"Referer={referer or '(none)'}{RESET}"
        )
        if proxy:
            print(f"{DIM}    Proxy: {proxy}{RESET}")
            print(f"{DIM}    Proxy TLS interception will fallback to insecure verification if needed.{RESET}")
        if insecure:
            print(f"{YELLOW}    HTTPS certificate verification disabled (--insecure).{RESET}")
        if verbose:
            print(f"{DIM}    Verbose mode enabled{RESET}")
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
        manual_url = url
        svc_type = svc.get("type", "http")

        print(f"{DIM}[{idx}/{len(SERVICES)}] {name}...{RESET}", end="", flush=True)

        classification = "UNKNOWN"
        detail = ""
        http_code = "N/A"

        try:
            if svc_type == "maps_js":
                classification, detail = check_maps_js_in_browser(
                    api_key,
                    proxy=proxy,
                    verbose=verbose,
                    ignore_https_errors=bool(proxy or insecure),
                )
                http_code = "n/a"

            elif svc_type == "firebase_identity_toolkit":
                # Firebase Identity Toolkit: try anonymous sign-up (safe, does not require email)
                payload = {"returnSecureToken": True}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "idToken" in data:
                    classification = "ACCEPTED (anonymous sign-up allowed)"
                    detail = "Anonymous sign-up succeeded. Key is valid and project allows registration."
                elif resp.status_code == 400 and "error" in data:
                    err = data["error"].get("message", "")
                    if "API_KEY_INVALID" in err:
                        classification = "REJECTED (invalid key)"
                        detail = err
                    elif "OPERATION_NOT_ALLOWED" in err:
                        classification = "ACCEPTED (key valid, registration disabled)"
                        detail = err
                    else:
                        classification = f"ERROR ({err})"
                        detail = err
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "firebase_installations":
                # Firebase Installations: try POST with dummy data
                payload = {"appId": "1:1234567890:web:abcdef123456", "authVersion": "FIS_v2", "sdkVersion": "w:0.0.0"}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "fid" in data:
                    classification = "ACCEPTED (installations allowed)"
                    detail = "Installations API responded with FID. Key is valid."
                elif resp.status_code == 400 and "error" in data:
                    err = data["error"].get("message", "")
                    if "API_KEY_INVALID" in err:
                        classification = "REJECTED (invalid key)"
                        detail = err
                    else:
                        classification = f"ERROR ({err})"
                        detail = err
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "firebase_auth_rest":
                # Firebase Auth REST: try anonymous sign-up
                payload = {"returnSecureToken": True}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "idToken" in data:
                    classification = "ACCEPTED (anonymous sign-up allowed)"
                    detail = "Anonymous sign-up succeeded. Key is valid and project allows registration."
                elif resp.status_code == 400 and "error" in data:
                    err = data["error"].get("message", "")
                    if "API_KEY_INVALID" in err:
                        classification = "REJECTED (invalid key)"
                        detail = err
                    elif "OPERATION_NOT_ALLOWED" in err:
                        classification = "ACCEPTED (key valid, registration disabled)"
                        detail = err
                    else:
                        classification = f"ERROR ({err})"
                        detail = err
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "firebase_fcm":
                # FCM: try POST with dummy data
                payload = {"registration_ids": ["dummy"]}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "failure" in data:
                    classification = "ACCEPTED (key valid, FCM responded)"
                    detail = "FCM responded. Key is valid."
                elif resp.status_code == 401:
                    classification = "REJECTED (invalid key)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "firebase_app_check":
                # App Check: try POST with dummy data
                payload = {"debugToken": "dummy"}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200:
                    classification = "ACCEPTED (key valid, App Check responded)"
                    detail = "App Check responded. Key is valid."
                elif resp.status_code == 400 and "error" in data:
                    err = data["error"].get("message", "")
                    if "API_KEY_INVALID" in err:
                        classification = "REJECTED (invalid key)"
                        detail = err
                    else:
                        classification = f"ERROR ({err})"
                        detail = err
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "gemini":
                # Gemini API: try generateContent with a minimal prompt.
                payload = {
                    "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
                    "generationConfig": {"maxOutputTokens": 1},
                }
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                data_text = str(data).lower()
                if resp.status_code == 200 and "candidates" in data:
                    classification = "ACCEPTED (key valid, Gemini responded)"
                    detail = "Gemini responded. Key is valid."
                elif resp.status_code == 400 and "API_KEY_INVALID" in str(data):
                    classification = "REJECTED (invalid key)"
                    detail = data
                elif resp.status_code == 403 and (
                    "api_key_service_blocked" in data_text
                    or "requests to this api" in data_text
                    or " are blocked" in data_text
                    or "api is restricted" in data_text
                ):
                    classification = "ACCEPTED (blocked by key API restrictions)"
                    detail = data
                elif resp.status_code == 403 and "PERMISSION_DENIED" in str(data):
                    classification = "ACCEPTED (permission denied)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "vertex_ai":
                # Vertex AI: try POST with dummy instance
                payload = {"instances": [{"content": "Hello"}]}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "predictions" in data:
                    classification = "ACCEPTED (key valid, Vertex AI responded)"
                    detail = "Vertex AI responded. Key is valid."
                elif resp.status_code == 403 and "PERMISSION_DENIED" in str(data):
                    classification = "ACCEPTED (key valid, but not allowed for this model)"
                    detail = data
                elif resp.status_code == 400 and "API_KEY_INVALID" in str(data):
                    classification = "REJECTED (invalid key)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "cloud_vision":
                # Vision API: try POST with dummy image
                payload = {"requests": [{"image": {"content": ""}, "features": [{"type": "LABEL_DETECTION"}]}]}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "responses" in data:
                    classification = "ACCEPTED (key valid, Vision responded)"
                    detail = "Vision API responded. Key is valid."
                elif resp.status_code == 400 and "API_KEY_INVALID" in str(data):
                    classification = "REJECTED (invalid key)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "cloud_speech":
                # Speech-to-Text: try POST with dummy config
                payload = {"config": {"encoding": "LINEAR16", "languageCode": "en-US"}, "audio": {"content": ""}}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "results" in data:
                    classification = "ACCEPTED (key valid, Speech-to-Text responded)"
                    detail = "Speech-to-Text responded. Key is valid."
                elif resp.status_code == 400 and "API_KEY_INVALID" in str(data):
                    classification = "REJECTED (invalid key)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "cloud_tts":
                # Text-to-Speech: try POST with dummy input
                payload = {"input": {"text": "Hello"}, "voice": {"languageCode": "en-US", "ssmlGender": "NEUTRAL"}, "audioConfig": {"audioEncoding": "MP3"}}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "audioContent" in data:
                    classification = "ACCEPTED (key valid, TTS responded)"
                    detail = "Text-to-Speech responded. Key is valid."
                elif resp.status_code == 400 and "API_KEY_INVALID" in str(data):
                    classification = "REJECTED (invalid key)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            elif svc_type == "cloud_nlp":
                # Natural Language API: try POST with dummy document
                payload = {"document": {"type": "PLAIN_TEXT", "content": "Hello world"}, "encodingType": "UTF8"}
                resp = send_request("POST", url, headers={**headers, "Content-Type": "application/json"}, json=payload, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                data = resp.json() if resp.content else {}
                if resp.status_code == 200 and "entities" in data:
                    classification = "ACCEPTED (key valid, NLP responded)"
                    detail = "Natural Language API responded. Key is valid."
                elif resp.status_code == 400 and "API_KEY_INVALID" in str(data):
                    classification = "REJECTED (invalid key)"
                    detail = data
                else:
                    classification = f"UNKNOWN ({resp.status_code})"
                    detail = data
                http_code = resp.status_code

            else:
                # Default: GET request
                resp = send_request("GET", url, headers=headers, timeout=TIMEOUT, proxies=proxies, verbose=verbose, verify=tls_verify)
                classification, detail = interpret_http_response(resp)
                http_code = resp.status_code

        except Exception as e:
            classification = "NETWORK ERROR"
            detail = f"{type(e).__name__}: {e}"
            verbose_print(verbose, f"Network exception: {detail}")
            http_code = "N/A"

        color = color_for_classification(classification)
        print(f" {color}{classification}{RESET}")

        results.append({
            "index": idx,
            "name": name,
            "classification": classification,
            "http_code": http_code,
            "detail": detail,
            "manual_url": manual_url,
        })

    print_table(results)

    print(
        f"{DIM}Note: 'ACCEPTED (Maps JS OK)' means the map actually initialized "
        f"for origin 'http://127.0.0.1:<random_port>'. If your key is supposed "
        f"to be restricted, that’s a red flag. 'ACCEPTED (blocked by referrer ACL)' "
        f"means Maps JS correctly rejected the key for that origin. Timeouts are "
        f"classified as UNKNOWN rather than crashing.{RESET}\n"
    )

    if args.out:
        write_output_file(args.out, results, origin=origin, referer=referer, proxy=proxy, fmt=out_format)
        print(f"{GREEN}[+] Results saved to {args.out} (format: {out_format}){RESET}\n")


def run():
    # Make sure Playwright + Chromium are ready (or disable Maps JS gracefully)
    ensure_playwright_browsers()
    main()


if __name__ == "__main__":
    run()
