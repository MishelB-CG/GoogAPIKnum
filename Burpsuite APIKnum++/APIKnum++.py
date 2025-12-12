# -*- coding: utf-8 -*-
#
# APIKnum++ - Multi-provider API key scanner for Burp Suite (Jython)
#
# Features:
#   - Passive & active scanning for many API key formats.
#   - For each detected key, runs a validation HTTP request roughly
#     equivalent to the "curl" examples in keyhacks.
#   - Caches results per (provider, key) so that:
#       * Passive scan only validates each key once.
#       * Active scan reuses cached results instead of re-validating.
#   - Raises:
#       * High/Medium issues for confirmed valid keys.
#       * Information issues for detected keys where validation fails,
#         is invalid, or needs additional context.
#   - Highlights exact locations of keys in request/response using markers.
#   - Logs detections and validation results to the Extender output.
#
# NOTE (Google Maps JavaScript API):
#   This extension does NOT load the Maps JS API or render HTML.
#   It only calls a Google HTTP API (Geocoding) from the scanner environment.
#   That can tell you:
#     - The key is active and usable from the scanner IP.
#     - Or it is restricted / invalid (based on error messages).
#   It CANNOT fully validate browser-side referrer restrictions.
#   The issue text for Google keys explains how to manually verify JS API
#   restrictions in a browser.

from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL, HttpURLConnection
from java.util import ArrayList

import threading
import re
import base64
from array import array

DEBUG = False
HTTP_TIMEOUT_MS = 8000  # 8s network timeout per validation

# ------------- Provider definitions -------------

PROVIDER_DEFS = [
    {
        "id": "slack_webhook",
        "name": "Slack Incoming Webhook",
        "regexes": [
            r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"
        ],
        "validator": "validate_slack_webhook",
    },
    {
        "id": "slack_api_token",
        "name": "Slack API token",
        "regexes": [
            r"xox[abprsxo]-[0-9A-Za-z\-]+",
        ],
        "validator": "validate_slack_api_token",
    },
    {
        "id": "github_token",
        "name": "GitHub Personal Access Token",
        "regexes": [
            r"ghp_[0-9A-Za-z]{36}",
            r"gho_[0-9A-Za-z]{36}",
            r"ghu_[0-9A-Za-z]{36}",
            r"ghs_[0-9A-Za-z]{36}",
            r"ghr_[0-9A-Za-z]{36}",
        ],
        "validator": "validate_github_token",
    },
    {
        "id": "sendgrid_token",
        "name": "SendGrid API Token",
        "regexes": [
            r"SG\.[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}",
        ],
        "validator": "validate_sendgrid_token",
    },
    {
        "id": "square_access_token",
        "name": "Square Access Token",
        "regexes": [
            r"EAAA[a-zA-Z0-9]{60}",
        ],
        "validator": "validate_square_access_token",
    },
    {
        "id": "hubspot_hapikey",
        "name": "HubSpot hapikey",
        "regexes": [
            r"\b[0-9a-fA-F]{32}\b",
        ],
                "context_keywords": ["hapikey", "hubapi.com", "hubspot"],
"validator": "validate_hubspot_hapikey",
        "needs_context": False,
    },
    {
        "id": "infura_api_key",
        "name": "Infura API key",
        "regexes": [
            r"https://mainnet\.infura\.io/v3/[0-9a-fA-F]{32}",
        ],
        "validator": "validate_infura_v3_key_from_url",
    },
    {
        "id": "dropbox_api_token",
        "name": "Dropbox API Token",
        "regexes": [
            r"sl\.[A-Za-z0-9\-_]{30,}",
        ],
        "validator": "validate_dropbox_token",
    },
    {
        "id": "pendo_integration_key",
        "name": "Pendo Integration Key",
        "regexes": [
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        ],
                "context_keywords": ["x-pendo-integration-key", "pendo"],
"validator": "validate_pendo_integration_key",
        "needs_context": False,
    },
    {
        "id": "twilio_sid_authtoken",
        "name": "Twilio Account SID (requires Auth Token context)",
        "regexes": [
            r"AC[0-9a-fA-F]{32}",
        ],
        "validator": "validate_twilio_sid_and_token",
        "needs_context": True,
    },
    {
        "id": "stripe_secret_key",
        "name": "Stripe Secret Key",
        "regexes": [
            r"sk_live_[0-9a-zA-Z]{20,40}",
            r"sk_test_[0-9a-zA-Z]{20,40}",
        ],
        "validator": "validate_stripe_secret_key",
    },
    {
        "id": "google_api_key",
        "name": "Google API Key (Maps/Geocoding etc.)",
        "regexes": [
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
        ],
        "validator": "validate_google_api_key",
        "needs_context": False,
    },
    {
        "id": "mailgun_private_key",
        "name": "Mailgun Private API Key",
        "regexes": [
            r"\bkey-[0-9A-Za-z]{32}\b",
        ],
        "validator": "validate_mailgun_private_key",
    },
    {
        "id": "mailchimp_api_key",
        "name": "Mailchimp API Key",
        "regexes": [
            r"\b[0-9a-f]{32}-us(?:0?[1-9]|1[0-3])\b",
        ],
        "validator": "validate_mailchimp_api_key",
    },
    {
        "id": "mapbox_access_token",
        "name": "Mapbox Access Token (pk./sk.)",
        "regexes": [
            r"\bpk\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
            r"\bsk\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
        ],
        "validator": "validate_mapbox_access_token",
    },
    {
        "id": "gitlab_pat",
        "name": "GitLab Personal Access Token",
        "regexes": [
            r"\bglpat-[0-9A-Za-z\-_]{20,}\b",
        ],
        "validator": "validate_gitlab_pat",
    },
    {
        "id": "telegram_bot_token",
        "name": "Telegram Bot Token",
        "regexes": [
            r"\b[0-9]{6,12}:[A-Za-z0-9_-]{30,50}\b",
        ],
        "validator": "validate_telegram_bot_token",
    },
    {
        "id": "discord_bot_token",
        "name": "Discord Bot Token",
        "regexes": [
            r"\b[MN][A-Za-z0-9\-_]{23,28}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}\b",
        ],
        "validator": "validate_discord_bot_token",
    },
    {
        "id": "npm_token",
        "name": "NPM Access Token",
        "regexes": [
            r"\bnpm_[A-Za-z0-9]{32,48}\b",
        ],
        "validator": "validate_npm_token",
    },
    # --- new providers from keyhacks ---
    {
        "id": "google_recaptcha_secret",
        "name": "Google reCAPTCHA secret key",
        "regexes": [
            r"\b6[0-9A-Za-z_-]{39}\b",
        ],
        "validator": "validate_google_recaptcha_secret",
        "needs_context": True,
    },
    {
        "id": "zapier_webhook",
        "name": "Zapier Webhook URL",
        "regexes": [
            r"https://hooks\.zapier\.com/hooks/catch/[0-9]+/[0-9A-Za-z]+/?",
        ],
        "validator": "validate_zapier_webhook",
    },
    {
        "id": "pagerduty_api_token",
        "name": "PagerDuty API token",
        "regexes": [
            r"Token token=[0-9A-Za-z]{16,40}",
        ],
        "validator": "validate_pagerduty_api_token",
    },
    {
        "id": "wpengine_api_key",
        "name": "WPEngine API Key",
        "regexes": [
            r"wpe_apikey=[0-9A-Za-z]{16,64}",
        ],
        "validator": "validate_wpengine_api_key",
        "needs_context": True,
    },
    {
        "id": "datadog_api_key",
        "name": "DataDog API key",
        "regexes": [
            r"https://api\.datadoghq\.com/api/v1/dashboard\?api_key=[0-9a-fA-F]{32}&application_key=",
        ],
        "validator": "validate_datadog_api_key",
        "needs_context": True,
    },
    {
        "id": "wakatime_api_key",
        "name": "WakaTime API Key",
        "regexes": [
            r"https://wakatime\.com/api/v1/users/current\?api_key=[0-9a-fA-F]{32}",
        ],
        "validator": "validate_wakatime_api_key",
    },
    {
        "id": "newrelic_rest_api_key",
        "name": "New Relic REST API Key",
        "regexes": [
            r"X-Api-Key:[ \t]*[0-9A-Za-z]{20,40}",
        ],
        "validator": "validate_newrelic_rest_api_key",
    },
]


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("APIKnum++: Multi-API Key Scanner")

        # Build provider objects with compiled regexes
        self._providers = []
        for pdef in PROVIDER_DEFS:
            compiled = []
            for pat in pdef["regexes"]:
                try:
                    compiled.append(re.compile(pat))
                except Exception as e:
                    callbacks.printError(
                        "Error compiling regex for provider %s: %s"
                        % (pdef["id"], str(e))
                    )
            p = {
                "id": pdef["id"],
                "name": pdef["name"],
                "validator": pdef["validator"],
                "regexes": compiled,
                "needs_context": pdef.get("needs_context", False),
            }
            self._providers.append(p)

        # cache: (provider_id, key) -> {status, detail}
        self._tested = {}
        self._lock = threading.RLock()

        callbacks.registerScannerCheck(self)
        callbacks.printOutput("[+] APIKnum++ loaded with %d providers" % len(self._providers))
        return

    # ------------- IScannerCheck methods -------------

    def doPassiveScan(self, baseRequestResponse):
        try:
            text, is_authenticated = self._extract_text_and_auth_context(baseRequestResponse)
            if not text:
                return None

            matches = self._find_provider_matches_in_text(text)
            if not matches:
                return None

            url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()

            for provider, key in matches:
                prov_id = provider["id"]
                snippet = key[:3] + "..." + key[-3:]
                with self._lock:
                    state = self._tested.get((prov_id, key))
                    if state is None:
                        self._tested[(prov_id, key)] = {"status": "pending"}
                        self._callbacks.printOutput(
                            "[APIKnum++] Passive: detected %s key (%s) at %s - scheduling validation"
                            % (prov_id, snippet, url)
                        )
                        t = threading.Thread(
                            target=self._run_provider_validation,
                            args=(provider, key, baseRequestResponse, is_authenticated),
                        )
                        t.setDaemon(True)
                        t.start()
                    else:
                        self._callbacks.printOutput(
                            "[APIKnum++] Passive: %s key (%s) at %s already seen (status=%s), skipping re-validation"
                            % (prov_id, snippet, url, state.get("status"))
                        )

            return None

        except Exception as e:
            self._callbacks.printError("Error in doPassiveScan: %s" % e)
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            text, is_authenticated = self._extract_text_and_auth_context(baseRequestResponse)
            if not text:
                return None

            matches = self._find_provider_matches_in_text(text)
            if not matches:
                return None

            issues = []
            url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()

            for provider, key in matches:
                prov_id = provider["id"]
                validator_name = provider["validator"]
                vfunc = getattr(self, validator_name, None)
                if vfunc is None:
                    continue

                snippet = key[:3] + "..." + key[-3:]

                with self._lock:
                    cache = self._tested.get((prov_id, key))

                if cache and cache.get("status") not in (None, "pending"):
                    status = cache["status"]
                    info = cache.get("detail", "")
                    self._callbacks.printOutput(
                        "[APIKnum++] Active: detected %s key (%s) at %s - reusing cached status=%s"
                        % (prov_id, snippet, url, status)
                    )
                else:
                    self._callbacks.printOutput(
                        "[APIKnum++] Active: detected %s key (%s) at %s - validating"
                        % (prov_id, snippet, url)
                    )
                    status, info = vfunc(key)
                    self._callbacks.printOutput(
                        "[APIKnum++] Active validation result %s key (%s): %s"
                        % (prov_id, snippet, status)
                    )
                    with self._lock:
                        self._tested[(prov_id, key)] = {
                            "status": status,
                            "detail": info,
                        }

                status_flag = self._status_to_flag(status, provider)
                issue = self._build_issue(provider, key, info, baseRequestResponse, is_authenticated, status_flag)
                if issue is not None:
                    issues.append(issue)

            if not issues:
                return None

            j_issues = ArrayList()
            for i in issues:
                j_issues.add(i)
            return j_issues

        except Exception as e:
            self._callbacks.printError("Error in doActiveScan: %s" % e)
            return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and \
           existingIssue.getUrl() == newIssue.getUrl():
            return -1
        return 0

    # ------------- Common scanning helpers -------------

    def _extract_text_and_auth_context(self, baseRequestResponse):
        req_bytes = baseRequestResponse.getRequest()
        req_str = self._helpers.bytesToString(req_bytes)

        resp_bytes = baseRequestResponse.getResponse()
        if resp_bytes is None:
            text = req_str
        else:
            resp_str = self._helpers.bytesToString(resp_bytes)
            text = req_str + "\n" + resp_str

        analyzed = self._helpers.analyzeRequest(baseRequestResponse)
        headers = analyzed.getHeaders()
        is_authenticated = False
        for h in headers:
            hl = h.lower()
            if hl.startswith("cookie:") or hl.startswith("authorization:"):
                is_authenticated = True
                break

        return text, is_authenticated

    def _find_provider_matches_in_text(self, text):
        matches = []
        tlower = text.lower()
        for provider in self._providers:
            ctx_keywords = provider.get("context_keywords")
            for cregex in provider["regexes"]:
                for m in cregex.finditer(text):
                    if ctx_keywords:
                        start = max(0, m.start() - 80)
                        end = min(len(text), m.end() + 80)
                        window = tlower[start:end]
                        ok = False
                        for kw in ctx_keywords:
                            if kw.lower() in window:
                                ok = True
                                break
                        if not ok:
                            continue
                    key = m.group(0)
                    matches.append((provider, key))
        return matches

    def _run_provider_validation(self, provider, key, baseRequestResponse, is_authenticated):
        prov_id = provider["id"]
        validator_name = provider["validator"]

        try:
            vfunc = getattr(self, validator_name, None)
            if vfunc is None:
                self._callbacks.printError(
                    "[APIKnum++] No validator for provider %s" % prov_id
                )
                with self._lock:
                    self._tested[(prov_id, key)] = {
                        "status": "error",
                        "detail": "validator-missing",
                    }
                return

            snippet = key[:3] + "..." + key[-3:]
            self._callbacks.printOutput(
                "[APIKnum++] Passive: validating %s key (%s)"
                % (prov_id, snippet)
            )

            status, info = vfunc(key)

            self._callbacks.printOutput(
                "[APIKnum++] Passive validation result %s key (%s): %s"
                % (prov_id, snippet, status)
            )

            with self._lock:
                self._tested[(prov_id, key)] = {
                    "status": status,
                    "detail": info,
                }

            status_flag = self._status_to_flag(status, provider)
            issue = self._build_issue(provider, key, info, baseRequestResponse, is_authenticated, status_flag)
            if issue is not None:
                self._callbacks.addScanIssue(issue)

        except Exception as e:
            self._callbacks.printError(
                "[APIKnum++] Error validating key for provider %s: %s"
                % (prov_id, e)
            )
            with self._lock:
                self._tested[(prov_id, key)] = {
                    "status": "error",
                    "detail": str(e),
                }

    def _status_to_flag(self, status, provider):
        # Normalized statuses:
        #   - invalid: not a real key / token rejected
        #   - restricted: key exists but is blocked by ACL/scope/origin/IP/referrer restrictions
        #   - unrestricted: key works from scanner environment (highest risk)
        #   - needs_context: cannot validate without extra identifiers/secrets
        #   - unknown/error: validator could not decide
        if status in ("unrestricted", "restricted", "invalid", "error", "unknown"):
            return status
        if status == "valid":
            return "unrestricted"
        if status == "unknown" and provider.get("needs_context", False):
            return "needs_context"
        return "unknown" 

    def _build_issue(self, provider, key, info, baseRequestResponse, is_authenticated, status_flag):
        analyzed = self._helpers.analyzeRequest(baseRequestResponse)
        url = analyzed.getUrl()

        snippet = key
        prov_name = provider["name"]

        if status_flag == "unrestricted":
            if is_authenticated:
                severity = "Medium"
                context = "Valid key/token confirmed from the scanner environment. It appears in an authenticated request/response."
            else:
                severity = "Medium"
                context = "Valid key/token confirmed from the scanner environment and appears in content that looks unauthenticated."
            name = "UNRESTRICTED %s (APIKnum++)" % prov_name
            validation_line = info
            confidence = "Firm"
        elif status_flag == "restricted":
            severity = "Information"
            context = (
                "Valid key/token confirmed, but provider-side restrictions (IP/origin/referrer, scopes, SSO, or ACLs) "
                "appear to block use from the scanner environment. This is still a secret exposure."
            )
            name = "RESTRICTED %s (APIKnum++)" % prov_name
            validation_line = info
            confidence = "Firm"
        elif status_flag == "needs_context":
            severity = "Information"
            context = (
                "A provider-specific identifier/secret is required to validate this credential (for example paired secrets, "
                "project/tenant configuration, or provider ACLs). Treat as potential exposure and validate manually."
            )
            name = "%s requires manual verification (APIKnum++)" % prov_name
            validation_line = info
            confidence = "Tentative"
        elif status_flag == "error":
            severity = "Information"
            context = (
                "The key was detected, but the validator encountered an error (network/provider "
                "issue). Treat this as a potential key exposure and validate manually."
            )
            name = "%s detected - validation error (APIKnum++)" % prov_name
            validation_line = info
            confidence = "Tentative"
        else:  # "unknown"
            return None

        detail = (
            "APIKnum++ identified an API credential. <br>\n"
            "<b>Provider:</b> %s<br>\n"
            "<b>Identified key:</b> %s<br>\n"
            "<b>Validation / notes:</b> %s<br>\n"
            "<b>Context:</b> %s\n"
        ) % (prov_name, snippet, validation_line, context)

        if provider["id"] == "google_api_key":
            detail += (
                "\n<br><br><b>Additional note for Google Maps JavaScript API:</b> "
                "This extension only tests the key via an HTTP API from the scanner IP. "
                "To verify browser-side referrer restrictions, create a minimal HTML page that loads "
                "https://maps.googleapis.com/maps/api/js?key=YOUR_KEY&callback=initMap "
                "from the target origin and observe whether the map loads or errors such as "
                "'RefererNotAllowedMapError' are shown in the browser console."
            )

        remediation = (
            "Rotate the leaked key and ensure it is not exposed in client-side "
            "or otherwise untrusted locations. Review provider-side access controls "
            "(IP/referrer restrictions, scopes, environment segregation) and tighten "
            "them as appropriate."
        )

        # Build markers for key occurrences in request/response
        req_bytes = baseRequestResponse.getRequest()
        resp_bytes = baseRequestResponse.getResponse()
        key_bytes = key.encode("utf-8")

        req_markers = ArrayList()
        resp_markers = ArrayList()

        if req_bytes is not None:
            self._add_markers_for_bytes(req_bytes, key_bytes, req_markers)

        if resp_bytes is not None:
            self._add_markers_for_bytes(resp_bytes, key_bytes, resp_markers)

        marked_rr = self._callbacks.applyMarkers(
            baseRequestResponse,
            req_markers if not req_markers.isEmpty() else None,
            resp_markers if not resp_markers.isEmpty() else None,
        )

        http_messages = [marked_rr]

        return APIKeyLeakIssue(
            baseRequestResponse.getHttpService(),
            url,
            http_messages,
            name,
            detail,
            remediation,
            severity,
            confidence,
        )

    def _add_markers_for_bytes(self, msg_bytes, key_bytes, marker_list, max_markers=10):
        helpers = self._helpers
        offset = 0
        count = 0
        total_len = len(msg_bytes)
        key_len = len(key_bytes)

        while count < max_markers and offset < total_len:
            idx = helpers.indexOf(msg_bytes, key_bytes, True, offset, total_len)
            if idx == -1:
                break
            marker_list.add(array('i', [idx, idx + key_len]))
            count += 1
            offset = idx + key_len

    # ------------- HTTP helper -------------

    def _http_request(self, method, url_str, headers=None, body=None):
        try:
            url = URL(url_str)
            conn = url.openConnection()
            conn.setConnectTimeout(HTTP_TIMEOUT_MS)
            conn.setReadTimeout(HTTP_TIMEOUT_MS)
            if isinstance(conn, HttpURLConnection):
                conn.setRequestMethod(method)
            if headers:
                for k, v in headers.items():
                    conn.setRequestProperty(k, v)
            if body is not None:
                conn.setDoOutput(True)
                out = conn.getOutputStream()
                out.write(body.encode("utf-8"))
                out.flush()
                out.close()
            status = conn.getResponseCode()
            try:
                stream = conn.getInputStream()
            except:
                stream = conn.getErrorStream()
            if stream is None:
                return status, ""
            import java.io as io
            reader = io.BufferedReader(io.InputStreamReader(stream, "UTF-8"))
            buf = []
            line = reader.readLine()
            while line is not None:
                buf.append(line)
                line = reader.readLine()
            stream.close()
            return status, "\n".join(buf)
        except Exception as e:
            if DEBUG:
                self._callbacks.printError("[HTTP helper] %s" % e)
            return None, None

    # ------------- Validators -------------

    def validate_slack_webhook(self, url):
        headers = {"Content-Type": "application/json"}
        body = '{"text":""}'
        status, resp_body = self._http_request("POST", url, headers, body)
        if status is None:
            return "unknown", "No response from Slack webhook"
        if "missing_text_or_fallback_or_attachments" in resp_body:
            return "unrestricted", "Slack webhook responded with missing_text_or_fallback_or_attachments (valid endpoint)"
        if status == 404 or "invalid" in resp_body.lower():
            return "invalid", "Slack webhook returned error (%d)" % status
        return "unknown", "Slack webhook response (%d) did not match expected pattern" % status

    def validate_slack_api_token(self, token):
        headers = {
            "Accept": "application/json; charset=utf-8",
            "Authorization": "Bearer " + token,
        }
        status, body = self._http_request("POST", "https://slack.com/api/auth.test", headers, "")
        if status is None:
            return "unknown", "No response from Slack API"
        bl = body.lower()
        if '"ok":true' in bl.replace(" ", "") or '"ok": true' in bl:
            return "unrestricted", "Slack auth.test returned ok=true (token accepted)"
        if "invalid_auth" in bl or "not_authed" in bl:
            return "invalid", "Slack auth.test reported invalid_auth/not_authed"
        return "unknown", "Slack auth.test HTTP %d" % status

    def validate_github_token(self, token):
        headers = {
            "Authorization": "token " + token,
            "User-Agent": "APIKnumPlusPlus",
        }
        status, body = self._http_request("GET", "https://api.github.com/user", headers, None)
        if status is None:
            return "unknown", "No response from GitHub"
        if status == 200 and '"login"' in body:
            return "unrestricted", "GitHub /user returned 200 with login field (token accepted)"
        if status == 401:
            return "invalid", "GitHub returned 401 (invalid/expired token)"
        if status in (403, 404):
            return "restricted", "GitHub returned %d (token valid but insufficient permissions / SSO / scope)" % status
        return "unknown", "GitHub /user HTTP %d" % status

    def validate_sendgrid_token(self, token):
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        }
        status, body = self._http_request("GET", "https://api.sendgrid.com/v3/scopes", headers, None)
        if status is None:
            return "unknown", "No response from SendGrid"
        if status == 200 and "scopes" in body:
            return "unrestricted", "SendGrid /v3/scopes returned scopes (token accepted)"
        if status in (401, 403):
            return "invalid", "SendGrid returned %d (unauthorized)" % status
        return "unknown", "SendGrid /v3/scopes HTTP %d" % status

    def validate_square_access_token(self, token):
        headers = {"Authorization": "Bearer " + token}
        status, body = self._http_request("GET", "https://connect.squareup.com/v2/locations", headers, None)
        if status is None:
            return "unknown", "No response from Square"
        if status == 200 and '"locations"' in body:
            return "unrestricted", "Square /v2/locations returned locations (token accepted)"
        if status == 401 or "UNAUTHORIZED" in body:
            return "invalid", "Square reported unauthorized"
        return "unknown", "Square /v2/locations HTTP %d" % status

    def validate_hubspot_hapikey(self, key):
        url = "https://api.hubapi.com/owners/v2/owners?hapikey=%s" % key
        status, body = self._http_request("GET", url, None, None)
        if status is None:
            return "unknown", "No response from HubSpot"
        bl = body.lower()
        if status == 200 and "[" in body and "ownerid" in bl:
            return "unrestricted", "HubSpot owners API returned data (hapikey accepted)"
        if status in (401, 403):
            return "invalid", "HubSpot returned %d (unauthorized)" % status
        return "unknown", "HubSpot /owners HTTP %d" % status

    def validate_infura_v3_key_from_url(self, url_with_key):
        headers = {"Content-Type": "application/json"}
        body = '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}'
        status, body_resp = self._http_request("POST", url_with_key, headers, body)
        if status is None:
            return "unknown", "No response from Infura"
        if status == 200 and '"result"' in body_resp:
            return "unrestricted", "Infura returned JSON-RPC result (key accepted)"
        if status in (401, 403):
            return "invalid", "Infura returned %d (unauthorized)" % status
        return "unknown", "Infura HTTP %d" % status

    def validate_dropbox_token(self, token):
        headers = {"Authorization": "Bearer " + token}
        status, body = self._http_request(
            "POST",
            "https://api.dropboxapi.com/2/users/get_current_account",
            headers,
            ""
        )
        if status is None:
            return "unknown", "No response from Dropbox"
        if status == 200 and '"account_id"' in body:
            return "unrestricted", "Dropbox current_account returned account_id (token accepted)"
        if status in (401, 403):
            return "invalid", "Dropbox returned %d (unauthorized)" % status
        return "unknown", "Dropbox HTTP %d" % status

    def validate_pendo_integration_key(self, key):
        headers = {
            "content-type": "application/json",
            "x-pendo-integration-key": key,
        }
        status, body = self._http_request("GET", "https://app.pendo.io/api/v1/feature", headers, None)
        if status is None:
            return "unknown", "No response from Pendo"
        if status == 200 and ("[" in body or "{" in body):
            return "unrestricted", "Pendo /api/v1/feature returned data (key accepted)"
        if status in (401, 403):
            return "invalid", "Pendo returned %d (unauthorized)" % status
        return "unknown", "Pendo HTTP %d" % status

    def validate_twilio_sid_and_token(self, sid):
        return "unknown", (
            "Twilio Account SID detected. Full validation requires pairing with the "
            "corresponding Auth Token and knowledge of account scopes / ACLs. "
            "Use Twilio/keyhacks checks and tenant context to confirm impact."
        )

    def validate_stripe_secret_key(self, sk):
        auth_bytes = ("%s:" % sk).encode("utf-8")
        auth_value = base64.b64encode(auth_bytes)
        if isinstance(auth_value, bytes):
            auth_value = auth_value.decode("ascii")
        headers = {
            "Authorization": "Basic " + auth_value,
        }
        status, body = self._http_request("GET", "https://api.stripe.com/v1/charges?limit=1", headers, None)
        if status is None:
            return "unknown", "No response from Stripe"
        if status == 200 and '"data"' in body:
            return "unrestricted", "Stripe /v1/charges returned data (secret key accepted)"
        if status in (401, 403):
            return "invalid", "Stripe returned %d (unauthorized)" % status
        return "unknown", "Stripe HTTP %d" % status

    def validate_google_api_key(self, key):
        url = "https://maps.googleapis.com/maps/api/geocode/json?address=Berlin&key=%s" % key
        status, body = self._http_request("GET", url, None, None)
        if status is None:
            return "unknown", "No response from Google Geocoding API"
        bl = body.lower()
        if status == 200 and '"error_message"' not in bl:
            return (
                "valid",
                "Google Geocoding API call succeeded from the scanner IP. "
                "The key is active and accepts requests from this environment. "
                "Referrer/IP/application restrictions must still be checked in the GCP console."
            )
        if "api keys with referer restrictions" in bl or \
           "this ip, site or mobile application is not authorized" in bl or \
           "referernotallowedmaperror" in bl:
            return (
                "restricted",
                "Google API responded with a restriction-related error. "
                "The key likely exists but is restricted by IP/referrer/origin. "
                "Manually confirm restrictions and scopes in GCP."
            )
        if "invalid api key" in bl:
            return "invalid", "Google reported 'invalid API key'."
        return (
            "unknown",
            "Google Geocoding API returned HTTP %d with error_message or error codes; manual review needed."
            % status
        )

    def validate_mailgun_private_key(self, key):
        auth_bytes = ("api:%s" % key).encode("utf-8")
        auth_value = base64.b64encode(auth_bytes)
        if isinstance(auth_value, bytes):
            auth_value = auth_value.decode("ascii")
        headers = {
            "Authorization": "Basic " + auth_value,
        }
        status, body = self._http_request("GET", "https://api.mailgun.net/v3/domains", headers, None)
        if status is None:
            return "unknown", "No response from Mailgun"
        if status == 200 and "domains" in body:
            return (
                "valid",
                "Mailgun /v3/domains returned data (key accepted). "
                "Review Mailgun key type and IP restrictions."
            )
        if status in (401, 403):
            return "invalid", "Mailgun returned %d (unauthorized)" % status
        return "unknown", "Mailgun /v3/domains HTTP %d" % status

    def validate_mailchimp_api_key(self, key):
        try:
            parts = key.split("-")
            dc = parts[1]
        except Exception:
            return "unknown", "Cannot parse Mailchimp data center from key"
        url = "https://%s.api.mailchimp.com/3.0/" % dc
        headers = {
            "Authorization": "apikey " + key,
        }
        status, body = self._http_request("GET", url, headers, None)
        if status is None:
            return "unknown", "No response from Mailchimp"
        if status == 200 and '"account_id"' in body:
            return (
                "valid",
                "Mailchimp root API returned data (API key accepted). "
                "Ensure it is not used client-side and has least privilege."
            )
        if status in (401, 403):
            return "invalid", "Mailchimp returned %d (unauthorized)" % status
        return "unknown", "Mailchimp /3.0 HTTP %d" % status

    def validate_mapbox_access_token(self, token):
        url = "https://api.mapbox.com/tokens/v2?access_token=%s" % token
        status, body = self._http_request("GET", url, None, None)
        if status is None:
            return "unknown", "No response from Mapbox"
        if status == 200 and ('"tokens"' in body or '"note"' in body):
            return (
                "valid",
                "Mapbox Tokens API accepted the token from the scanner IP. "
                "Review token scopes and allowed URLs."
            )
        if status == 401:
            return "invalid", "Mapbox returned 401 (invalid/expired token)"
        if status == 403:
            return "restricted", "Mapbox returned 403 (token lacks scopes/ACLs or is otherwise restricted)"
        return "unknown", "Mapbox tokens API HTTP %d" % status

    def validate_gitlab_pat(self, token):
        headers = {
            "Private-Token": token,
        }
        status, body = self._http_request("GET", "https://gitlab.com/api/v4/user", headers, None)
        if status is None:
            return "unknown", "No response from gitlab.com"
        if status == 200 and '"username"' in body:
            return "unrestricted", "GitLab /user returned 200 with username (token accepted)"
        if status in (401, 403):
            return "invalid", "GitLab returned %d (unauthorized)" % status
        return "unknown", "GitLab /user HTTP %d" % status

    def validate_telegram_bot_token(self, token):
        url = "https://api.telegram.org/bot%s/getMe" % token
        status, body = self._http_request("GET", url, None, None)
        if status is None:
            return "unknown", "No response from Telegram"
        bl = body.lower()
        if status == 200 and '"ok":true' in bl.replace(" ", ""):
            return "unrestricted", "Telegram getMe succeeded (bot token accepted)"
        if "unauthorized" in bl or status == 401:
            return "invalid", "Telegram reported unauthorized"
        return "unknown", "Telegram getMe HTTP %d" % status

    def validate_discord_bot_token(self, token):
        headers = {
            "Authorization": "Bot " + token,
        }
        status, body = self._http_request("GET", "https://discord.com/api/v10/users/@me", headers, None)
        if status is None:
            return "unknown", "No response from Discord"
        if status == 200 and '"id"' in body and '"username"' in body:
            return "unrestricted", "Discord /users/@me returned user info (bot token accepted)"
        if status in (401, 403):
            return "invalid", "Discord returned %d (unauthorized)" % status
        return "unknown", "Discord /users/@me HTTP %d" % status

    def validate_npm_token(self, token):
        headers = {
            "Authorization": "Bearer " + token,
        }
        status, body = self._http_request("GET", "https://registry.npmjs.org/-/whoami", headers, None)
        if status is None:
            return "unknown", "No response from NPM registry"
        if status == 200 and '"username"' in body:
            return "unrestricted", "NPM /-/whoami returned username (token accepted)"
        if status in (401, 403):
            return "invalid", "NPM returned %d (unauthorized)" % status
        return "unknown", "NPM /-/whoami HTTP %d" % status

    def validate_google_recaptcha_secret(self, key):
        """
        We cannot fully validate without a real user response.
        Test: POST secret=<key>&response=dummy. If invalid-input-secret appears,
        the secret is invalid. Otherwise we treat as unknown but existing.
        """
        body = "secret=%s&response=dummy" % key
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        status, resp = self._http_request(
            "POST",
            "https://www.google.com/recaptcha/api/siteverify",
            headers,
            body,
        )
        if status is None:
            return "unknown", "No response from Google reCAPTCHA siteverify"
        if "invalid-input-secret" in resp:
            return "invalid", "reCAPTCHA siteverify reported invalid-input-secret"
        return (
            "unknown",
            "reCAPTCHA siteverify responded, but without a real challenge response "
            "the extension cannot confirm validity; use a real response parameter as per keyhacks."
        )

    def validate_zapier_webhook(self, url):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        status, body = self._http_request(
            "POST",
            url,
            headers,
            '{"name":"apiknum"}'
        )
        if status is None:
            return "unknown", "No response from Zapier webhook URL"
        if 200 <= status < 300:
            return "unrestricted", "Zapier webhook URL responded with HTTP %d to POST JSON" % status
        if status == 404:
            return "invalid", "Zapier webhook URL returned 404"
        return "unknown", "Zapier webhook URL returned HTTP %d" % status

    def validate_pagerduty_api_token(self, header_value):
        # header_value looks like "Token token=XYZ..."
        try:
            token = header_value.split("=", 1)[1].strip()
        except Exception:
            return "unknown", "Could not extract PagerDuty token from header"
        headers = {
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Authorization": "Token token=%s" % token,
        }
        status, body = self._http_request(
            "GET",
            "https://api.pagerduty.com/schedules",
            headers,
            None,
        )
        if status is None:
            return "unknown", "No response from PagerDuty"
        if status == 200 and '"schedules"' in body:
            return "unrestricted", "PagerDuty schedules endpoint returned data (token accepted)"
        if status in (401, 403):
            return "invalid", "PagerDuty returned %d (unauthorized)" % status
        return "unknown", "PagerDuty schedules HTTP %d" % status

    def validate_wpengine_api_key(self, key_with_param):
        """
        Needs account_name context to exercise properly.
        We only flag that the WPEngine key was found.
        """
        return "unknown", (
            "WPEngine wpe_apikey parameter detected. Full validation needs account_name "
            "and the /1.2/?method=site call as per keyhacks."
        )

    def validate_datadog_api_key(self, full_url):
        """
        This pattern includes both api_key and application_key in the URL.
        Proper validation requires both and may leak dashboards; this is context-heavy.
        """
        return "unknown", (
            "DataDog api_key parameter detected in Datadog API URL. "
            "Use the dashboard or metrics endpoints with both api_key and application_key "
            "from a controlled environment to confirm scope/impact."
        )

    def validate_wakatime_api_key(self, url_with_key):
        status, body = self._http_request("GET", url_with_key, None, None)
        if status is None:
            return "unknown", "No response from WakaTime"
        if status == 200 and '"data"' in body:
            return "unrestricted", "WakaTime /users/current API returned data (api_key accepted)"
        if status in (401, 403):
            return "invalid", "WakaTime returned %d (unauthorized)" % status
        return "unknown", "WakaTime /users/current HTTP %d" % status

    def validate_newrelic_rest_api_key(self, header_line):
        # header_line looks like "X-Api-Key: ABCDEF..."
        try:
            token = header_line.split(":", 1)[1].strip()
        except Exception:
            return "unknown", "Could not extract New Relic key from header"
        headers = {
            "X-Api-Key": token,
        }
        status, body = self._http_request(
            "GET",
            "https://api.newrelic.com/v2/applications.json",
            headers,
            None,
        )
        if status is None:
            return "unknown", "No response from New Relic"
        if status == 200 and '"applications"' in body:
            return "unrestricted", "New Relic applications API returned data (key accepted)"
        if status in (401, 403):
            return "invalid", "New Relic returned %d (unauthorized)" % status
        return "unknown", "New Relic /v2/applications HTTP %d" % status


class APIKeyLeakIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages,
                 name, detail, remediation, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._remediation = remediation
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  # custom

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return (
            "Various third-party API providers issue long-lived API keys and tokens "
            "for programmatic access. If these keys are exposed in client-side code or "
            "responses, an attacker may leverage them to perform actions against the "
            "associated accounts, often with significant impact (data exfiltration, "
            "billing abuse, or service disruption)."
        )

    def getRemediationBackground(self):
        return (
            "API keys and tokens should be treated as secrets. They must not be embedded "
            "in client-side code or exposed to untrusted parties. Restrict keys by IP, "
            "referrer, or environment wherever the provider allows it, and ensure keys "
            "have only the minimal necessary privileges."
        )

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
