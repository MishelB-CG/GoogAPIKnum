# -*- coding: utf-8 -*-
#
# Google API Key ACL Scanner (CLI Bridge, Secure Version)
#
# Passively scans for Google API keys and invokes the external CLI tool
# WITHOUT allowing the user to specify arbitrary python commands.
#
# Python executable is auto-detected:
#   - Windows: python.exe, py
#   - Linux/macOS: python3, python
#
# Only the CLI path is user-configurable.

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.net import URL
from java.util import UUID
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from javax.swing import JPanel, JLabel, JTextField, JButton, JOptionPane
from java.io import File

import threading
import time
import subprocess
import json
import re
import sys
import os

# -----------------------
# CONFIG
# -----------------------
DEBUG = True
CLI_TIMEOUT = 180
GOOGLE_KEY_REGEX = re.compile(r"AIza[0-9A-Za-z_\-]{35}")

SETTING_CLI_PATH = "gapi-cli-path"

# ------------------------
# PYTHON DETECTION LOGIC
# ------------------------
def detect_python_executable():
    """
    Try safe python executables based on OS.
    This prevents the user from injecting arbitrary shell commands.
    """
    candidates = []

    if os.name == "nt":  # Windows
        candidates = ["python.exe", "py"]
    else:  # Linux / macOS
        candidates = ["python3", "python"]

    for exe in candidates:
        try:
            p = subprocess.Popen(
                [exe, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            p.communicate(timeout=2)
            return exe
        except:
            continue

    return None


class BurpExtender(IBurpExtender, IScannerCheck, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Google API Key ACL Scanner (CLI Bridge - Secure)")

        self._cli_path = callbacks.loadExtensionSetting(SETTING_CLI_PATH)
        if self._cli_path is None:
            self._cli_path = ""

        # detect python now
        self._python_exec = detect_python_executable()
        if not self._python_exec:
            callbacks.printError("[!] FAILED to detect Python executable on this system.")
        else:
            callbacks.printOutput("[+] Using Python executable: %s" % self._python_exec)

        # state
        self._tested_keys = {}
        self._lock = threading.RLock()

        # UI
        self._build_ui()
        callbacks.addSuiteTab(self)

        callbacks.registerScannerCheck(self)
        callbacks.printOutput("[+] Google API Key ACL Scanner loaded (Secure Version)")
        callbacks.printOutput("[+] Configure only the CLI script path in the tab.")
        return

    # ---------------- ITab ---------------- #

    def getTabCaption(self):
        return "GAPI Key Scanner"

    def getUiComponent(self):
        return self._panel

    def _build_ui(self):
        panel = JPanel()
        panel.setLayout(BorderLayout())

        inner = JPanel()
        layout = GridBagLayout()
        inner.setLayout(layout)
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0

        row = 0

        # CLI path
        gbc.gridy = row
        gbc.gridx = 0
        inner.add(JLabel("CLI script path:"), gbc)
        self._cli_field = JTextField(self._cli_path, 30)
        gbc.gridx = 1
        inner.add(self._cli_field, gbc)
        row += 1

        # Info label
        gbc.gridy = row
        gbc.gridx = 0
        gbc.gridwidth = 2
        msg = JLabel(
            "<html>Example: <code>/home/user/gapi/cli.py</code><br>"
            "Python executable is auto-detected securely.</html>"
        )
        inner.add(msg, gbc)
        gbc.gridwidth = 1
        row += 1

        # Save button
        gbc.gridy = row
        gbc.gridx = 0
        save_btn = JButton("Save settings", actionPerformed=self._on_save_clicked)
        inner.add(save_btn, gbc)
        row += 1

        self._status = JLabel(" ")
        gbc.gridy = row
        gbc.gridx = 0
        gbc.gridwidth = 2
        inner.add(self._status, gbc)
        gbc.gridwidth = 1

        panel.add(inner, BorderLayout.NORTH)
        self._panel = panel

    def _on_save_clicked(self, event):
        path = self._cli_field.getText().strip()
        if not path:
            JOptionPane.showMessageDialog(
                self._panel, "CLI script path cannot be empty.",
                "Error", JOptionPane.ERROR_MESSAGE
            )
            return

        if not File(path).exists():
            JOptionPane.showMessageDialog(
                self._panel,
                "Warning: file does not exist, saving anyway.",
                "Warning",
                JOptionPane.WARNING_MESSAGE
            )

        self._cli_path = path
        self._callbacks.saveExtensionSetting(SETTING_CLI_PATH, path)
        self._status.setText("Settings saved.")
        self._callbacks.printOutput("[+] CLI path updated: %s" % path)

    # ---------------- IScannerCheck ---------------- #

    def doPassiveScan(self, baseRequestResponse):
        try:
            req = self._helpers.bytesToString(baseRequestResponse.getRequest())
            resp = baseRequestResponse.getResponse()
            if resp:
                resp = self._helpers.bytesToString(resp)
            else:
                resp = ""

            keys = set(GOOGLE_KEY_REGEX.findall(req + resp))
            if not keys:
                return None

            if DEBUG:
                self._callbacks.printOutput("[DEBUG] Detected keys: %s" % list(keys))

            analyzed = self._helpers.analyzeRequest(baseRequestResponse)
            headers = analyzed.getHeaders()
            is_authenticated = any(
                h.lower().startswith(("cookie:", "authorization:"))
                for h in headers
            )

            for key in keys:
                with self._lock:
                    if key not in self._tested_keys:
                        self._tested_keys[key] = "in-progress"
                        t = threading.Thread(
                            target=self._background_test_key,
                            args=(key, baseRequestResponse, is_authenticated),
                        )
                        t.setDaemon(True)
                        t.start()

            return None
        except Exception as e:
            self._callbacks.printError("Error in doPassiveScan: %s" % e)
            return None

    def doActiveScan(self, *args):
        return None

    def consolidateDuplicateIssues(self, e, n):
        if e.getIssueName() == n.getIssueName() and e.getUrl() == n.getUrl():
            return -1
        return 0

    # ---------------- Main Key Test Logic ---------------- #

    def _background_test_key(self, key, baseRequestResponse, is_authenticated):
        try:
            if not self._python_exec:
                self._callbacks.printError("[!] Python executable not found.")
                return

            if not self._cli_path:
                self._callbacks.printError("[!] CLI path not configured.")
                return

            origin = "https://%s.attacker.test" % UUID.randomUUID().toString().replace("-", "")
            referer = origin + "/index.html"

            cmd = [
                self._python_exec,
                self._cli_path,
                key,
                "-O", origin,
                "-R", referer,
                "-f", "json"
            ]

            if DEBUG:
                self._callbacks.printOutput("[DEBUG] CLI command: %s" % " ".join(cmd))

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            start = time.time()
            while proc.poll() is None and (time.time() - start) < CLI_TIMEOUT:
                time.sleep(0.25)

            if proc.poll() is None:
                try:
                    proc.terminate()
                except:
                    pass
                self._callbacks.printError("[!] CLI timed out for key %s" % key[:10])
                out, err = proc.communicate()
            else:
                out, err = proc.communicate()

            out = out.decode("utf-8", "ignore")
            err = err.decode("utf-8", "ignore")

            if DEBUG and out:
                self._callbacks.printOutput("[DEBUG] stdout:\n%s" % out)
            if DEBUG and err:
                self._callbacks.printOutput("[DEBUG] stderr:\n%s" % err)

            data = self._extract_json(out)
            if not data:
                self._callbacks.printError("[!] Failed to parse CLI JSON for key %s" % key)
                return

            permissive = self._extract_permissive(data)

            if permissive:
                self._raise_issue(key, permissive, origin, referer,
                                  baseRequestResponse, is_authenticated)

            with self._lock:
                self._tested_keys[key] = data

        except Exception as e:
            self._callbacks.printError("Error in _background_test_key: %s" % e)

    # ---------------- Helpers ---------------- #

    def _extract_json(self, out):
        t = out.strip()
        if t.startswith("{") and t.endswith("}"):
            try:
                return json.loads(t)
            except:
                pass

        try:
            start = t.find("{")
            end = t.rfind("}")
            if start != -1 and end != -1:
                return json.loads(t[start:end+1])
        except:
            pass

        return None

    def _extract_permissive(self, data):
        """
        "results" must contain per-service classifications.
        """
        good = []
        results = data.get("results", [])
        for r in results:
            cls = r.get("result", "").upper()
            svc = r.get("service", "Unknown")
            if cls.startswith("ACCEPTED"):
                if not any(x in cls for x in ["BLOCKED", "ACL", "QUOTA", "NOT ENABLED"]):
                    good.append(svc)
        return good

    def _raise_issue(self, key, services, origin, referer, baseRequestResponse, is_authenticated):
        analyzed = self._helpers.analyzeRequest(baseRequestResponse)
        url = analyzed.getUrl()

        sev = "Medium" if is_authenticated else "High"

        detail = (
            "The key <b>%s...</b> was tested using the external CLI tool and the following "
            "services accepted it from Origin <code>%s</code>:\n\n%s"
        ) % (key[:10], origin, ", ".join(services))

        rem = (
            "Configure referrer/IP restrictions in Google Cloud Console and rotate this key."
        )

        issue = GoogleIssue(
            baseRequestResponse.getHttpService(),
            url,
            [baseRequestResponse],
            "Google API key with permissive access controls",
            detail,
            rem,
            sev,
            "Firm"
        )

        self._callbacks.addScanIssue(issue)
        self._callbacks.printOutput("[+] Issue raised for key %s" % key[:10])


class GoogleIssue(IScanIssue):
    def __init__(self, svc, url, msgs, name, detail, rem, sev, conf):
        self.svc = svc
        self.url = url
        self.msgs = msgs
        self.name = name
        self.detail = detail
        self.rem = rem
        self.sev = sev
        self.conf = conf

    def getUrl(self):
        return self.url

    def getIssueName(self):
        return self.name

    def getSeverity(self):
        return self.sev

    def getConfidence(self):
        return self.conf

    def getIssueDetail(self):
        return self.detail

    def getRemediationDetail(self):
        return self.rem

    def getHttpMessages(self):
        return self.msgs

    def getHttpService(self):
        return self.svc
