# GoogAPIKnum
**Google API Key Authorization Misconfiguration Scanner**

GoogAPIKnum is a command‑line tool for enumerating authorization controls of Google API keys. It evaluates keys against multiple Google services, including dynamic analysis for the Google Maps JavaScript API to detect misconfigurations.

---

## Features

- Enumeration of supported Google APIs, including Maps, Places, Geocoding, Translate, YouTube Data, and others.
- Accurate Maps JavaScript API testing using a temporary local HTTP server and headless Chromium.
- Exportable output formats include JSON, CSV, and TXT.
- Burp Suite passive-scanning extension (TBA).
- Identification of Google API keys (`AIza...`) in application traffic or source code (TBA).

---

## Installation


### Clone the repository
```bash
git clone https://github.com/MishelB-CG/GoogAPIKnum.git
cd GoogAPIKnum
```

### Automated installation using pip (recommended)
1. Install GoogAPIKnum in editable mode and automatically register the entry-point script:

```bash
pip install -e .
```

2. After installation, you can run the tool with:

```bash
googapi-knum <API_KEY>
```

### Manual Installation
1. Install Python dependencies

```bash
pip install -r requirements.txt
```

*GoogAPIKnum will check during the first execution whether Playwright and the Chromium browser are installed.
If missing, it will prompt you or attempt to install automatically.*

2. You may also install the Chromium browser manually using the `playwright` CLI:

```bash
playwright install chromium
```

---

## Usage (CLI)

### Basic usage
```bash
python -m googapi-knum <API_KEY>
```

### Test with specific Origin and Referer
```bash
python -m googapi-knum <API_KEY> -O https://attacker.example -R https://attacker.example/page
```

### Export JSON/CSV/TXT output
```bash
python -m googapi-knum <API_KEY> -f json --out results.json
python -m googapi-knum <API_KEY> -f csv  --out results.csv
python -m googapi-knum <API_KEY> -f text --out results.txt
```

---


# APIKnum++ - Multi-provider API Key Scanner Extension for Burp Suite

APIKnum++ is a Burp Suite extension (Jython) that passively and actively scans HTTP traffic for API keys and tokens, validates them against their upstream providers where possible, and reports potential exposures directly in Burp.

Some key identification and validation patterns used in the extension are based on the [streeak/keyhacks](https://github.com/streaak/keyhacks) repository, extended and adapted for Burp.

## Features

- Passive scanning
  - Inspects requests and responses for known API key/token formats.
  - Triggers background validation requests for newly discovered keys.
  - Highlights the exact locations of keys using Burp markers.
  - Logs all findings to the Burp Extender Output tab.

- Active scanning
  - Reuses cached validation results where available.
  - Performs synchronous validation during active scanning.
  - Generates issues for valid, invalid, and manually-verifiable keys.

- Validation
  - Performs safe provider-specific HTTP calls inspired by keyhacks validation examples.
  - Distinguishes valid, invalid, unknown, and context-dependent API keys.
  - Caches results per (provider, key) pair to avoid repeated checks.

- Multi-provider support
  - Includes many popular API providers (Google, GitHub, Slack, Stripe, Mailgun, Dropbox, etc.).
  - Designed for easy addition of new providers.

## Installation

1. Download the extension file [APIKnum++.py](https://raw.githubusercontent.com/MishelB-CG/GoogAPIKnum/refs/heads/main/Burpsuite%20APIKnum%2B%2B/APIKnum%2B%2B.py).
2. Install Jython standalone [jython-standalone](https://central.sonatype.com/artifact/org.python/jython-standalone/versions).
3. In Burp Suite:
   - Go to Extender → Options → Python Environment.
   - Set the path to the Jython JAR.
4. Load the extension:
   - Extender → Extensions → Add → Select the .py file.
5. Verify successful loading in Extender → Output.

## Usage

### Passive Scanner

APIKnum++ passively analyzes every request and response passing through Burp.  
When it detects an API key:

- It logs the finding to Burp's output.
- It performs background validation (unless already cached).
- It raises an issue summarizing what was identified.

### Active Scanner

During Active Scans:

- Keys are rechecked against the cache.
- Missing or unknown keys are validated synchronously.
- Issues are raised in the same format as passive scanning.

### Output Logging

The extension logs:

- Key discovery
- Validation attempts
- Validation results
- Cache usage

Example:

```
[APIKnum++] Passive: detected github_token key (ghp...abc) - scheduling validation
[APIKnum++] Passive validation result github_token key (ghp...abc): valid
[APIKnum++] Active: detected google_api_key key (AIz...xyz) - reusing cached status=valid
```

## How It Works

Each provider entry contains:

- `id`: internal name
- `name`: human-readable name
- `regexes`: list of regex patterns to detect keys
- `validator`: method name to perform validation
- `needs_context`: optional flag for keys requiring additional context

Validators return:

- `"valid"`
- `"invalid"`
- `"unknown"`
- `"error"`

Issues always show:

- Provider name
- Key snippet
- Validation result
- Context & interpretation
- Remediation guidance

## Limitations

- Validation depends on the Burp machine's network environment.
- Some providers require additional contextual data (project ID, origin restrictions, etc.).
- Browser-only API checks (e.g., Google Maps JS API referrer restrictions) cannot be validated fully.
- Extension avoids destructive operations — only safe metadata queries are used.

## Contributing / Adding New Providers

### Provider Definition Format

```
{
    "id": "example_provider",
    "name": "Example Provider API Key",
    "regexes": [
        r"EXAMPLE-[0-9A-Za-z]{32}"
    ],
    "validator": "validate_example_provider",
    "needs_context": true  # optional
}
```

### Validator Function Format

```
def validate_example_provider(self, key):
    headers = {"Authorization": "Bearer " + key}
    status, body = self._http_request("GET", "https://api.example.com/v1/me", headers, None)
    if status == 200:
        return "valid", "Example API accepted the key"
    if status in (401, 403):
        return "invalid", "Unauthorized"
    return "unknown", "Unexpected status"
```

Guidelines:

- Keep calls safe and nondestructive.
- Try minimal endpoints (`/me`, `/verify`, `/metadata`).
- Document what your validator checks.

## Security Notice

Use GoogAPIKnum and APIKnum++ **only** on systems and applications you are explicitly authorized to test.  
Misuse may violate service terms, trigger billing charges, or result in legal consequences.
