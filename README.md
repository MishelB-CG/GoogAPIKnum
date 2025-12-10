# GoogAPIKnum
Google API Key Authorization Misconfiguration Scanner

GoogAPIKnum is a command‑line and Burp Suite–integrated tool for identifying, enumerating, and assessing the security posture of exposed Google API keys. It evaluates keys against multiple Google services and performs real JavaScript Maps API testing using Playwright to detect misconfigurations such as missing referrer restrictions.

---

## Features

- Identification of Google API keys (`AIza...`) in application traffic or source code.
- Enumeration of supported Google APIs including Maps, Places, Geocoding, Translate, YouTube Data, and others.
- Accurate Maps JavaScript API testing using a temporary local HTTP server and headless Chromium.
- Exportable output formats including JSON, CSV, and Markdown.
- Burp Suite passive-scanning extension (TBA).

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/<your-user>/GoogAPIKnum.git
cd GoogAPIKnum
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Playwright browser components
```bash
playwright install chromium
```

---

## Usage (CLI)

### Basic usage
```bash
python -m googapi_knum <API_KEY>
```

### Test with specific Origin and Referer
```bash
python -m googapi_knum <API_KEY> -O https://attacker.example -R https://attacker.example/page
```

### Export JSON/CSV/Markdown output
```bash
python -m googapi_knum <API_KEY> -f json --out results.json
python -m googapi_knum <API_KEY> -f csv  --out results.csv
python -m googapi_knum <API_KEY> -f md   --out results.md
```

---

## Burp Suite Integration

- TBA

## Security Notice

Use GoogAPIKnum **only** on systems and applications you are explicitly authorized to test.  
Misuse may violate service terms, trigger billing charges, or result in legal consequences.

---
