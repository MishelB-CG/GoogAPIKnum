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
git clone https://github.com/<your-user>/GoogAPIKnum.git
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

## Burp Suite Integration

- TBA

## Security Notice

Use GoogAPIKnum **only** on systems and applications you are explicitly authorized to test.  
Misuse may violate service terms, trigger billing charges, or result in legal consequences.
