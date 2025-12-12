# APIKnum++ - Multi-provider API Key Scanner for Burp Suite

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

- Follow keyhacks examples when available.
- Keep calls safe and nondestructive.
- Try minimal endpoints (`/me`, `/verify`, `/metadata`).
- Document what your validator checks.

## License

Provided for authorized security testing only.
