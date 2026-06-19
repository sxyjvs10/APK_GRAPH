"""
SecretAnalyzer v2.0
--------------------
Additions:
- Expanded pattern set: GitHub token, Twilio, SendGrid, PEM private key,
  Generic Bearer token, Hardcoded password field, Base64-encoded creds.
- Confidence levels: Critical/High/Medium based on pattern specificity.
- Deduplication: same value reported only once (keeps first location).
- Secret category tagging for graph/report grouping.
"""
import re
import base64
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM
from apkgraph.core.text_heuristics import MAX_STRING_LEN, is_noisy_identifier_like

# Each entry: (name, pattern, confidence, severity, use_noisy_filter, use_named_group)
_PATTERNS: list[tuple] = [
    # ── Cloud / Infrastructure ───────────────────────────────────────
    ("Google API Key",       r"AIza[0-9A-Za-z\-_]{35}",                             SEVERITY_CRITICAL, False, False),
    ("AWS Access Key ID",    r"AKIA[0-9A-Z]{16}",                                   SEVERITY_CRITICAL, False, False),
    ("AWS Secret Access Key",r"([0-9a-zA-Z/+]{40})",                                SEVERITY_HIGH,     True,  False),
    ("Firebase URL",         r"https://[a-zA-Z0-9-]+\.firebaseio\.com",              SEVERITY_HIGH,     False, False),
    ("Firebase App ID",      r"1:\d{12}:android:[0-9a-f]{16,}",                     SEVERITY_MEDIUM,   False, False),

    # ── Auth Tokens ──────────────────────────────────────────────────
    ("Slack Token",          r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}", SEVERITY_CRITICAL, False, False),
    ("GitHub Token",         r"ghp_[0-9A-Za-z]{36}",                               SEVERITY_CRITICAL, False, False),
    ("GitHub OAuth Token",   r"gho_[0-9A-Za-z]{36}",                               SEVERITY_CRITICAL, False, False),

    # ── Payment ──────────────────────────────────────────────────────
    ("Stripe Live Key",      r"sk_live_[0-9a-zA-Z]{24}",                            SEVERITY_CRITICAL, False, False),
    ("Stripe Test Key",      r"sk_test_[0-9a-zA-Z]{24}",                            SEVERITY_MEDIUM,   False, False),

    # ── Communication ────────────────────────────────────────────────
    ("Twilio Auth Token",    r"SK[0-9a-fA-F]{32}",                                 SEVERITY_CRITICAL, False, False),
    ("Mailgun API Key",      r"key-[0-9a-zA-Z]{32}",                               SEVERITY_HIGH,     False, False),
    ("SendGrid API Key",     r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",       SEVERITY_CRITICAL, False, False),

    # ── Cryptographic Material ───────────────────────────────────────
    ("PEM Private Key",      r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",  SEVERITY_CRITICAL, False, False),

    # ── JWT ──────────────────────────────────────────────────────────
    ("JWT",                  r"ey[A-Za-z0-9\-_=]+\.ey[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", SEVERITY_HIGH, False, False),

    # ── Generic patterns (named group — processed separately) ────────
    ("Generic Secret",
     r"(?i)(?P<keyword>secret|token|password|passwd|pwd|apikey|api_key|auth)\s*(?P<sep>[:=])\s*(?P<quote>['\"])(?P<value>[^'\"]{4,})(?P=quote)",
     SEVERITY_MEDIUM, False, True),

    ("Bearer Token",
     r"(?i)Bearer\s+(?P<value>[A-Za-z0-9\-_\.]{20,})",
     SEVERITY_HIGH, False, True),
]


class SecretAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        analysis = self.apk_data["analysis"]
        secret_findings: list[dict] = []
        seen_values: set[str] = set()

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            if not string or len(string) > MAX_STRING_LEN:
                continue

            locations = None  # lazy
            
            strings_to_test = [(string, False)]
            # If the string looks like valid Base64 and is reasonably long, try decoding it
            if len(string) >= 12 and len(string) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', string):
                try:
                    dec_bytes = base64.b64decode(string, validate=True)
                    dec_str = dec_bytes.decode('utf-8')
                    if dec_str.isprintable():
                        strings_to_test.append((dec_str, True))
                except Exception:
                    pass

            for test_str, is_b64_decoded in strings_to_test:
                for name, pattern, severity, use_noisy_filter, is_named in _PATTERNS:
                    if is_named:
                        for m in re.finditer(pattern, test_str):
                            try:
                                val = m.group("value")
                            except IndexError:
                                continue
                            if not val or val in seen_values:
                                continue
                            seen_values.add(val)
                            if locations is None:
                                locations = self._locations_for(string_analysis)
                            secret_findings.append({
                                "type": name + (" (Base64 Decoded)" if is_b64_decoded else ""),
                                "value": val[:120],
                                "confidence": severity,
                                "locations": locations,
                            })
                        continue

                matches = re.findall(pattern, test_str)
                if not matches:
                    continue

                for match in matches:
                    val = match if isinstance(match, str) else (match[-1] if isinstance(match, tuple) else match)
                    if not val or val in seen_values:
                        continue

                    # Entropy check to filter out non-random strings like names/labels
                    if len(val) > 15 and len(set(val)) < 8:
                        continue # Low entropy string

                    if use_noisy_filter and is_noisy_identifier_like(val):
                        continue

                    # Strict library and Dalvik class filtering
                    if self.is_library(val) or val.startswith("Landroid/") or val.startswith("Lcom/google") or val.startswith("Ljava"):
                        continue
                    
                    # Filter out any string that looks like a Dalvik class descriptor (e.g., Lcom/github/ybq...)
                    # This prevents class names that are exactly 40 chars from triggering the AWS Secret regex.
                    if val.startswith("L") and "/" in val and val.count("/") >= 2:
                        continue
                        
                    # Filter standard Android keywords
                    if val.lower() in ("password", "secret", "token", "key", "auth"):
                        continue

                    seen_values.add(val)
                    if locations is None:
                        locations = self._locations_for(string_analysis)
                    secret_findings.append({
                        "type": name + (" (Base64 Decoded)" if is_b64_decoded else ""),
                        "value": val[:120],
                        "confidence": severity,
                        "locations": locations or [],
                    })

        self.findings = secret_findings
        return self.findings

    @staticmethod
    def _locations_for(string_analysis) -> list[str]:
        locations = []
        try:
            for _, method in string_analysis.get_xref_from():
                try:
                    locations.append(f"{method.class_name}->{method.name}{method.descriptor}")
                except Exception:
                    continue
        except Exception:
            pass
        return locations
