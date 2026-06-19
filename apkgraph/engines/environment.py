"""
EnvironmentDiscoveryAnalyzer v2.0
----------------------------------
Fixes:
- v1.0 matched ANY string containing env keyword + "." — massive false positive rate.
- v2.0 requires URL-like structure (http/https prefix or hostname pattern) OR
  explicit key=value config assignment.
- Added environment type classification and deduplication.
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_MEDIUM, SEVERITY_HIGH

# Must look like a URL or config assignment, not just any string with a dot
_URL_PREFIX_RE   = re.compile(r"^https?://", re.IGNORECASE)
_HOSTNAME_RE     = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_CONFIG_ASSIGN_RE = re.compile(
    r"(?i)(?:base.?url|api.?host|server.?host|endpoint|host|domain)\s*[:=]\s*['\"]?([^\s'\"]+)"
)

_ENV_KEYWORDS = {
    "production": SEVERITY_HIGH,
    "staging":    SEVERITY_MEDIUM,
    "qa":         SEVERITY_MEDIUM,
    "uat":        SEVERITY_MEDIUM,
    "testing":    SEVERITY_MEDIUM,
    "internal":   SEVERITY_MEDIUM,
    "sandbox":    SEVERITY_MEDIUM,
    "development":SEVERITY_MEDIUM,
    "preprod":    SEVERITY_HIGH,
    "prod":       SEVERITY_HIGH,
    "dev":        SEVERITY_MEDIUM,
}


class EnvironmentDiscoveryAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        strings = self.apk_data.get("raw_strings", [])
        env_findings: list[dict] = []
        seen: set[str] = set()

        for string in strings:
            if not string or len(string) > 512:
                continue

            lower = string.lower()

            # Gate 1: Must look like a URL, hostname, or config assignment
            is_url      = bool(_URL_PREFIX_RE.match(string))
            is_hostname = bool(_HOSTNAME_RE.match(string.split("/")[0]))
            is_config   = bool(_CONFIG_ASSIGN_RE.search(string))

            if not (is_url or is_hostname or is_config):
                continue

            for env_kw, severity in _ENV_KEYWORDS.items():
                if env_kw in lower and string not in seen:
                    seen.add(string)
                    env_findings.append({
                        "environment": env_kw,
                        "value": string[:200],
                        "confidence": SEVERITY_MEDIUM,
                        "risk": severity,
                        "url_like": is_url or is_hostname,
                    })
                    break

        self.findings = env_findings
        return self.findings
