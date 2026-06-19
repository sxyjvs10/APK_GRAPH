"""
EndpointAnalyzer v2.0
----------------------
Fixes:
- URL regex now captures FULL URL including path + query string (was stripping them).
- Adds WebSocket (ws://, wss://) detection.
- Adds GraphQL endpoint heuristic (looks for /graphql path or operation names).
- Categorizes URLs: API endpoints, admin paths, auth endpoints, cloud storage.
- Deduplication built-in.
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM

# Full URL: scheme + host + optional port + optional path + optional query
_URL_RE = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"   # host
    r"(?::\d{1,5})?"                               # optional port
    r"(?:/[^\s'\"<>\\)]*)?",                        # optional path+query
    re.IGNORECASE,
)
_WS_RE  = re.compile(r"wss?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d{1,5})?(?:/[^\s'\"<>\\)]*)?", re.IGNORECASE)
_GQL_RE = re.compile(r"(?i)(?:/graphql|\"query\"\s*:|\"mutation\"\s*:)")

_ADMIN_KEYWORDS   = {"admin", "administrator", "superuser", "manage", "dashboard", "control"}
_AUTH_KEYWORDS    = {"login", "auth", "oauth", "token", "signin", "signup", "logout", "sso", "saml"}
_CLOUD_PATTERNS   = {
    "S3 Bucket":        re.compile(r"https?://[^/]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com"),
    "GCS Bucket":       re.compile(r"https?://storage\.googleapis\.com"),
    "Azure Blob":       re.compile(r"https?://[^/]+\.blob\.core\.windows\.net"),
    "Firebase DB":      re.compile(r"https?://[^/]+\.firebaseio\.com"),
    "Firebase Storage": re.compile(r"https?://[^/]+\.appspot\.com"),
}


def _categorize_url(url: str) -> list[str]:
    cats = []
    lower = url.lower()
    path = lower.split("?")[0]
    segments = set(path.split("/"))
    if segments & _ADMIN_KEYWORDS:
        cats.append("admin")
    if segments & _AUTH_KEYWORDS:
        cats.append("auth")
    for name, pat in _CLOUD_PATTERNS.items():
        if pat.search(url):
            cats.append(name)
    return cats


class EndpointAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        strings = self.apk_data.get("raw_strings", [])

        seen_urls: set[str] = set()
        seen_ws:   set[str] = set()
        endpoints: list[dict] = []
        graphql_detected = False

        for string in strings:
            if not string:
                continue

            # HTTP/HTTPS
            for url in _URL_RE.findall(string):
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                cats = _categorize_url(url)
                risk = SEVERITY_HIGH if ("admin" in cats or any(c in cats for c in _CLOUD_PATTERNS)) else SEVERITY_MEDIUM
                endpoints.append({
                    "url": url,
                    "categories": cats,
                    "risk": risk,
                })

            # WebSocket
            for ws in _WS_RE.findall(string):
                if ws not in seen_ws:
                    seen_ws.add(ws)

            # GraphQL
            if not graphql_detected and _GQL_RE.search(string):
                graphql_detected = True

        self.findings = {
            "urls": endpoints,
            "websockets": list(seen_ws),
            "graphql": graphql_detected,
            "stats": {
                "total_urls": len(endpoints),
                "admin_urls": sum(1 for e in endpoints if "admin" in e["categories"]),
                "auth_urls":  sum(1 for e in endpoints if "auth" in e["categories"]),
                "cloud_urls": sum(1 for e in endpoints if any(c in e["categories"] for c in _CLOUD_PATTERNS)),
            },
        }
        return self.findings
