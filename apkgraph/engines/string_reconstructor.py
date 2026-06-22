import re
import base64
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH

class StringReconstructorAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        raw_strings = self.apk_data.get("raw_strings", [])
        
        seen = set()
        for s in raw_strings:
            # Check for base64 encoded secrets
            if len(s) > 16 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', s):
                try:
                    decoded = base64.b64decode(s).decode('utf-8')
                    if len(decoded) > 8 and decoded.isprintable():
                        if decoded not in seen:
                            seen.add(decoded)
                            # Flag if it looks like a key or highly entropic
                            if re.search(r'(?i)(key|token|secret|password|auth|bearer)', decoded) or len(set(decoded)) > 12:
                                findings.append({
                                    "type": "Obfuscated Secret Recovered",
                                    "value": f"Base64: {s} -> {decoded[:50]}",
                                    "confidence": "High",
                                    "locations": [],
                                    "description": "Recovered a base64 obfuscated string that appears to be a hidden secret, token, or URL."
                                })
                except Exception:
                    pass
        self.findings = findings
        return self.findings
