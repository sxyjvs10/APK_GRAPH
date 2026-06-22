import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM

class PhantomApiAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        raw_strings = self.apk_data.get("raw_strings", [])
        
        # Regex for URLs
        url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9./?=-]*)?')
        
        phantom_keywords = ['dev', 'test', 'staging', 'uat', 'internal', 'admin', 'debug', 'v0']
        
        seen = set()
        for s in raw_strings:
            matches = url_pattern.findall(s)
            for match in matches:
                if match in seen:
                    continue
                seen.add(match)
                
                lower_match = match.lower()
                matched_keywords = [kw for kw in phantom_keywords if kw in lower_match]
                
                if matched_keywords:
                    findings.append({
                        "type": "Phantom API Endpoint",
                        "value": match,
                        "confidence": "High",
                        "locations": [],
                        "description": f"Detected undocumented or internal endpoint. Keywords found: {', '.join(matched_keywords)}"
                    })
        self.findings = findings
        return self.findings
