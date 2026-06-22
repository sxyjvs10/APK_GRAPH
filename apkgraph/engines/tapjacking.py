from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_LOW

class TapjackingAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        raw_strings = self.apk_data.get("raw_strings", [])
        
        found_protection = False
        for s in raw_strings:
            if "filterTouchesWhenObscured" in s:
                found_protection = True
                break
                
        if not found_protection:
            findings.append({
                "type": "Tapjacking Vulnerability",
                "value": "filterTouchesWhenObscured not found",
                "confidence": "Low",
                "locations": ["res/layout/"],
                "description": "The application does not appear to use the 'filterTouchesWhenObscured' attribute in its layouts. Malicious applications could draw transparent overlays on top of this app to trick users into clicking buttons (Tapjacking)."
            })
            
        self.findings = findings
        return self.findings
