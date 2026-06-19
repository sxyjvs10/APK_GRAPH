from apkgraph.core.engine import BaseIntelligenceModule

class HiddenFunctionAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.hidden_keywords = [
            "admin", "debug", "developer", "internal", "support", "test", "qa", "config"
        ]

    def analyze(self):
        apk = self.apk_data['apk']
        hidden_findings = []

        components = apk.get_activities() + apk.get_services() + apk.get_receivers() + apk.get_providers()
        
        for component in components:
            # PRO MOVE: Skip library noise (Google, AndroidX, etc.)
            if self.is_library(component):
                continue

            # Check leaf name for keywords to avoid package-name false positives
            leaf_name = component.split('.')[-1].lower()
            for keyword in self.hidden_keywords:
                if keyword in leaf_name:
                    hidden_findings.append({
                        "name": component,
                        "reason": f"Hidden component: '{keyword}'",
                        "exported": self.is_exported(component)
                    })

        # Check raw strings for hidden API flags
        strings = self.apk_data.get('raw_strings', [])
        for string in strings:
            if len(string) < 6 or len(string) > 50:
                continue
            s_lower = string.lower()
            if s_lower.startswith("enable_") or s_lower.startswith("is_dev_") or "devmode" in s_lower or "godmode" in s_lower:
                hidden_findings.append({
                    "name": string,
                    "reason": "Hidden feature flag discovered",
                    "exported": False
                })

        self.findings = hidden_findings
        return self.findings
