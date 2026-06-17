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
            for keyword in self.hidden_keywords:
                if keyword in component.lower():
                    hidden_findings.append({
                        "name": component,
                        "reason": f"Keyword '{keyword}' found in component name",
                        "exported": apk.is_exported(component)
                    })

        self.findings = hidden_findings
        return self.findings
