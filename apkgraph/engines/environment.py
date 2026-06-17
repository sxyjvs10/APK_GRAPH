from apkgraph.core.engine import BaseIntelligenceModule
import re

class EnvironmentDiscoveryAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.env_keywords = [
            "production", "staging", "qa", "uat", "testing", 
            "internal", "sandbox", "development", "preprod"
        ]

    def analyze(self):
        analysis = self.apk_data['analysis']
        env_findings = []

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            # Check for env keywords in URLs or config strings
            for env in self.env_keywords:
                if env in string.lower():
                    # Simple heuristic: if it looks like a hostname or a config key
                    if "." in string or "_" in string:
                        env_findings.append({
                            "environment": env,
                            "value": string,
                            "confidence": "Medium"
                        })

        self.findings = env_findings
        return self.findings
