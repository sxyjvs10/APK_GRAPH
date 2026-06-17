import re
from apkgraph.core.engine import BaseIntelligenceModule

class SecretAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.patterns = {
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Access Key": r"([0-9a-zA-Z/+]{40})",
            "Firebase URL": r"https://.*\.firebaseio\.com",
            "Slack Token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
            "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Generic Secret": r"(?i)(secret|token|password|key|auth)([:=])(['\"]) ([^'\"]+)(['\"])",
            "JWT": r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        }

    def analyze(self):
        analysis = self.apk_data['analysis']
        secret_findings = []

        # Search in all strings found in DEX
        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            for name, pattern in self.patterns.items():
                matches = re.findall(pattern, string)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            val = match[3]
                        else:
                            val = match
                        
                        secret_findings.append({
                            "type": name,
                            "value": val,
                            "confidence": "Medium" # Simple heuristic
                        })

        self.findings = secret_findings
        return self.findings
