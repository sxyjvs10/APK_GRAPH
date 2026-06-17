from apkgraph.core.engine import BaseIntelligenceModule
import re

class CryptoAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.weak_algorithms = ["MD5", "SHA1", "DES", "3DES", "RC4"]
        self.weak_configs = ["AES/ECB", "DES/ECB"]

    def analyze(self):
        analysis = self.apk_data['analysis']
        crypto_findings = []

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            # Check for weak algorithms in strings
            for algo in self.weak_algorithms:
                if algo in string.upper():
                    crypto_findings.append({
                        "type": "Weak Algorithm",
                        "value": algo,
                        "risk": "Medium"
                    })
            
            # Check for weak configurations
            for config in self.weak_configs:
                if config in string.upper():
                    crypto_findings.append({
                        "type": "Weak Configuration",
                        "value": config,
                        "risk": "High"
                    })

        # Look for static IVs or hardcoded keys (heuristic)
        # Often represented as byte arrays or hex strings
        
        self.findings = crypto_findings
        return self.findings
