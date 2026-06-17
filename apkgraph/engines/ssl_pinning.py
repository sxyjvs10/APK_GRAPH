from apkgraph.core.engine import BaseIntelligenceModule

class SSLPinningAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.pinning_indicators = {
            "CertificatePinner": "OkHttp",
            "TrustKit": "TrustKit",
            "Conscrypt": "Conscrypt",
            "Network Security Config": "Android Native"
        }

    def analyze(self):
        analysis = self.apk_data['analysis']
        pinning_findings = {
            "pinning": False,
            "frameworks": []
        }

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            for indicator, framework in self.pinning_indicators.items():
                if indicator in string:
                    pinning_findings["pinning"] = True
                    if framework not in pinning_findings["frameworks"]:
                        pinning_findings["frameworks"].append(framework)

        self.findings = pinning_findings
        return self.findings
