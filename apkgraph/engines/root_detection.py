from apkgraph.core.engine import BaseIntelligenceModule

class RootDetectionAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.root_indicators = [
            "RootBeer", "Magisk", "supersu", "busybox", "Frida", "Xposed"
        ]

    def analyze(self):
        analysis = self.apk_data['analysis']
        root_findings = {
            "detected": False,
            "indicators": []
        }

        for string_analysis in analysis.get_strings():
            string = string_analysis.get_value()
            for indicator in self.root_indicators:
                if indicator.lower() in string.lower():
                    root_findings["detected"] = True
                    if indicator not in root_findings["indicators"]:
                        root_findings["indicators"].append(indicator)

        self.findings = root_findings
        return self.findings
