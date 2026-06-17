from apkgraph.core.engine import BaseIntelligenceModule

class SDKFingerprintAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.sdk_indicators = {
            "Firebase": "com/google/firebase",
            "AWS": "com/amazonaws",
            "Azure": "com/microsoft/azure",
            "OneSignal": "com/onesignal",
            "Mixpanel": "com/mixpanel",
            "Branch": "io/branch",
            "AppsFlyer": "com/appsflyer",
            "Retrofit": "retrofit2",
            "OkHttp": "okhttp3"
        }

    def analyze(self):
        analysis = self.apk_data['analysis']
        sdk_findings = []

        classes = [c.name for c in analysis.get_classes()]
        
        for name, indicator in self.sdk_indicators.items():
            for cls in classes:
                if indicator in cls:
                    if name not in sdk_findings:
                        sdk_findings.append(name)
                    break

        self.findings = sdk_findings
        return self.findings
