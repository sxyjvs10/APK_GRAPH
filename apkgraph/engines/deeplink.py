from apkgraph.core.engine import BaseIntelligenceModule

class DeepLinkAnalyzer(BaseIntelligenceModule):
    def analyze(self):
        manifest_xml = self.apk_data['manifest']
        deeplink_findings = {
            "schemes": set(),
            "hosts": set(),
            "app_links": False,
            "intent_filters": []
        }

        # XML namespace for Android
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        # Find all data tags in intent-filters
        for application in manifest_xml.findall("application"):
            for component_tag in ["activity", "service", "receiver"]:
                for component in application.findall(component_tag):
                    for intent_filter in component.findall("intent-filter"):
                        # Check for autoVerify (App Links)
                        auto_verify = intent_filter.get("{http://schemas.android.com/apk/res/android}autoVerify")
                        if auto_verify == "true":
                            deeplink_findings["app_links"] = True
                        
                        # Extract schemes and hosts
                        for data in intent_filter.findall("data"):
                            scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                            if scheme:
                                deeplink_findings["schemes"].add(scheme)
                            
                            host = data.get("{http://schemas.android.com/apk/res/android}host")
                            if host:
                                deeplink_findings["hosts"].add(host)

        deeplink_findings["schemes"] = list(deeplink_findings["schemes"])
        deeplink_findings["hosts"] = list(deeplink_findings["hosts"])
        
        self.findings = deeplink_findings
        return self.findings
