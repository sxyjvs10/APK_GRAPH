from apkgraph.core.engine import BaseIntelligenceModule

class DeepLinkAnalyzer(BaseIntelligenceModule):
    def analyze(self):
        manifest_xml = self.apk_data['manifest']
        deeplink_findings = {
            "schemes": set(),
            "hosts": set(),
            "app_links": False,
            "intent_filters": [],
            "adb_commands": []
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
                        
                        # Extract schemes and hosts to build adb URIs
                        schemes_here = []
                        hosts_here = []
                        for data in intent_filter.findall("data"):
                            scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                            if scheme:
                                deeplink_findings["schemes"].add(scheme)
                                schemes_here.append(scheme)
                            
                            host = data.get("{http://schemas.android.com/apk/res/android}host")
                            if host:
                                deeplink_findings["hosts"].add(host)
                                hosts_here.append(host)
                                
                        # Generate ADB exploit payloads for testing the deep links
                        if schemes_here:
                            for scheme in schemes_here:
                                host_str = hosts_here[0] if hosts_here else "example"
                                uri = f"{scheme}://{host_str}/exploit_test"
                                cmd = f'adb shell am start -W -a android.intent.action.VIEW -d "{uri}"'
                                if cmd not in deeplink_findings["adb_commands"]:
                                    deeplink_findings["adb_commands"].append(cmd)

        deeplink_findings["schemes"] = list(deeplink_findings["schemes"])
        deeplink_findings["hosts"] = list(deeplink_findings["hosts"])
        
        self.findings = deeplink_findings
        return self.findings
