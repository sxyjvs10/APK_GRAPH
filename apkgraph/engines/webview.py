from apkgraph.core.engine import BaseIntelligenceModule

class WebViewAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.webview_methods = [
            "addJavascriptInterface",
            "setAllowFileAccess",
            "setAllowUniversalAccessFromFileURLs",
            "setJavaScriptEnabled"
        ]

    def analyze(self):
        analysis = self.apk_data['analysis']
        webview_findings = []

        for method_analysis in analysis.get_methods():
            if method_analysis.is_external():
                continue
            
            method = method_analysis.get_method()
            for instr in method.get_instructions():
                output = instr.get_output()
                for web_method in self.webview_methods:
                    if web_method in output:
                        webview_findings.append({
                            "method": method.get_name(),
                            "class": method.get_class_name(),
                            "vulnerability": f"Insecure WebView Config: {web_method}",
                            "risk": "High"
                        })

        self.findings = webview_findings
        return self.findings
