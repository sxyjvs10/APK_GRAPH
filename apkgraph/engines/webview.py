"""
WebViewAnalyzer v2.0
---------------------
Additions:
- Detects loadUrl() with http:// (not just config methods).
- Detects evaluateJavascript() — potential XSS injection point.
- Deduplication per (class, vulnerability) pair.
- Severity classification: addJavascriptInterface = Critical, file access = High, JS = Medium.
"""
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM

_WEBVIEW_SIGS = {
    "addJavascriptInterface":                ("Insecure JS Interface (potential RCE)",    SEVERITY_CRITICAL),
    "setAllowUniversalAccessFromFileURLs":    ("Universal File Access Enabled (UXSS)",     SEVERITY_CRITICAL),
    "setAllowFileAccess":                     ("File Access Enabled",                      SEVERITY_HIGH),
    "setAllowFileAccessFromFileURLs":         ("File URL Cross-Origin Access",             SEVERITY_HIGH),
    "setJavaScriptEnabled":                   ("JavaScript Enabled",                       SEVERITY_MEDIUM),
    "evaluateJavascript":                     ("evaluateJavascript() — XSS injection pt",  SEVERITY_HIGH),
}

# loadUrl with http:// scheme is also a finding
_LOAD_URL_HTTP_PATTERN = "loadUrl"


class WebViewAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        analysis = self.apk_data["analysis"]
        webview_findings: list[dict] = []
        seen: set[tuple] = set()

        for method_analysis in analysis.get_methods():
            if method_analysis.is_external():
                continue
            try:
                method_obj = method_analysis.get_method()
                class_name = method_obj.get_class_name()
                method_name = method_obj.get_name()
            except Exception:
                continue

            if self.is_library(class_name):
                continue

            for instr in method_obj.get_instructions():
                try:
                    output = instr.get_output()
                except Exception:
                    continue

                for sig, (desc, severity) in _WEBVIEW_SIGS.items():
                    key = (class_name, sig)
                    if sig in output and key not in seen:
                        seen.add(key)
                        webview_findings.append({
                            "class": class_name,
                            "method": method_name,
                            "vulnerability": f"{sig}: {desc}",
                            "risk": severity,
                        })

                # loadUrl with http:// check
                if _LOAD_URL_HTTP_PATTERN in output and "http://" in output:
                    key = (class_name, "loadUrl_http")
                    if key not in seen:
                        seen.add(key)
                        webview_findings.append({
                            "class": class_name,
                            "method": method_name,
                            "vulnerability": "loadUrl() with cleartext HTTP",
                            "risk": SEVERITY_HIGH,
                        })

        self.findings = webview_findings
        return self.findings
