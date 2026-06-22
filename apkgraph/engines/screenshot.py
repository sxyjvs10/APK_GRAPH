from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_MEDIUM

class ScreenshotAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        analysis = self.apk_data.get("analysis")
        if not analysis:
            return findings
            
        set_flags_called = False
        for method in analysis.get_methods():
            if method.is_external():
                continue
            try:
                for _, call, _ in method.get_xref_from():
                    if "Landroid/view/Window;->setFlags" in f"{call.class_name}->{call.name}":
                        set_flags_called = True
                        break
            except Exception:
                pass
            if set_flags_called:
                break
                
        if not set_flags_called:
            findings.append({
                "type": "Screenshot & Screen Recording Allowed",
                "value": "FLAG_SECURE not detected",
                "confidence": "Medium",
                "locations": [],
                "description": "The application does not appear to use WindowManager.LayoutParams.FLAG_SECURE. This allows users or background malware to take screenshots or record the screen while sensitive data is displayed."
            })
            
        self.findings = findings
        return self.findings
