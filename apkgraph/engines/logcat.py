from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_MEDIUM

class LogcatLeakageAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        analysis = self.apk_data.get("analysis")
        if not analysis:
            return findings
            
        log_methods = [
            "Landroid/util/Log;->v",
            "Landroid/util/Log;->d",
            "Landroid/util/Log;->i",
            "Landroid/util/Log;->w",
            "Landroid/util/Log;->e",
            "Ljava/io/PrintStream;->println"
        ]
        
        count = 0
        locations = []
        
        for method in analysis.get_methods():
            if method.is_external():
                continue
                
            # avoid reporting 3rd party lib logs too heavily
            if method.class_name.startswith(("Landroid/", "Landroidx/", "Lcom/google/", "Lorg/apache/")):
                continue
                
            try:
                for _, call, _ in method.get_xref_from():
                    call_desc = f"{call.class_name}->{call.name}"
                    if any(call_desc.startswith(log_m) for log_m in log_methods):
                        count += 1
                        if len(locations) < 5:
                            locations.append(f"{method.class_name}->{method.name}")
            except Exception:
                pass
                
        if count > 0:
            findings.append({
                "type": "Logcat Information Disclosure",
                "value": f"{count} logging calls found in app-specific code",
                "confidence": "High",
                "locations": locations,
                "description": "The application makes extensive use of Logcat (Log.d, Log.v, etc.) or System.out.println. Sensitive information might be leaked to the system logs, which can be read by other apps or via ADB."
            })
            
        self.findings = findings
        return self.findings
