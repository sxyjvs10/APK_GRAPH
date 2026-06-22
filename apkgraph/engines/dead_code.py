from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_LOW

class DeadCodeAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        analysis = self.apk_data.get("analysis")
        if not analysis:
            return findings
            
        # simple heuristic: methods with 0 xrefs to them, not starting with standard lifecycle names
        lifecycle_prefixes = ("on", "init", "<init>", "<clinit>", "get", "set", "call")
        
        count = 0
        for method in analysis.get_methods():
            if method.is_external():
                continue
                
            try:
                xrefs_to = method.get_xref_to()
                if len(xrefs_to) == 0:
                    name = method.name
                    if not name.startswith(lifecycle_prefixes):
                        if "Landroid" not in method.class_name and "Ljava" not in method.class_name:
                            # Likely dead code / orphaned
                            count += 1
            except Exception:
                pass
                
        if count > 0:
            findings.append({
                "type": "Dead/Hidden Code Resurrection",
                "value": f"{count} orphaned methods found",
                "confidence": "Low",
                "locations": [],
                "description": "Detected methods that have no cross-references calling them. These may be hidden features, backdoors, or leftover debug code that can be executed dynamically."
            })
            
        self.findings = findings
        return self.findings
