from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_MEDIUM

class PermissionGapAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        manifest = self.apk_data.get("manifest")
        if not manifest:
            return findings
            
        requested_permissions = []
        try:
            permissions = self.apk_data.get("apk").get_permissions()
            requested_permissions = [p.split('.')[-1] for p in permissions]
        except Exception:
            pass
            
        # Hardcoded map of Permission -> required classes
        perm_map = {
            "CAMERA": ["Landroid/hardware/Camera", "Landroid/hardware/camera2"],
            "ACCESS_FINE_LOCATION": ["Landroid/location/LocationManager"],
            "READ_CONTACTS": ["Landroid/provider/ContactsContract"],
            "RECORD_AUDIO": ["Landroid/media/MediaRecorder", "Landroid/media/AudioRecord"]
        }
        
        analysis = self.apk_data.get("analysis")
        if not analysis:
            return findings
            
        used_classes = set()
        for cls in analysis.get_classes():
            used_classes.add(cls.name)
            
        for perm, required_classes in perm_map.items():
            if perm in requested_permissions:
                # Check if any required class is used
                used = False
                for req in required_classes:
                    if any(req in c for c in used_classes):
                        used = True
                        break
                if not used:
                    findings.append({
                        "type": "Phantom Permission (Supply Chain)",
                        "value": perm,
                        "confidence": "Medium",
                        "locations": ["AndroidManifest.xml"],
                        "description": f"Permission {perm} is requested but related Android APIs are never called in the bytecode. This indicates a potential supply chain payload or an over-privileged app."
                    })
                    
        self.findings = findings
        return self.findings
