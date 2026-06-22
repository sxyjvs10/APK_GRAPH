"""
FridaHookAnalyzer v1.0
-----------------------
Analyzes Frida scripts in the frida_scripts/ directory to identify which
Java classes they hook via Java.use(). It then scans the current APK to 
detect if the targeted classes actually exist in the compiled code.

This allows the tool to "understand how the hooking works and where the 
hooking is done" by correlating Frida script targets with the actual APK binary.
"""
import os
import re
import glob
from pathlib import Path
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

_JAVA_USE_RE = re.compile(r'Java\.use\([\'"]([^\'"]+)[\'"]\)')

def _is_app_specific_class(cls_name: str) -> bool:
    """Returns True if the class is likely app-specific or a non-standard 3rd party library, not a core Android/Java library."""
    core_prefixes = (
        "java.", "javax.", "android.", "androidx.", "dalvik.", "libcore.", "sun.", 
        "org.apache.", "org.json.", "org.xml.", "org.w3c.", "com.android.", "kotlin.", "kotlinx."
    )
    return not cls_name.startswith(core_prefixes)

class FridaHookAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        analysis = self.apk_data["analysis"]
        
        # 1. Get all available classes in the APK
        # Androguard class names are like Lcom/example/App;, we need them like com.example.App
        apk_classes = set()
        for cls_analysis in analysis.get_classes():
            name = cls_analysis.name
            if name.startswith("L") and name.endswith(";"):
                name = name[1:-1].replace("/", ".")
            apk_classes.add(name)

        # 2. Find frida scripts directory
        scripts_dir = None
        candidates = [
            Path(__file__).parent.parent.parent / "frida_scripts",
            Path.cwd() / "frida_scripts",
        ]
        for c in candidates:
            if c and c.exists():
                scripts_dir = c
                break

        result = {
            "hooked_scripts_matched": [],
            "total_scripts_analyzed": 0,
            "overall_severity": SEVERITY_LOW
        }

        if not scripts_dir:
            self.findings = result
            return self.findings

        # 3. Analyze each script for Java.use and match against APK classes
        matched_scripts = []
        for js_file in scripts_dir.glob("*.js"):
            result["total_scripts_analyzed"] += 1
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                uses = set(_JAVA_USE_RE.findall(content))
                
                if not uses:
                    continue
                
                # Check which classes are in the APK
                matched_classes = []
                app_specific_matches = []
                
                for cls in uses:
                    # Frida syntax often matches exactly the Java syntax (com.example.App)
                    if cls in apk_classes:
                        # ONLY count non-core classes as a 'verified match' to avoid universally false positives
                        if _is_app_specific_class(cls):
                            matched_classes.append(cls)
                
                if matched_classes:
                    severity = SEVERITY_HIGH
                    
                    matched_scripts.append({
                        "script_name": js_file.name,
                        "script_content": content,
                        "total_targets": len(uses),
                        "matched_targets": len(matched_classes),
                        "confidence": "High",
                        "classes_found_in_apk": matched_classes,
                        "severity": severity
                    })
                    
                    result["overall_severity"] = SEVERITY_HIGH
                        
            except Exception:
                pass

        # Sort by confidence and number of matches
        matched_scripts.sort(key=lambda x: (x["confidence"] == "High", x["matched_targets"]), reverse=True)
        result["hooked_scripts_matched"] = matched_scripts

        self.findings = result
        return self.findings
