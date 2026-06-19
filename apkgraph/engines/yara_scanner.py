"""
YaraScannerAnalyzer v1.0
------------------------
Allows custom YARA rules to be applied to the APK and decompiled contents.
Looks for a 'yara_rules/' directory next to the tool and compiles any .yara files.
"""
import os
from pathlib import Path
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

class YaraScannerAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        result = {
            "matched_rules": [],
            "total_rules": 0,
            "overall_severity": SEVERITY_LOW
        }
        
        apk_path = self.apk_data.get("apk_path")
        if not apk_path:
            self.findings = result
            return self.findings

        # 1. Try to import yara
        try:
            import yara
        except ImportError:
            result["error"] = "yara-python not installed. Run: pip install yara-python"
            self.findings = result
            return self.findings

        # 2. Find rules directory
        rules_dir = None
        candidates = [
            Path(__file__).parent.parent.parent / "yara_rules",
            Path.cwd() / "yara_rules",
        ]
        for c in candidates:
            if c and c.exists():
                rules_dir = c
                break

        if not rules_dir:
            self.findings = result
            return self.findings

        # 3. Compile rules
        rule_files = {}
        for y_file in rules_dir.glob("*.yara"):
            rule_files[y_file.stem] = str(y_file)
            result["total_rules"] += 1
            
        if not rule_files:
            self.findings = result
            return self.findings
            
        try:
            compiled_rules = yara.compile(filepaths=rule_files)
        except Exception as e:
            result["error"] = f"YARA compilation error: {e}"
            self.findings = result
            return self.findings

        # 4. Scan APK file directly (which is a ZIP)
        try:
            matches = compiled_rules.match(apk_path)
            for m in matches:
                # Severity can be defined in rule meta, default to High
                severity = m.meta.get("severity", SEVERITY_HIGH)
                desc = m.meta.get("description", "YARA Rule Match")
                
                result["matched_rules"].append({
                    "rule": m.rule,
                    "description": desc,
                    "tags": m.tags,
                    "severity": severity,
                    "strings_matched": [str(s[2]) for s in m.strings[:3]] # First 3 strings
                })
                
                if severity == SEVERITY_HIGH:
                    result["overall_severity"] = SEVERITY_HIGH
                elif severity == SEVERITY_MEDIUM and result["overall_severity"] == SEVERITY_LOW:
                    result["overall_severity"] = SEVERITY_MEDIUM
        except Exception:
            pass

        self.findings = result
        return self.findings
