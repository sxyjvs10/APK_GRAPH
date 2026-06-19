"""
CrossPlatformAnalyzer v1.0
--------------------------
Specifically targets cross-platform frameworks (React Native, Cordova, Ionic, Flutter)
to extract Javascript bundles and configurations that standard Dalvik scanners miss.
Routes extracted JS bundles through the Secret and Endpoint engines!
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

class CrossPlatformAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        result = {
            "frameworks_detected": [],
            "js_bundles_found": [],
            "secrets_found": [],
            "endpoints_found": [],
            "overall_severity": SEVERITY_LOW
        }

        apk = self.apk_data.get("apk")
        if not apk:
            self.findings = result
            return result

        # Detect React Native
        react_bundle = None
        for filename in apk.get_files():
            if "index.android.bundle" in filename:
                react_bundle = filename
                if "React Native" not in result["frameworks_detected"]:
                    result["frameworks_detected"].append("React Native")
                result["js_bundles_found"].append(filename)
                
            elif "www/" in filename and filename.endswith(".js"):
                if "Cordova/Ionic" not in result["frameworks_detected"]:
                    result["frameworks_detected"].append("Cordova/Ionic")
                result["js_bundles_found"].append(filename)

        if not result["frameworks_detected"]:
            self.findings = result
            return result

        # Extract and parse
        from apkgraph.engines.secret import _PATTERNS as SECRET_PATTERNS
        
        # Simple URL regex for JS bundles
        url_re = re.compile(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_./-]*)*")

        for js_file in result["js_bundles_found"]:
            try:
                data = apk.get_file(js_file)
                # Decode as UTF-8 ignoring errors
                text = data.decode('utf-8', errors='ignore')
                
                # 1. Search for Endpoints
                urls = url_re.findall(text)
                for u in urls:
                    if u not in result["endpoints_found"]:
                        result["endpoints_found"].append(u)
                        
                # 2. Search for Secrets
                for name, pattern, severity in SECRET_PATTERNS:
                    matches = re.findall(pattern, text)
                    for match in matches:
                        val = match if isinstance(match, str) else (match[-1] if isinstance(match, tuple) else match)
                        if len(val) > 15 and len(set(val)) >= 8:
                            # Valid entropy
                            result["secrets_found"].append({
                                "type": name,
                                "value": val[:120],
                                "bundle": js_file,
                                "severity": severity
                            })
                            if severity == SEVERITY_HIGH:
                                result["overall_severity"] = SEVERITY_HIGH
            except Exception:
                pass

        # Deduplicate secrets
        seen = set()
        uniq_sec = []
        for s in result["secrets_found"]:
            if s["value"] not in seen:
                seen.add(s["value"])
                uniq_sec.append(s)
        result["secrets_found"] = uniq_sec

        self.findings = result
        return self.findings
