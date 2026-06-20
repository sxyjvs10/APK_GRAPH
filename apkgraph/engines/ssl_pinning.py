"""
SSLPinningAnalyzer v2.0
------------------------
Deep code analysis for SSL/TLS pinning implementations.
Detects: OkHttp3 CertificatePinner, TrustKit, custom TrustManager, 
Network Security Config pinning, manual cert comparison, Conscrypt,
public key pinning, and WebViewClient SSL error handling.
"""
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_CRITICAL, SEVERITY_MEDIUM, SEVERITY_LOW

#  Pinning method signatures 
_PINNING_SIGS = {
    # OkHttp3
    "okhttp3/CertificatePinner": {
        "name": "OkHttp3 CertificatePinner",
        "description": "OkHttp3 CertificatePinner enforces public key or cert SHA256 pins.",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_HIGH,
        "method_hooks": ["check", "Builder.add"],
    },
    # TrustKit (Square/DataTheorem)
    "com/datatheorem/android/trustkit": {
        "name": "TrustKit (DataTheorem)",
        "description": "TrustKit enforces HPKP-style pinning with reporting.",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_HIGH,
        "method_hooks": ["PinningTrustManager.checkServerTrusted"],
    },
    # Conscrypt
    "com/android/org/conscrypt/TrustManagerImpl": {
        "name": "Conscrypt TrustManagerImpl",
        "description": "System-level TLS trust manager used by Conscrypt (default Android TLS library).",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_HIGH,
        "method_hooks": ["verifyChain"],
    },
    # Manual SHA256 comparison
    "getPublicKey": {
        "name": "Manual Public Key Pinning",
        "description": "Code manually extracts and compares certificate public key bytes.",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_HIGH,
        "method_hooks": ["getPublicKey", "getEncoded"],
    },
    # Network Security Config (XML-based)
    "NetworkSecurityConfig": {
        "name": "Network Security Config (XML)",
        "description": "res/xml/network_security_config.xml defines certificate pins.",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_HIGH,
        "method_hooks": ["PinSet"],
    },
    # WebViewClient SSL errors
    "onReceivedSslError": {
        "name": "WebView SSL Error Handling",
        "description": "onReceivedSslError() implementation detected — may proceed() or cancel().",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_MEDIUM,
        "method_hooks": ["onReceivedSslError"],
    },
    # Apache HttpClient
    "org/apache/http/conn/ssl": {
        "name": "Apache HttpClient SSL Pinning",
        "description": "Apache HttpClient SSL socket factory with custom verification.",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_MEDIUM,
        "method_hooks": ["verify"],
    },
    # Appcelerator
    "appcelerator/https": {
        "name": "Appcelerator HTTPS Pinning",
        "description": "Appcelerator framework custom pinning implementation.",
        "bypass_script": "ssl_pinning_universal.js",
        "severity": SEVERITY_MEDIUM,
        "method_hooks": ["PinningHostnameVerifier.verify"],
    },
}

# SHA-256 pin patterns in strings (hex or base64)
_SHA256_HEX_LEN  = 64
_SHA256_B64_LEN  = 44

import re
_HEX_RE  = re.compile(r'^[0-9a-fA-F]{64}$')
_B64_PIN = re.compile(r'^[A-Za-z0-9+/]{43}=$')  # base64 SHA256


class SSLPinningAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        analysis = self.apk_data["analysis"]
        raw_strings = self.apk_data.get("raw_strings", [])

        result = {
            "pinning": False,
            "implementations": [],
            "hardcoded_pins": [],
            "classes_with_pinning": [],
            "bypass_scripts": [],
            "overall_severity": SEVERITY_LOW,
        }

        detected_sigs = set()

        #  Phase 1: Class-level signature scan 
        for cls_analysis in analysis.get_classes():
            cls_name = cls_analysis.name

            for sig, info in _PINNING_SIGS.items():
                if sig in cls_name:
                    if sig not in detected_sigs:
                        detected_sigs.add(sig)
                        result["implementations"].append({
                            "name":          info["name"],
                            "description":   info["description"],
                            "class":         cls_name,
                            "bypass_script": info["bypass_script"],
                            "severity":      info["severity"],
                            "method_hooks":  info["method_hooks"],
                        })
                        if info["bypass_script"] not in result["bypass_scripts"]:
                            result["bypass_scripts"].append(info["bypass_script"])

        #  Phase 2: Method-level scan 
        for cls_analysis in analysis.get_classes():
            cls_name = cls_analysis.name
            if self.is_library(cls_name):
                continue

            for method_analysis in cls_analysis.get_methods():
                try:
                    method_obj  = method_analysis.get_method()
                    method_name = method_obj.get_name()
                except Exception:
                    continue

                # Detect custom TrustManager implementations
                if method_name in ("checkServerTrusted", "checkClientTrusted", "getAcceptedIssuers"):
                    sig_key = f"{cls_name}#TrustManager"
                    if sig_key not in detected_sigs:
                        detected_sigs.add(sig_key)
                        result["implementations"].append({
                            "name":          "Custom X509TrustManager",
                            "description":   f"Class {cls_name} implements X509TrustManager — may override cert validation.",
                            "class":         cls_name,
                            "method":        method_name,
                            "bypass_script": "ssl_pinning_universal.js",
                            "severity":      SEVERITY_HIGH,
                            "method_hooks":  [f"{cls_name.split('/')[-1]}.{method_name}"],
                        })
                        if "ssl_pinning_universal.js" not in result["bypass_scripts"]:
                            result["bypass_scripts"].append("ssl_pinning_universal.js")

                    result["classes_with_pinning"].append(f"{cls_name}->{method_name}")

                # Detect onReceivedSslError in app code
                if method_name == "onReceivedSslError" and "android/webkit/WebViewClient" not in cls_name:
                    # Check if it calls handler.proceed() (bad) or handler.cancel() (good)
                    instr_text = " ".join(
                        instr.get_output() for instr in method_obj.get_instructions()
                        if hasattr(instr, "get_output")
                    )
                    calls_proceed = "proceed" in instr_text
                    sig_key = f"{cls_name}#onReceivedSslError"
                    if sig_key not in detected_sigs:
                        detected_sigs.add(sig_key)
                        result["implementations"].append({
                            "name":          "WebViewClient.onReceivedSslError",
                            "description":   f"{'UNSAFE: calls handler.proceed() — accepts all SSL errors!' if calls_proceed else 'Safe: calls handler.cancel()'}",
                            "class":         cls_name,
                            "calls_proceed": calls_proceed,
                            "bypass_script": "ssl_pinning_universal.js",
                            "severity":      SEVERITY_CRITICAL if calls_proceed else SEVERITY_LOW,
                            "method_hooks":  [f"{cls_name.split('/')[-1]}.onReceivedSslError"],
                        })

        #  Phase 3: Hardcoded pin detection in strings 
        for s in raw_strings:
            if not s or len(s) < 40:
                continue
            if _HEX_RE.match(s.strip()):
                result["hardcoded_pins"].append({"format": "SHA256-hex", "value": s[:64]})
            elif _B64_PIN.match(s.strip()):
                result["hardcoded_pins"].append({"format": "SHA256-base64", "value": s[:44]})

        # Deduplicate pins
        seen_pins = set()
        unique_pins = []
        for p in result["hardcoded_pins"]:
            if p["value"] not in seen_pins:
                seen_pins.add(p["value"])
                unique_pins.append(p)
        result["hardcoded_pins"] = unique_pins[:20]

        #  Set overall result 
        result["pinning"] = len(result["implementations"]) > 0
        if result["implementations"]:
            severities = [i["severity"] for i in result["implementations"]]
            # Priority: Critical > High > Medium
            for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM):
                if sev in severities:
                    result["overall_severity"] = sev
                    break

        self.findings = result
        return self.findings
