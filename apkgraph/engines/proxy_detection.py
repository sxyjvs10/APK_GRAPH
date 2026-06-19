"""
ProxyDetectionAnalyzer — NEW ENGINE v1.0
-----------------------------------------
Detects proxy/VPN detection code in the APK:
1. System.getProperty("http.proxyHost") checks
2. ConnectivityManager proxy queries
3. NetworkInfo TYPE_VPN checks
4. OkHttp3 proxy configuration
5. Custom ProxySelector implementations
6. android.net.Proxy usage
7. NET_CAPABILITY_NOT_VPN checks
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

_PROXY_SIGS = {
    "http.proxyHost":               ("System proxy property check",    "ProxyDetection_SystemProperty", SEVERITY_HIGH),
    "https.proxyHost":              ("HTTPS proxy property check",     "ProxyDetection_SystemProperty", SEVERITY_HIGH),
    "getDefaultProxy":              ("ConnectivityManager proxy check", "ProxyDetection_ConnMgr",        SEVERITY_HIGH),
    "TYPE_VPN":                     ("VPN network type check",          "ProxyDetection_VPN",            SEVERITY_HIGH),
    "NET_CAPABILITY_NOT_VPN":       ("VPN capability check",            "ProxyDetection_VPN",            SEVERITY_HIGH),
    "ProxySelector":                ("Custom ProxySelector usage",      "ProxyDetection_ProxySelector",  SEVERITY_MEDIUM),
    "isConnectedToProxy":           ("Custom proxy connection check",   "ProxyDetection_Custom",         SEVERITY_MEDIUM),
    "android.net.Proxy":            ("android.net.Proxy usage",         "ProxyDetection_AndroidProxy",   SEVERITY_MEDIUM),
    "checkProxySetting":            ("Custom proxy setting check",      "ProxyDetection_Custom",         SEVERITY_MEDIUM),
    "getNetworkCapabilities":       ("Network capability VPN check",    "ProxyDetection_Capabilities",   SEVERITY_MEDIUM),
    "NetworkSecurityConfigProvider":("NSC proxy enforcement",           "ProxyDetection_NSC",            SEVERITY_LOW),
}

_IP_PROXY_RE = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}')

_VPN_METHOD_NAMES = frozenset([
    "isVpnActive", "isVpnConnected", "isUsingVpn", "detectVpn",
    "checkVpn", "isProxySet", "isProxyEnabled", "detectProxy",
    "checkProxy", "isProxyActive",
])


class ProxyDetectionAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        analysis    = self.apk_data["analysis"]
        raw_strings = self.apk_data.get("raw_strings", set())

        result = {
            "detected":        False,
            "techniques":      [],
            "custom_methods":  [],
            "bypass_scripts":  ["proxy_detection_bypass.js"],
            "hardcoded_proxy": None,
        }

        detected_cats = set()

        # ── Phase 1: Instruction scan ─────────────────────────────────────
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

                if method_name in _VPN_METHOD_NAMES:
                    entry = f"{cls_name}->{method_name}()"
                    if entry not in result["custom_methods"]:
                        result["custom_methods"].append(entry)

                try:
                    for instr in method_obj.get_instructions():
                        try:
                            out = instr.get_output()
                        except Exception:
                            continue
                        for sig, (desc, category, severity) in _PROXY_SIGS.items():
                            if sig in out and category not in detected_cats:
                                detected_cats.add(category)
                                result["techniques"].append({
                                    "technique": desc,
                                    "signature": sig,
                                    "class":     cls_name,
                                    "method":    method_name,
                                    "severity":  severity,
                                })
                except Exception:
                    pass

        # ── Phase 2: String pool scan ─────────────────────────────────────
        for s in raw_strings:
            if not s:
                continue
            for sig, (desc, category, severity) in _PROXY_SIGS.items():
                if sig in s and category not in detected_cats:
                    detected_cats.add(category)
                    result["techniques"].append({
                        "technique": desc,
                        "signature": sig,
                        "class":     "string_pool",
                        "method":    "(static string)",
                        "severity":  severity,
                    })
            if result["hardcoded_proxy"] is None and _IP_PROXY_RE.search(s):
                result["hardcoded_proxy"] = s[:100]

        result["detected"] = bool(result["techniques"] or result["custom_methods"])
        self.findings = result
        return self.findings
