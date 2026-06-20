"""
RootDetectionAnalyzer v2.0
---------------------------
Deep analysis of root detection implementations.
Detects: RootBeer, file system checks, build property checks,
package queries, Runtime.exec su calls, SafetyNet, Magisk detection,
and Frida/Xposed self-detection.
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

#  Root detection signatures 
_ROOT_CLASS_SIGS = {
    "com/scottyab/rootbeer": {
        "name": "RootBeer Library",
        "description": "RootBeer is a dedicated root detection library by Scott Alexander-Bown.",
        "bypass_script": "root_detection_bypass.js",
        "severity": SEVERITY_HIGH,
    },
    "com/topjohnwu/magisk": {
        "name": "Magisk Detection (topjohnwu)",
        "description": "Checks for Magisk superuser package directly.",
        "bypass_script": "root_detection_bypass.js",
        "severity": SEVERITY_HIGH,
    },
    "com/google/android/gms/safetynet": {
        "name": "SafetyNet API",
        "description": "Google SafetyNet Attestation used to detect device integrity.",
        "bypass_script": "root_detection_bypass.js",
        "severity": SEVERITY_HIGH,
    },
    "com/google/android/play/core/integrity": {
        "name": "Play Integrity API",
        "description": "Newer replacement for SafetyNet. Harder to bypass.",
        "bypass_script": "root_detection_bypass.js",
        "severity": SEVERITY_HIGH,
    },
    "eu/chainfire/supersu": {
        "name": "SuperSU Detection",
        "description": "Checks for Chainfire SuperSU package.",
        "bypass_script": "root_detection_bypass.js",
        "severity": SEVERITY_MEDIUM,
    },
}

_SU_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/su/bin/su", "/system/su", "/data/local/xbin/su",
    "/data/local/bin/su", "/data/local/su",
    "com.noshufou.android.su", "com.thirdparty.superuser",
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.topjohnwu.magisk", "/sbin/magisk", "/data/adb/magisk",
    "/system/bin/busybox", "/system/xbin/busybox",
]

_XPOSED_FRIDA_SIGS = [
    "de.robv.android.xposed",
    "XposedBridge",
    "XposedHelpers",
    "com.saurik.substrate",
    "frida-agent",
    "gum-js-loop",
    "/data/local/tmp/frida",
    "re.frida.server",
]

_BUILD_CHECKS = [
    "test-keys",
    "ro.build.tags",
    "ro.debuggable",
    "ro.secure",
    "service.adb.root",
]

_ROOT_METHOD_NAMES = frozenset([
    "isRooted", "isDeviceRooted", "isRootAvailable",
    "checkRoot", "isRootPresent", "hasRootAccess",
    "checkForRoot", "deviceIsRooted", "isRootingDetected",
    "detectRoot", "checkSuperUser", "isMagiskPresent",
])


class RootDetectionAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        analysis   = self.apk_data["analysis"]
        raw_strings= self.apk_data.get("raw_strings", set())

        result = {
            "detected": False,
            "implementations": [],
            "indicators": [],
            "su_path_checks": [],
            "build_property_checks": [],
            "frida_xposed_detection": [],
            "custom_methods": [],
            "bypass_scripts": [],
            "safetynet": False,
            "play_integrity": False,
        }

        detected_sigs = set()

        #  Phase 1: Class-level scan 
        for cls_analysis in analysis.get_classes():
            cls_name = cls_analysis.name
            for sig, info in _ROOT_CLASS_SIGS.items():
                if sig in cls_name and sig not in detected_sigs:
                    detected_sigs.add(sig)
                    result["implementations"].append({
                        "name":          info["name"],
                        "description":   info["description"],
                        "class":         cls_name,
                        "bypass_script": info["bypass_script"],
                        "severity":      info["severity"],
                    })
                    if info["bypass_script"] not in result["bypass_scripts"]:
                        result["bypass_scripts"].append(info["bypass_script"])
                    if "safetynet" in sig:
                        result["safetynet"] = True
                    if "integrity" in sig:
                        result["play_integrity"] = True

        #  Phase 2: Method-level scan for custom root checks 
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

                if method_name in _ROOT_METHOD_NAMES:
                    entry = f"{cls_name}->{method_name}()"
                    # Extract Dalvik code for AI prompt
                    code_snippet = []
                    try:
                        for instr in method_obj.get_instructions():
                            try:
                                code_snippet.append(f"{instr.get_name()} {instr.get_output()}")
                            except Exception:
                                pass
                    except Exception:
                        pass
                    
                    code_str = "\n".join(code_snippet[:50]) # limit 50 lines to avoid massive prompt
                    
                    if not any(isinstance(m, dict) and m.get("method") == entry for m in result["custom_methods"]):
                        result["custom_methods"].append({"method": entry, "code": code_str})
                        
                    if "root_detection_bypass.js" not in result["bypass_scripts"]:
                        result["bypass_scripts"].append("root_detection_bypass.js")

                # Scan instructions for su path checks
                try:
                    for instr in method_obj.get_instructions():
                        try:
                            out = instr.get_output()
                        except Exception:
                            continue
                        for path in _SU_PATHS:
                            if path in out and path not in result["su_path_checks"]:
                                result["su_path_checks"].append(path)
                        for build_key in _BUILD_CHECKS:
                            if build_key in out and build_key not in result["build_property_checks"]:
                                result["build_property_checks"].append(build_key)
                        for frida_sig in _XPOSED_FRIDA_SIGS:
                            if frida_sig in out and frida_sig not in result["frida_xposed_detection"]:
                                result["frida_xposed_detection"].append(frida_sig)
                except Exception:
                    pass

        #  Phase 3: String pool scan 
        for s in raw_strings:
            if not s:
                continue
            for path in _SU_PATHS:
                if path in s and path not in result["su_path_checks"]:
                    result["su_path_checks"].append(path)
            for frida_sig in _XPOSED_FRIDA_SIGS:
                if frida_sig in s and frida_sig not in result["frida_xposed_detection"]:
                    result["frida_xposed_detection"].append(frida_sig)

        #  Phase 4: Build indicators from string pool 
        result["indicators"] = (
            (["RootBeer"]        if any("rootbeer" in i["name"].lower() for i in result["implementations"]) else []) +
            (["SafetyNet"]       if result["safetynet"]       else []) +
            (["Play Integrity"]  if result["play_integrity"]  else []) +
            (["Frida/Xposed"]    if result["frida_xposed_detection"] else []) +
            (["su path checks"]  if result["su_path_checks"] else []) +
            (["Build properties"]if result["build_property_checks"] else []) +
            (["Custom methods"]  if result["custom_methods"] else [])
        )

        result["detected"] = bool(
            result["implementations"] or result["custom_methods"] or
            result["su_path_checks"] or result["frida_xposed_detection"]
        )

        self.findings = result
        return self.findings
