"""
NativeLibraryAnalyzer v1.0
--------------------------
Extracts and analyzes native C/C++ libraries (.so files) embedded in the APK.
Searches for hidden anti-debugging (ptrace checks), root detection techniques,
crypto libraries, and common obfuscator/packer signatures that bypass Java analysis.
"""
import re
import math
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
from apkgraph.engines.secret import _PATTERNS
from apkgraph.core.text_heuristics import is_noisy_identifier_like

_NATIVE_SIGS = {
    # Anti-Debug / Anti-Reversing
    b"ptrace":         ("Anti-Debug: ptrace() check",       "Native_AntiDebug", SEVERITY_HIGH),
    b"TracerPid":      ("Anti-Debug: TracerPid check",      "Native_AntiDebug", SEVERITY_HIGH),
    b"gdbserver":      ("Anti-Debug: gdbserver check",      "Native_AntiDebug", SEVERITY_MEDIUM),
    b"frida-agent":    ("Anti-Instrumentation: Frida check","Native_AntiHook",  SEVERITY_HIGH),
    b"gum-js-loop":    ("Anti-Instrumentation: Frida check","Native_AntiHook",  SEVERITY_HIGH),
    b"xposed":         ("Anti-Instrumentation: Xposed check","Native_AntiHook", SEVERITY_HIGH),

    # Hidden Root Detection
    b"/system/bin/su": ("Hidden Root Check: su path",       "Native_Root",      SEVERITY_HIGH),
    b"/system/xbin/su":("Hidden Root Check: su path",       "Native_Root",      SEVERITY_HIGH),
    b"magisk":         ("Hidden Root Check: Magisk",        "Native_Root",      SEVERITY_HIGH),
    b"rootbeer":       ("Native RootBeer library",          "Native_Root",      SEVERITY_HIGH),

    # Cryptography
    b"AES_set_encrypt_key": ("Crypto: OpenSSL AES",         "Native_Crypto",    SEVERITY_LOW),
    b"EVP_DecryptInit":     ("Crypto: OpenSSL EVP",         "Native_Crypto",    SEVERITY_LOW),
    b"mbedtls_aes_crypt":   ("Crypto: mbedTLS AES",         "Native_Crypto",    SEVERITY_LOW),
}

class NativeLibraryAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        apk = self.apk_data.get("apk")
        
        result = {
            "libraries_found": [],
            "total_libraries": 0,
            "signatures_detected": [],
            "high_entropy_libs": [],
            "secrets_found": [],
            "overall_severity": SEVERITY_LOW
        }

        if not apk:
            self.findings = result
            return self.findings

        # Iterate through all files in the APK
        lib_files = [f for f in apk.get_files() if f.startswith("lib/") and f.endswith(".so")]
        result["total_libraries"] = len(lib_files)

        detected_cats = set()

        for lib_path in lib_files:
            lib_name = lib_path.split("/")[-1]
            if lib_name not in result["libraries_found"]:
                result["libraries_found"].append(lib_name)
                
            try:
                # Read the binary content of the .so file
                file_data = apk.get_file(lib_path)
                
                # Check for signatures
                for sig, (desc, category, severity) in _NATIVE_SIGS.items():
                    if sig in file_data:
                        if (lib_name, category) not in detected_cats:
                            detected_cats.add((lib_name, category))
                            result["signatures_detected"].append({
                                "library": lib_name,
                                "technique": desc,
                                "severity": severity
                            })
                            if severity == SEVERITY_HIGH:
                                result["overall_severity"] = SEVERITY_HIGH
                            elif severity == SEVERITY_MEDIUM and result["overall_severity"] == SEVERITY_LOW:
                                result["overall_severity"] = SEVERITY_MEDIUM

                # Calculate Shannon entropy to detect packed/encrypted libraries
                entropy = self._calculate_entropy(file_data)
                if entropy > 7.5:  # High entropy threshold for native code
                    result["high_entropy_libs"].append({
                        "library": lib_name,
                        "entropy": round(entropy, 2),
                        "warning": "Highly compressed or packed library detected (DexGuard/Bangcle?)"
                    })
                    
                # Extract printable strings and scan for hardcoded secrets
                extracted_secrets = self._scan_for_secrets(file_data, lib_name)
                if extracted_secrets:
                    result["secrets_found"].extend(extracted_secrets)
                    result["overall_severity"] = SEVERITY_HIGH

            except Exception:
                pass

        self.findings = result
        return self.findings

    def _scan_for_secrets(self, data: bytes, lib_name: str) -> list[dict]:
        secrets = []
        seen_values = set()
        
        # Regex to extract printable ASCII strings >= 8 characters
        string_pattern = re.compile(b"[\x20-\x7E]{8,}")
        for match in string_pattern.finditer(data):
            try:
                string_val = match.group(0).decode('ascii')
            except Exception:
                continue
                
            if len(string_val) > 2000:
                continue
                
            for name, pattern, severity, use_noisy_filter, is_named in _PATTERNS:
                if is_named:
                    for m in re.finditer(pattern, string_val):
                        try:
                            val = m.group("value")
                            if val and val not in seen_values:
                                seen_values.add(val)
                                secrets.append({
                                    "library": lib_name,
                                    "type": name,
                                    "value": val[:120],
                                    "severity": severity
                                })
                        except IndexError:
                            pass
                    continue
                    
                for match_val in re.findall(pattern, string_val):
                    val = match_val if isinstance(match_val, str) else (match_val[-1] if isinstance(match_val, tuple) else match_val)
                    if not val or val in seen_values:
                        continue
                        
                    if len(val) > 15 and len(set(val)) < 8:
                        continue
                        
                    if use_noisy_filter and is_noisy_identifier_like(val):
                        continue
                        
                    seen_values.add(val)
                    secrets.append({
                        "library": lib_name,
                        "type": name,
                        "value": val[:120],
                        "severity": severity
                    })
        return secrets

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of a byte array."""
        if not data:
            return 0.0
        entropy = 0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        
        length = len(data)
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
