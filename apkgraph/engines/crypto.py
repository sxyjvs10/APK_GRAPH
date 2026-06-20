from apkgraph.core.engine import BaseIntelligenceModule
from apkgraph.core.taint import TaintEngine
from apkgraph.core.text_heuristics import shannon_entropy, _is_structural_noise

class CryptoAnalyzer(BaseIntelligenceModule):
    def __init__(self, apk_data):
        super().__init__(apk_data)
        self.weak_algorithms = ["MD5", "SHA1", "DES", "3DES", "RC4"]
        self.crypto_sinks = [
            "Ljavax/crypto/Cipher;->getInstance",
            "Ljavax/crypto/spec/SecretKeySpec;-><init>",
            "Ljavax/crypto/spec/IvParameterSpec;-><init>",
            "Ljava/security/MessageDigest;->getInstance"
        ]

    def analyze(self):
        analysis = self.apk_data['analysis']
        taint = TaintEngine(analysis)
        crypto_findings = []

        # 1. Check for weak algorithm strings
        strings = self.apk_data.get('raw_strings', [])
        for string in strings:
            # Skip short generic strings and common Android class names
            if len(string) < 3 or string.startswith("Landroid") or string.startswith("Ljava"):
                continue
                
            for algo in self.weak_algorithms:
                if f" {algo} " in f" {string.upper()} ":
                    # Filter out generic exception messages
                    if "exception" in string.lower() or "error" in string.lower():
                        continue
                    crypto_findings.append({
                        "type": "Weak Algorithm String",
                        "value": algo,
                        "context": string,
                        "risk": "Low"  # Downgraded: presence of string does not mean usage
                    })

        # 2. PRO MOVE: Taint Analysis for Key Material
        # Check if high-entropy strings (potential keys) flow into crypto sinks
        for string_analysis in analysis.get_strings():
            val = string_analysis.get_value()
            if len(val) < 16 or len(val) > 256: continue
            
            # Use robust text heuristics to eliminate false positives
            if _is_structural_noise(val) or shannon_entropy(val) < 3.8:
                continue
                
            # If this looks like a genuine high-entropy secret, trace it!
            for _, method in string_analysis.get_xref_from():
                if self.is_library(method.class_name): continue
                
                # Trace flow from method using string to crypto sink
                paths = taint.find_paths([method], self.crypto_sinks, max_depth=3)
                if paths:
                    crypto_findings.append({
                        "type": "Hardcoded Key Material in Crypto Sink",
                        "value": val[:16] + "...",
                        "usage_method": f"{method.class_name}->{method.name}",
                        "sink_path": paths[0],
                        "risk": "Critical"
                    })

        self.findings = crypto_findings
        return self.findings
