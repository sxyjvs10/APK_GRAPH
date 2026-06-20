"""
DeobfuscationAnalyzer v1.0
---------------------------
Detects string encryption/obfuscation routines (XOR loops, Base64 wrappers, AES wrappers)
and attempts to statically identify the methods responsible for decrypting strings at runtime.
This allows analysts to know exactly which methods to hook with Frida to dump all hidden strings.
"""
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

class DeobfuscationAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        analysis = self.apk_data.get("analysis")
        if not analysis:
            self.findings = {"detected_methods": [], "overall_severity": SEVERITY_LOW}
            return self.findings

        result = {
            "detected_methods": [],
            "overall_severity": SEVERITY_LOW
        }

        # Signatures of obfuscation
        # 1. Heavily using XOR operations returning String
        # 2. Base64 + Cipher.doFinal
        for cls_analysis in analysis.get_classes():
            cls_name = cls_analysis.name
            
            # Skip obvious standard libraries to reduce noise
            if self.is_library(cls_name):
                continue
                
            for method_analysis in cls_analysis.get_methods():
                try:
                    method_obj = method_analysis.get_method()
                    method_name = method_obj.get_name()
                    descriptor = method_obj.get_descriptor()
                    
                    # We are looking for routines that return a String
                    if not descriptor.endswith(")Ljava/lang/String;"):
                        continue
                        
                    # Get instructions
                    instructions = [i.get_name() for i in method_obj.get_instructions()]
                    
                    # Heuristic 1: XOR based string decryption (DexGuard, custom packers)
                    # Often uses xor-int, xor-int/lit8, etc. in a loop
                    xor_count = sum(1 for inst in instructions if 'xor' in inst)
                    
                    # Heuristic 2: AES/DES Crypto (javax/crypto/Cipher)
                    has_cipher = any("Ljavax/crypto/Cipher;->doFinal" in (getattr(i, 'get_output', lambda: '')() or '') for i in method_obj.get_instructions())
                    
                    # Heuristic 3: Stack-based string building using byte arrays
                    has_fill_array = any("fill-array-data" in inst for inst in instructions)
                    
                    is_suspicious = False
                    reason = ""
                    severity = SEVERITY_LOW
                    
                    if xor_count >= 3 and has_fill_array:
                        is_suspicious = True
                        reason = f"XOR-based string decryption routine detected (XOR count: {xor_count})"
                        severity = SEVERITY_HIGH
                    elif has_cipher and has_fill_array:
                        is_suspicious = True
                        reason = "AES/Crypto-based string decryption with hardcoded byte arrays"
                        severity = SEVERITY_HIGH
                    elif xor_count >= 5:
                        is_suspicious = True
                        reason = f"Heavy XOR operations in string returning method (XOR count: {xor_count})"
                        severity = SEVERITY_MEDIUM
                        
                    if is_suspicious:
                        # Find xrefs to see where this decryption routine is used
                        xrefs_from = len(list(method_analysis.get_xref_to()))  # get_xref_to() gives where this method is called FROM
                        
                        # Build a proper dynamic Frida hook for String Decryption
                        # Convert Lcom/app/Utils; to com.app.Utils
                        clean_class = cls_name.strip("L").replace("/", ".").strip(";")
                        
                        hook_script = f"""Java.perform(function() {{
    var TargetClass = Java.use("{clean_class}");
    var overloads = TargetClass.{method_name}.overloads;
    for (var i = 0; i < overloads.length; i++) {{
        overloads[i].implementation = function() {{
            var decryptedStr = this.{method_name}.apply(this, arguments);
            console.log("[+] Decrypted String from {clean_class}.{method_name}: " + decryptedStr);
            return decryptedStr;
        }};
    }}
}});"""

                        result["detected_methods"].append({
                            "class": cls_name,
                            "method": f"{method_name}{descriptor}",
                            "reason": reason,
                            "xref_count": xrefs_from,
                            "severity": severity,
                            "frida_hook": hook_script
                        })
                        
                        if severity == SEVERITY_HIGH:
                            result["overall_severity"] = SEVERITY_HIGH
                        elif severity == SEVERITY_MEDIUM and result["overall_severity"] == SEVERITY_LOW:
                            result["overall_severity"] = SEVERITY_MEDIUM
                            
                except Exception:
                    pass

        self.findings = result
        return self.findings
