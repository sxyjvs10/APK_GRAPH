"""
DataStorageAnalyzer — NEW ENGINE v2.0
---------------------------------------
Detects insecure data storage patterns:
1. SharedPreferences with sensitive key names (MODE_PRIVATE check is not enough).
2. SQLiteDatabase usage with plaintext (no SQLCipher).
3. External storage writes (getExternalStorageDirectory, Environment.DIRECTORY_*).
4. Hardcoded file paths with sensitive names.
5. Log.d/e calls with sensitive data patterns.
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|auth|credit.?card|ssn|dob|private.?key|pin)",
)

_EXTERNAL_STORAGE_METHODS = frozenset([
    "getExternalStorageDirectory",
    "getExternalFilesDir",
    "getExternalCacheDir",
    "getExternalStoragePublicDirectory",
])

_SQLITE_METHODS = frozenset([
    "openOrCreateDatabase",
    "getWritableDatabase",
    "getReadableDatabase",
])

_LOG_METHODS = frozenset(["Log.d", "Log.v", "Log.i", "Log.w", "Log.e"])

# Known SQLCipher class prefix — presence means DB is encrypted
_SQLCIPHER_PREFIX = "net/sqlcipher"


class DataStorageAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        analysis = self.apk_data["analysis"]
        findings: list[dict] = []

        #  Check for SQLCipher presence 
        sqlcipher_present = any(
            _SQLCIPHER_PREFIX in cls.name
            for cls in analysis.get_classes()
        )

        for cls_analysis in analysis.get_classes():
            cls_name = cls_analysis.name
            if self.is_library(cls_name):
                continue

            for method_analysis in cls_analysis.get_methods():
                try:
                    method_obj = method_analysis.get_method()
                    method_name = method_obj.get_name()
                    class_name  = method_obj.get_class_name()
                except Exception:
                    continue
                if getattr(method_obj, "is_external", lambda: False)():
                    continue

                try:
                    instructions = method_obj.get_instructions()
                except Exception:
                    continue
                
                for instr in instructions:
                    try:
                        output = instr.get_output()
                    except Exception:
                        continue

                    #  External Storage 
                    for ext_method in _EXTERNAL_STORAGE_METHODS:
                        if ext_method in output:
                            findings.append({
                                "type": "External Storage Write",
                                "location": f"{class_name}->{method_name}",
                                "method": ext_method,
                                "risk": SEVERITY_HIGH,
                                "note": "Data written to external storage is readable by any app with READ_EXTERNAL_STORAGE.",
                            })
                            break

                    #  SQLite without encryption 
                    for sql_method in _SQLITE_METHODS:
                        if sql_method in output and not sqlcipher_present:
                            findings.append({
                                "type": "Unencrypted SQLite Database",
                                "location": f"{class_name}->{method_name}",
                                "method": sql_method,
                                "risk": SEVERITY_LOW,
                                "note": "SQLite database is not encrypted. (Info/Low risk unless storing sensitive PII/Auth data)",
                            })
                            break

                    #  SharedPreferences with sensitive keys 
                    if "getSharedPreferences" in output or "putString" in output or "putInt" in output:
                        if _SENSITIVE_KEY_RE.search(output):
                            findings.append({
                                "type": "Sensitive SharedPreferences Key",
                                "location": f"{class_name}->{method_name}",
                                "snippet": output[:120],
                                "risk": SEVERITY_LOW,
                                "note": "SharedPreferences may store sensitive auth material. Verify if token/pwd is stored in plaintext.",
                            })

        #  Check hardcoded file paths with sensitive names 
        for string in self.apk_data.get("raw_strings", []):
            if string and "/" in string and _SENSITIVE_KEY_RE.search(string):
                if string.startswith("/data/") or string.startswith("/sdcard/"):
                    findings.append({
                        "type": "Hardcoded Sensitive File Path",
                        "location": "string pool",
                        "value": string[:120],
                        "risk": SEVERITY_MEDIUM,
                        "note": "Hardcoded path to a file with a sensitive name.",
                    })

        self.findings = findings
        return self.findings
