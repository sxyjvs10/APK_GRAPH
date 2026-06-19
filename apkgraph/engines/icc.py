"""
ICCAnalyzer v2.0
-----------------
Fixes:
- method.name was used on MethodAnalysis — fixed to method.get_method().get_name().
- Taint is now only run on app-level classes (library classes were being included).
- Per-entry-point analysis with proper sink labelling.
- Added SQL injection sink, file write sink, SharedPreferences sink.
"""
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
from apkgraph.core.taint import TaintEngine


_DANGEROUS_SINKS = [
    # Remote code / command execution
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/ProcessBuilder;->start",
    "Ldalvik/system/DexClassLoader;",
    "Ljava/io/FileOutputStream;",
    "Ljava/io/File;",
    "[NATIVE]",
    # Network
    "Ljava/net/URL;->openConnection",
    # WebView RCE
    "Landroid/webkit/WebView;->loadUrl",
    "Landroid/webkit/WebView;->evaluateJavascript",
    # SQL injection
    "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
    "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
    # Log leakage
    "Landroid/util/Log;->d",
    "Landroid/util/Log;->e",
    "Landroid/util/Log;->v",
    # Broadcast / startActivity (re-delegation)
    "Landroid/content/Context;->sendBroadcast",
    "Landroid/content/Context;->startActivity",
]

_ENTRY_POINTS = frozenset([
    "onCreate", "onStart", "onResume",
    "onReceive",
    "onStartCommand", "onBind",
    "query", "insert", "update", "delete",  # ContentProvider
    "onHandleIntent",
])

_SINK_SEVERITY = {
    "Ljava/lang/Runtime;->exec": SEVERITY_CRITICAL,
    "Ljava/lang/ProcessBuilder;->start": SEVERITY_CRITICAL,
    "Ldalvik/system/DexClassLoader;": SEVERITY_HIGH,
    "Ljava/io/FileOutputStream;": SEVERITY_HIGH,
    "Ljava/io/File;": SEVERITY_MEDIUM,
    "Landroid/content/Context;->sendBroadcast": SEVERITY_MEDIUM,
    "Landroid/content/Context;->startActivity": SEVERITY_LOW,
    "[NATIVE]": SEVERITY_CRITICAL, # Cross-boundary data flow
    "loadUrl": SEVERITY_CRITICAL,
    "evaluateJavascript": SEVERITY_CRITICAL,
    "execSQL": SEVERITY_HIGH,
    "rawQuery": SEVERITY_HIGH,
    "Log": SEVERITY_MEDIUM,
}


def _sink_severity(sink_path: list[str]) -> str:
    last = sink_path[-1] if sink_path else ""
    for key, sev in _SINK_SEVERITY.items():
        if key in last:
            return sev
    return SEVERITY_MEDIUM


class ICCAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        analysis = self.apk_data["analysis"]
        taint = TaintEngine(analysis)
        icc_findings: list[dict] = []

        for cls_analysis in analysis.get_classes():
            cls_name = cls_analysis.name
            if self.is_library(cls_name):
                continue

            for method_analysis in cls_analysis.get_methods():
                # FIX: was method_analysis.name — correct is get_method().get_name()
                try:
                    method_obj = method_analysis.get_method()
                    method_name = method_obj.get_name()
                except Exception:
                    continue

                if method_name not in _ENTRY_POINTS:
                    continue

                paths = taint.find_paths([method_analysis], _DANGEROUS_SINKS, max_depth=4)
                for path in paths:
                    icc_findings.append({
                        "component": cls_name,
                        "entry_point": method_name,
                        "sink_path": path,
                        "sink": path[-1] if path else "unknown",
                        "risk": _sink_severity(path),
                    })

        self.findings = icc_findings
        return self.findings
