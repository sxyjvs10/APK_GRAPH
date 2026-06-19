"""
IntentHijackingAnalyzer — NEW ENGINE v2.0
------------------------------------------
Detects implicit Intents sent without explicit component targets,
which can be intercepted by malicious apps registered for the same action.

Detection approach:
1. Find Intent construction + setAction() without setComponent()/setClass().
2. Find sendBroadcast() / startActivity() calls originating from app code.
3. Flag action strings that match known sensitive system broadcasts.
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM

# Sensitive action strings that should NOT be broadcast implicitly
_SENSITIVE_ACTIONS = {
    "android.intent.action.SEND":           "Shares data via implicit intent (data theft risk)",
    "android.intent.action.VIEW":            "Opens URI via implicit intent",
    "android.intent.action.CALL":            "Makes phone call via implicit intent",
    "android.intent.action.SENDTO":          "Sends message via implicit intent",
    "android.intent.action.PICK":            "Picks content via implicit intent",
    "android.intent.action.GET_CONTENT":     "Reads file/URI via implicit intent",
    "android.intent.action.BOOT_COMPLETED":  "Registered for BOOT — check for persistence",
}

_IMPLICIT_DISPATCH_METHODS = frozenset([
    "sendBroadcast",
    "startActivity",
    "startService",
])


class IntentHijackingAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        analysis = self.apk_data["analysis"]
        findings: list[dict] = []

        # Phase 1: String-based detection of sensitive action strings in app code
        for string_analysis in analysis.get_strings():
            val = string_analysis.get_value()
            if not val:
                continue

            for action, note in _SENSITIVE_ACTIONS.items():
                if action in val:
                    # Check if used in app code (not library)
                    for _, method in string_analysis.get_xref_from():
                        try:
                            cls = method.class_name
                        except Exception:
                            continue
                        if not self.is_library(cls):
                            findings.append({
                                "type": "Sensitive Implicit Intent Action",
                                "action": action,
                                "component": cls,
                                "note": note,
                                "risk": SEVERITY_HIGH,
                            })
                            break

        # Phase 2: Instruction-level detection of implicit dispatch calls
        seen_locations: set[str] = set()
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

                location = f"{class_name}->{method_name}"
                if location in seen_locations:
                    continue

                instructions_output = []
                if getattr(method_obj, "is_external", lambda: False)():
                    continue
                try:
                    instructions = method_obj.get_instructions()
                except Exception:
                    continue
                    
                for instr in instructions:
                    try:
                        instructions_output.append(instr.get_output())
                    except Exception:
                        pass

                full_output = "\n".join(instructions_output)

                # Must use an implicit dispatch method
                uses_dispatch = any(m in full_output for m in _IMPLICIT_DISPATCH_METHODS)
                if not uses_dispatch:
                    continue

                # Implicit = no setComponent or setClass
                uses_explicit = "setComponent" in full_output or "setClass" in full_output
                if uses_explicit:
                    continue

                # Must construct an Intent (otherwise could be something else)
                if "Landroid/content/Intent" not in full_output:
                    continue

                seen_locations.add(location)
                findings.append({
                    "type": "Implicit Intent Dispatch",
                    "component": class_name,
                    "action": method_name,
                    "risk": SEVERITY_MEDIUM,
                    "note": "Intent sent without setComponent() — can be intercepted by malicious apps.",
                })

        self.findings = findings
        return self.findings
