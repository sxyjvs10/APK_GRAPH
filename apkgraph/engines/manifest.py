from apkgraph.core.engine import BaseIntelligenceModule
from lxml import etree

class ManifestAnalyzer(BaseIntelligenceModule):
    def is_exported(self, component_name):
        """Helper to check if a component is exported in the manifest."""
        manifest_xml = self.apk_data['manifest']
        # The manifest is an lxml Element
        # Components can be under <application>
        for application in manifest_xml.findall("application"):
            for component_tag in ["activity", "service", "receiver", "provider"]:
                for component in application.findall(component_tag):
                    # In Android, name can be shorthand like .MainActivity or full name
                    name = component.get("{http://schemas.android.com/apk/res/android}name")
                    if name == component_name or self._normalize_name(name) == component_name:
                        exported = component.get("{http://schemas.android.com/apk/res/android}exported")
                        if exported:
                            return exported.lower() == "true"
                        
                        # If not explicitly set, exported is true if there's an intent-filter
                        intent_filters = component.findall("intent-filter")
                        return len(intent_filters) > 0
        return False

    def _normalize_name(self, name):
        if not name: return ""
        if name.startswith("."):
            return self.apk_data['package'] + name
        return name

    def analyze(self):
        apk = self.apk_data['apk']
        
        manifest_findings = {
            "exported_components": [],
            "dangerous_permissions": [],
            "custom_permissions": [],
            "intent_filters": []
        }

        # Analyze Permissions
        permissions = apk.get_permissions()
        # get_details_permissions returns a dict with permission info
        details = apk.get_details_permissions()
        for perm in permissions:
            if perm in details:
                if "dangerous" in details[perm][0].lower():
                    manifest_findings["dangerous_permissions"].append(perm)
            if not perm.startswith("android.permission"):
                manifest_findings["custom_permissions"].append(perm)

        # Analyze Exported Components
        for activity in apk.get_activities():
            if self.is_exported(activity):
                manifest_findings["exported_components"].append({"type": "activity", "name": activity})

        for service in apk.get_services():
            if self.is_exported(service):
                manifest_findings["exported_components"].append({"type": "service", "name": service})

        for receiver in apk.get_receivers():
            if self.is_exported(receiver):
                manifest_findings["exported_components"].append({"type": "receiver", "name": receiver})

        for provider in apk.get_providers():
            if self.is_exported(provider):
                manifest_findings["exported_components"].append({"type": "provider", "name": provider})

        self.findings = manifest_findings
        return self.findings
