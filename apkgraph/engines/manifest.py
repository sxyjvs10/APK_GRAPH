from apkgraph.core.engine import BaseIntelligenceModule

class ManifestAnalyzer(BaseIntelligenceModule):
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
                manifest_findings["exported_components"].append({
                    "type": "activity", 
                    "name": activity,
                    "source": "library" if self.is_library(activity) else "app"
                })

        for service in apk.get_services():
            if self.is_exported(service):
                manifest_findings["exported_components"].append({
                    "type": "service", 
                    "name": service,
                    "source": "library" if self.is_library(service) else "app"
                })

        for receiver in apk.get_receivers():
            if self.is_exported(receiver):
                manifest_findings["exported_components"].append({
                    "type": "receiver", 
                    "name": receiver,
                    "source": "library" if self.is_library(receiver) else "app"
                })

        for provider in apk.get_providers():
            if self.is_exported(provider):
                manifest_findings["exported_components"].append({
                    "type": "provider", 
                    "name": provider,
                    "source": "library" if self.is_library(provider) else "app"
                })

        self.findings = manifest_findings
        return self.findings
