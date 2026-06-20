"""
NetworkSecurityConfigAnalyzer — NEW ENGINE v2.0
-------------------------------------------------
Parses res/xml/network_security_config.xml from the APK to detect:
1. Cleartext traffic permitted (globally or per domain).
2. Missing certificate pinning.
3. User-installed CA certificates trusted (debug/production mismatch).
4. Trust anchors explicitly set to system+user CAs.
"""
import xml.etree.ElementTree as ET
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM

_NSC_PATHS = [
    "res/xml/network_security_config.xml",
    "res/xml/network-security-config.xml",
]


class NetworkSecurityConfigAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> dict:
        findings = {
            "cleartext_permitted": False,
            "cleartext_domains": [],
            "user_ca_trusted": False,
            "pinned_domains": [],
            "missing_pinning_domains": [],
            "issues": [],
        }

        # Try to read NSC from APK resources
        nsc_bytes = None
        for path in _NSC_PATHS:
            nsc_bytes = self.get_resource_bytes(path)
            if nsc_bytes:
                break

        if not nsc_bytes:
            # Also check manifest for android:usesCleartextTraffic
            findings.update(self._check_manifest_cleartext())
            self.findings = findings
            return self.findings

        try:
            root = ET.fromstring(nsc_bytes.decode("utf-8", errors="replace"))
        except ET.ParseError:
            self.findings = findings
            return self.findings

        #  Global cleartext 
        base_config = root.find("base-config")
        if base_config is not None:
            cleartext = base_config.get("cleartextTrafficPermitted", "true")
            if cleartext.lower() == "true":
                findings["cleartext_permitted"] = True
                findings["issues"].append({
                    "issue": "Global cleartext traffic permitted",
                    "risk": SEVERITY_HIGH,
                })
            # User CA trust
            for trust_anchors in base_config.findall("trust-anchors"):
                for cert in trust_anchors.findall("certificates"):
                    src = cert.get("src", "")
                    if src == "user":
                        findings["user_ca_trusted"] = True
                        findings["issues"].append({
                            "issue": "User-installed CA certificates trusted (allows MITM)",
                            "risk": SEVERITY_CRITICAL,
                        })

        #  Per-domain config 
        pinned_domains: set[str] = set()
        all_domains: list[str] = []

        for domain_config in root.findall("domain-config"):
            domain_names = [d.text for d in domain_config.findall("domain") if d.text]
            all_domains.extend(domain_names)

            cleartext = domain_config.get("cleartextTrafficPermitted", "false")
            if cleartext.lower() == "true":
                findings["cleartext_domains"].extend(domain_names)
                findings["issues"].append({
                    "issue": f"Cleartext allowed for: {', '.join(domain_names)}",
                    "risk": SEVERITY_HIGH,
                })

            # Check pinning config
            pin_set = domain_config.find("pin-set")
            if pin_set is not None:
                for d in domain_names:
                    pinned_domains.add(d)
                findings["pinned_domains"].extend(domain_names)

            # User CA trust per domain
            for trust_anchors in domain_config.findall("trust-anchors"):
                for cert in trust_anchors.findall("certificates"):
                    if cert.get("src") == "user":
                        findings["user_ca_trusted"] = True
                        findings["issues"].append({
                            "issue": f"User CA trusted for domains: {domain_names}",
                            "risk": SEVERITY_CRITICAL,
                        })

        # Domains without pinning
        findings["missing_pinning_domains"] = [
            d for d in all_domains if d not in pinned_domains
        ]

        self.findings = findings
        return self.findings

    def _check_manifest_cleartext(self) -> dict:
        """Fallback: check AndroidManifest for usesCleartextTraffic."""
        result = {"cleartext_permitted": False, "issues": []}
        try:
            manifest = self.apk_data["manifest"]
            app = manifest.find("application")
            if app is not None:
                ct = app.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic", "false")
                if ct.lower() == "true":
                    result["cleartext_permitted"] = True
                    result["issues"].append({
                        "issue": "android:usesCleartextTraffic=true in AndroidManifest",
                        "risk": SEVERITY_HIGH,
                    })
        except Exception:
            pass
        return result
