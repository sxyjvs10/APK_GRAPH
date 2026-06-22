from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH

class SignatureAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        findings = []
        apk = self.apk_data.get("apk")
        if not apk:
            return findings
            
        try:
            is_v1 = apk.is_signed_v1()
            is_v2 = apk.is_signed_v2()
            is_v3 = apk.is_signed_v3()
            
            if is_v1 and not is_v2 and not is_v3:
                findings.append({
                    "type": "Insecure Signature (v1 Only)",
                    "value": "v1 signature detected",
                    "confidence": "High",
                    "locations": ["META-INF/"],
                    "description": "The APK is signed using only the obsolete v1 signature scheme. It is vulnerable to the Janus vulnerability (CVE-2017-13156) and tampering."
                })
                
            certs = apk.get_certificates()
            for cert in certs:
                issuer = getattr(cert.issuer, 'human_friendly', str(cert.issuer))
                subject = getattr(cert.subject, 'human_friendly', str(cert.subject))
                if "Android Debug" in issuer or "Android Debug" in subject:
                    findings.append({
                        "type": "Debug Certificate Used",
                        "value": issuer,
                        "confidence": "High",
                        "locations": ["META-INF/CERT.RSA"],
                        "description": "The APK is signed with a known Android Debug certificate. This should never be deployed to production."
                    })
        except Exception:
            pass
                
        self.findings = findings
        return self.findings
