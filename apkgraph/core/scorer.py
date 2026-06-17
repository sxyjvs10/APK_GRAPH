class RiskScorer:
    def __init__(self, findings, paths):
        self.findings = findings
        self.paths = paths
        self.score = 0
        self.rating = "Low"

    def calculate(self):
        """
        Formula:
        Risk = Attack Surface Exposure + Sensitive Assets + Authentication Weaknesses + ...
        """
        # Simple scoring logic
        manifest = self.findings.get("Manifest", {})
        secrets = self.findings.get("Secret", [])
        
        exposure_score = len(manifest.get("exported_components", [])) * 5
        secret_score = len(secrets) * 10
        path_score = len(self.paths) * 15

        self.score = min(exposure_score + secret_score + path_score, 100)

        if self.score > 75:
            self.rating = "Critical"
        elif self.score > 50:
            self.rating = "High"
        elif self.score > 25:
            self.rating = "Medium"
        else:
            self.rating = "Low"

        return {"score": self.score, "rating": self.rating}
