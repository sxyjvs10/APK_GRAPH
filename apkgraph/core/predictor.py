class AttackPathPredictor:
    def __init__(self, graph):
        self.graph = graph
        self.predicted_paths = []

    def predict(self):
        """
        Predict attack paths based on relationships in the graph.
        """
        nodes = self.graph.nodes(data=True)
        
        exported_components = [n for n, d in nodes if d.get('type') == 'ExportedComponent']
        secrets = [n for n, d in nodes if d.get('type') == 'Secret']
        endpoints = [n for n, d in nodes if d.get('type') == 'Endpoint']
        deeplinks = [n for n, d in nodes if d.get('type') == 'DeepLink']
        jwts = [n for n, d in nodes if d.get('type') == 'JWT']

        # 1. Deep Link -> Exported Component (Potential Auth Bypass)
        if deeplinks and exported_components:
            self.predicted_paths.append({
                "name": "Deep Link to Exported Activity",
                "description": "A deep link might allow direct access to an exported activity, potentially bypassing authentication.",
                "steps": [deeplinks[0], exported_components[0]],
                "confidence": "High"
            })

        # 2. JWT -> Admin API (Privilege Escalation)
        admin_endpoints = [e for e in endpoints if "admin" in e.lower()]
        if jwts and admin_endpoints:
            self.predicted_paths.append({
                "name": "JWT Token to Admin API",
                "description": "A hardcoded or leaked JWT might grant access to administrative APIs.",
                "steps": [jwts[0], admin_endpoints[0]],
                "confidence": "Critical"
            })

        # 3. Secret -> Endpoint (Unauthorized Access)
        if secrets and endpoints:
            self.predicted_paths.append({
                "name": "Hardcoded Secret to Backend",
                "description": "Hardcoded secrets could be used to authenticate with backend endpoints.",
                "steps": [secrets[0], endpoints[0]],
                "confidence": "High"
            })

        return self.predicted_paths
