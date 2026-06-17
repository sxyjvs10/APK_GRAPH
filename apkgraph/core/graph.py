import networkx as nx

class KnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_finding(self, finding_type, value, attributes=None):
        node_id = f"{finding_type}:{value}"
        self.graph.add_node(node_id, type=finding_type, value=value, **(attributes or {}))
        return node_id

    def add_relationship(self, source_id, target_id, relation_type):
        self.graph.add_edge(source_id, target_id, relation=relation_type)

    def correlate(self, all_findings):
        """
        Build the graph by correlating findings from different modules.
        """
        # Add Application node
        app_node = self.add_finding("Application", "Root")

        # Manifest
        manifest = all_findings.get("Manifest", {})
        for component in manifest.get("exported_components", []):
            comp_node = self.add_finding("ExportedComponent", component['name'], {"comp_type": component['type']})
            self.add_relationship(app_node, comp_node, "exports")

        # Secrets
        secrets = all_findings.get("Secret", [])
        for secret in secrets:
            secret_node = self.add_finding("Secret", secret['value'], {"secret_type": secret['type']})
            self.add_relationship(app_node, secret_node, "contains")

        # Endpoints
        endpoints = all_findings.get("Endpoint", {})
        for url in endpoints.get("urls", []):
            url_node = self.add_finding("Endpoint", url)
            self.add_relationship(app_node, url_node, "communicates_with")

        # Deep Links
        deeplinks = all_findings.get("DeepLink", {})
        for scheme in deeplinks.get("schemes", []):
            scheme_node = self.add_finding("DeepLink", scheme)
            self.add_relationship(app_node, scheme_node, "handles")

        # WebView
        webviews = all_findings.get("WebView", [])
        for wv in webviews:
            wv_node = self.add_finding("WebView", wv['class'], {"vulnerability": wv['vulnerability']})
            self.add_relationship(app_node, wv_node, "uses_webview")

        # JWT
        jwts = all_findings.get("JWT", [])
        for jwt in jwts:
            jwt_node = self.add_finding("JWT", jwt['token'][:20] + "...", {"payload": jwt['payload']})
            self.add_relationship(app_node, jwt_node, "uses_jwt")

        return self.graph

    def get_graph_data(self):
        return nx.node_link_data(self.graph)
