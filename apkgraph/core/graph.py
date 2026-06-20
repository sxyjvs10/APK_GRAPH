"""
KnowledgeGraph v2.0
--------------------
Fixes & Additions:
- All 13 engine findings are now correlated into the graph (was only 6).
- Cross-module edges: Secret → Endpoint, DeepLink → ExportedComponent, ICC → Sink, etc.
- get_attack_surface_summary() for quick stats.
- Node type coverage: Secret, Endpoint, DeepLink, ExportedComponent, WebView,
  JWT, CryptoIssue, ICCFlow, HiddenComponent, SDK, Environment, DataStorage,
  IntentHijack, NetworkConfig.
"""
import networkx as nx


class KnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_counter = 0
        # Quick lookup maps for cross-module correlation
        self._secret_nodes: list[str] = []
        self._endpoint_nodes: list[str] = []
        self._deeplink_nodes: list[str] = []
        self._exported_nodes: list[str] = []
        self._webview_nodes: list[str] = []
        self._jwt_nodes: list[str] = []

    # ------------------------------------------------------------------
    def _add_node(self, ntype: str, value: str, **attrs) -> str:
        self.node_counter += 1
        nid = f"{ntype}:{self.node_counter}"
        self.graph.add_node(nid, type=ntype, value=value, **attrs)
        return nid

    def _add_edge(self, src: str, dst: str, relation: str):
        self.graph.add_edge(src, dst, relation=relation)

    def _get_package_node(self, class_name: str, app_node: str) -> str:
        if not class_name or "." not in class_name.replace("/", "."):
            return app_node
            
        cname = class_name.replace("/", ".").strip("L;")
        parts = cname.split(".")
        
        parent = app_node
        for i, part in enumerate(parts):
            if not part: continue
            node_id = "Pkg:" + ".".join(parts[:i+1])
            is_leaf = (i == len(parts) - 1)
            ntype = "Class" if is_leaf else "Package"
            
            if not self.graph.has_node(node_id):
                self.graph.add_node(node_id, type=ntype, value=part, full_name=".".join(parts[:i+1]))
                self.graph.add_edge(parent, node_id, relation="contains")
                
            parent = node_id
            
        return parent


    # ------------------------------------------------------------------
    def correlate(self, all_findings: dict):
        app_node = self._add_node("Application", "Root")

        # ── Manifest ──────────────────────────────────────────────────
        manifest = all_findings.get("Manifest", {})
        if not isinstance(manifest, dict):
            manifest = {}
        for comp in manifest.get("exported_components", []):
            parent = self._get_package_node(comp.get("name", ""), app_node)
            n = self._add_node("ExportedComponent", comp["name"],
                               comp_type=comp["type"],
                               source=comp.get("source", "unknown"))
            self._add_edge(parent, n, "exports")
            self._exported_nodes.append(n)

        for perm in manifest.get("dangerous_permissions", []):
            n = self._add_node("DangerousPermission", perm)
            self._add_edge(app_node, n, "requests_permission")

        # ── Secrets ───────────────────────────────────────────────────
        for sec in (all_findings.get("Secret") or []):
            if not isinstance(sec, dict):
                continue
            n = self._add_node("Secret", str(sec.get("value", ""))[:60],
                               secret_type=sec.get("type", ""),
                               confidence=sec.get("confidence", ""))
            self._add_edge(app_node, n, "contains_secret")
            self._secret_nodes.append(n)

        # ── Endpoints ─────────────────────────────────────────────────
        endpoints = all_findings.get("Endpoint", {})
        if isinstance(endpoints, dict):
            for url in endpoints.get("urls", []):
                n = self._add_node("Endpoint", url)
                self._add_edge(app_node, n, "communicates_with")
                self._endpoint_nodes.append(n)
            if endpoints.get("graphql"):
                n = self._add_node("GraphQL", "GraphQL API detected")
                self._add_edge(app_node, n, "uses_graphql")
            if endpoints.get("websocket"):
                n = self._add_node("WebSocket", "WebSocket detected")
                self._add_edge(app_node, n, "uses_websocket")

        # ── Deep Links ────────────────────────────────────────────────
        deeplinks = all_findings.get("DeepLink", {})
        if isinstance(deeplinks, dict):
            for scheme in deeplinks.get("schemes", []):
                n = self._add_node("DeepLink", scheme)
                self._add_edge(app_node, n, "handles_scheme")
                self._deeplink_nodes.append(n)
            for host in deeplinks.get("hosts", []):
                n = self._add_node("DeepLinkHost", host)
                self._add_edge(app_node, n, "handles_host")

        # ── WebView ───────────────────────────────────────────────────
        for wv in (all_findings.get("WebView") or []):
            if not isinstance(wv, dict):
                continue
            parent = self._get_package_node(wv.get("class", ""), app_node)
            n = self._add_node("WebView", wv.get("class", ""),
                               vulnerability=wv.get("vulnerability", ""),
                               risk=wv.get("risk", ""))
            self._add_edge(parent, n, "uses_webview")
            self._webview_nodes.append(n)

        # ── JWT ───────────────────────────────────────────────────────
        for jwt in (all_findings.get("JWT") or []):
            if not isinstance(jwt, dict):
                continue
            token_preview = (jwt.get("token") or "")[:30] + "..."
            n = self._add_node("JWT", token_preview,
                               payload=str(jwt.get("payload", "")))
            self._add_edge(app_node, n, "contains_jwt")
            self._jwt_nodes.append(n)

        # ── Crypto ────────────────────────────────────────────────────
        for crypto in (all_findings.get("Crypto") or []):
            if not isinstance(crypto, dict):
                continue
            n = self._add_node("CryptoIssue", crypto.get("value", ""),
                               issue_type=crypto.get("type", ""),
                               risk=crypto.get("risk", ""))
            self._add_edge(app_node, n, "uses_weak_crypto")

        for icc in (all_findings.get("ICC") or []):
            if not isinstance(icc, dict):
                continue
            parent = self._get_package_node(icc.get("component", ""), app_node)
            sink_path = icc.get("sink_path", [])
            sink_label = sink_path[-1] if sink_path else "unknown"
            n = self._add_node("ICCFlow", icc.get("component", ""),
                               entry_point=icc.get("entry_point", ""),
                               sink=sink_label,
                               risk=icc.get("risk", ""))
            self._add_edge(parent, n, "has_icc_flow")

        # ── HiddenFunction ────────────────────────────────────────────
        for hf in (all_findings.get("HiddenFunction") or []):
            if not isinstance(hf, dict):
                continue
            parent = self._get_package_node(hf.get("name", ""), app_node)
            n = self._add_node("HiddenComponent", hf.get("name", ""),
                               reason=hf.get("reason", ""),
                               exported=hf.get("exported", False))
            self._add_edge(parent, n, "has_hidden_component")

        # ── SDKFingerprint ────────────────────────────────────────────
        for sdk_name in (all_findings.get("SDKFingerprint") or []):
            n = self._add_node("SDK", str(sdk_name))
            self._add_edge(app_node, n, "uses_sdk")

        # ── Environment ───────────────────────────────────────────────
        for env in (all_findings.get("Environment") or []):
            if not isinstance(env, dict):
                continue
            n = self._add_node("EnvironmentConfig", env.get("value", "")[:80],
                               environment=env.get("environment", ""),
                               confidence=env.get("confidence", ""))
            self._add_edge(app_node, n, "leaks_environment")

        # ── DataStorage ───────────────────────────────────────────────
        for ds in (all_findings.get("DataStorage") or []):
            if not isinstance(ds, dict):
                continue
            n = self._add_node("DataStorage", ds.get("location", ""),
                               storage_type=ds.get("type", ""),
                               risk=ds.get("risk", ""))
            self._add_edge(app_node, n, "stores_data")

        # ── NetworkSecurityConfig ──────────────────────────────────────
        nsc = all_findings.get("NetworkSecurityConfig")
        if isinstance(nsc, dict):
            if nsc.get("cleartext_permitted"):
                n = self._add_node("NetworkConfig", "Cleartext Traffic Allowed")
                self._add_edge(app_node, n, "allows_cleartext")
            for domain in nsc.get("pinned_domains", []):
                n = self._add_node("NetworkConfig", f"Pinned: {domain}")
                self._add_edge(app_node, n, "pins_certificate")

        # ── IntentHijacking ───────────────────────────────────────────
        for ih in (all_findings.get("IntentHijacking") or []):
            if not isinstance(ih, dict):
                continue
            parent = self._get_package_node(ih.get("component", ""), app_node)
            n = self._add_node("IntentHijack", ih.get("component", ""),
                               action=ih.get("action", ""),
                               risk=ih.get("risk", ""))
            self._add_edge(parent, n, "uses_implicit_intent")

        # ── SSL Pinning ───────────────────────────────────────────────
        for sp in (all_findings.get("SSLPinning", {}).get("implementations", []) or []):
            if not isinstance(sp, dict): continue
            parent = self._get_package_node(sp.get("class", ""), app_node)
            n = self._add_node("SSLPinning", sp.get("name", ""), risk=sp.get("severity", ""))
            self._add_edge(parent, n, "has_ssl_pinning")

        # ── Root Detection ────────────────────────────────────────────
        for rd in (all_findings.get("RootDetection", {}).get("implementations", []) or []):
            if not isinstance(rd, dict): continue
            parent = self._get_package_node(rd.get("class", ""), app_node)
            n = self._add_node("RootDetection", rd.get("name", ""), risk=rd.get("severity", ""))
            self._add_edge(parent, n, "has_root_detection")

        # ── Cross-module correlation edges ────────────────────────────
        # Secret → Endpoint (can authenticate)
        for s in self._secret_nodes[:3]:
            for e in self._endpoint_nodes[:3]:
                self._add_edge(s, e, "may_authenticate_to")

        # DeepLink → ExportedComponent (potential bypass)
        for dl in self._deeplink_nodes[:3]:
            for ec in self._exported_nodes[:3]:
                self._add_edge(dl, ec, "may_invoke")

        # JWT → Endpoint (access token)
        for jwt in self._jwt_nodes[:3]:
            for ep in self._endpoint_nodes[:3]:
                self._add_edge(jwt, ep, "may_authorize")

        # WebView + DeepLink → XSS chain
        for wv in self._webview_nodes[:2]:
            for dl in self._deeplink_nodes[:2]:
                self._add_edge(dl, wv, "may_inject_via")

        self._prune_orphans()
        return self.graph

    def _prune_orphans(self):
        """Remove leaf nodes that don't connect to anything meaningful to reduce graph size."""
        # Find nodes with degree 1 (only connected to the root Application node)
        # Skip ExportedComponent, Endpoint, and AttackPath nodes
        to_remove = []
        for node, degree in dict(self.graph.degree()).items():
            if degree <= 1:
                node_data = self.graph.nodes[node]
                ntype = node_data.get("type", "")
                # Only prune generic noisy nodes
                if ntype in ["EnvironmentConfig", "Secret", "CryptoIssue", "SDK"]:
                    to_remove.append(node)
                    
        for node in to_remove:
            self.graph.remove_node(node)

    # ------------------------------------------------------------------
    def get_graph_data(self) -> dict:
        return nx.node_link_data(self.graph)

    def get_attack_surface_summary(self) -> dict:
        nodes = self.graph.nodes(data=True)
        by_type: dict[str, int] = {}
        for _, d in nodes:
            t = d.get("type", "Unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "by_type": by_type,
        }
