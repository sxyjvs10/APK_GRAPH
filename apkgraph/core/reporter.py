"""
ReportGenerator v3.0 — Full Threat & Reproduction Report
----------------------------------------------------------
- JSON: structured, includes reproduction steps per finding
- Markdown: per-threat sections with PoC and remediation
- HTML: professional single-file pentest report with:
    - Executive summary
    - Risk gauge + stat cards
    - Per-finding threat cards (collapsible)
    - Exact reproduction steps (numbered)
    - Copy-ready PoC code blocks
    - CVSS score per finding
    - Remediation advice
    - Severity color coding
"""
import os
import json
import base64
import datetime
from apkgraph.core.engine import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
from apkgraph.core.reproduction import enrich_findings

_SEV_EMOJI = {
    "Critical": "", "High": "🟠", "Medium": "🟡",
    "Low": "🟢", "Info": "", "Informational": "",
}
_SEV_COLOR = {
    "Critical": "#e74c3c", "High": "#e67e22", "Medium": "#f39c12",
    "Low": "#27ae60", "Info": "#3498db", "Informational": "#3498db",
}

_REMEDIATION = {
    "Secret":              "Rotate all exposed secrets immediately. Use Android Keystore or a remote secrets manager. Remove secrets from source code and APK resources.",
    "JWT":                 "Remove hardcoded JWTs. Implement server-side token issuance with short TTL. Never store tokens in APK strings.",
    "ExportedComponent":   "Add android:exported='false' or android:permission to all components not intended for public access.",
    "WebView":             "Disable JS (setJavaScriptEnabled(false)) unless strictly required. Set setAllowFileAccess(false) and setAllowUniversalAccessFromFileURLs(false). Never use addJavascriptInterface on pre-API-17 targets.",
    "CryptoIssue":         "Replace MD5/SHA1/DES with SHA-256/AES-256-GCM. Store keys in Android Keystore, not in APK strings.",
    "ICCFlow":             "Validate and sanitize all Intent extras before passing to exec()/SQL/WebView. Use explicit Intents wherever possible.",
    "DataStorage":         "Use EncryptedSharedPreferences and EncryptedFile from Jetpack Security. Never write sensitive data to external storage.",
    "NetworkConfig":       "Set android:usesCleartextTraffic='false'. Implement certificate pinning for sensitive domains.",
    "IntentHijacking":     "Use explicit Intents with setComponent(). Use LocalBroadcastManager for internal events.",
    "HiddenFunction":      "Remove debug/admin components before release. Use BuildConfig.DEBUG to gate development features.",
}


class ReportGenerator:
    def __init__(self, data: dict):
        self.data      = data
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 
    def generate_json(self, output_path: str):
        apk_meta  = self.data.get("apk_meta", {})
        findings  = self.data["findings"]
        enriched  = enrich_findings(findings, apk_meta.get("package", ""))
        out = {
            "meta": {"tool": "APKGraph v2.0", "timestamp": self.timestamp},
            "apk":  apk_meta,
            "risk": self.data["risk"],
            "attack_paths": self.data["attack_paths"],
            "findings": self._sanitize(enriched),
            "graph_summary": self.data.get("graph_summary", {}),
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"[+] JSON report:     {output_path}")

    # 
    def generate_markdown(self, output_path: str):
        findings     = self.data["findings"]
        risk         = self.data["risk"]
        paths        = self.data["attack_paths"]
        apk_meta     = self.data.get("apk_meta", {})
        graph_summary= self.data.get("graph_summary", {})
        enriched     = enrich_findings(findings, apk_meta.get("package", ""))

        md = []
        md.append("# APKGraph v2.0 — Android Security Assessment Report\n\n")
        md.append(f"> **Generated:** {self.timestamp}  \n")
        if apk_meta:
            md.append(f"> **App:** {apk_meta.get('app_name','N/A')} · `{apk_meta.get('package','N/A')}`  \n")
            md.append(f"> **Version:** {apk_meta.get('version_name','N/A')} (code {apk_meta.get('version_code','N/A')})  \n")
            md.append(f"> **SDK:** min={apk_meta.get('min_sdk','N/A')} target={apk_meta.get('target_sdk','N/A')}  \n")
        md.append("\n---\n\n")

        #  Risk Score 
        emoji = _SEV_EMOJI.get(risk["rating"], "")
        md.append(f"## {emoji} Risk Score: {risk['score']}/100 — {risk['rating']}\n\n")

        #  Attack Paths 
        if paths:
            md.append("---\n\n##  Attack Paths\n\n")
            for i, p in enumerate(paths, 1):
                md.append(f"### {i}. {p['name']}\n\n")
                md.append(f"| Field | Value |\n|-------|-------|\n")
                md.append(f"| Confidence | {p.get('confidence','N/A')} |\n")
                md.append(f"| CVSS Impact | {p.get('cvss_impact','N/A')} |\n")
                md.append(f"| Source | {p.get('source_type','N/A')}: {str(p.get('source_value',''))[:60]} |\n")
                md.append(f"| Target | {p.get('target_type','N/A')}: {str(p.get('target_value',''))[:60]} |\n\n")
                md.append(f"**Description:** {p['description']}\n\n")

        #  SCA Section 
        sca_findings = findings.get("SDKFingerprint", [])
        if sca_findings:
            md.append("---\n\n##  Software Composition Analysis (SCA)\n\n")
            md.append("| Component | Version | Vulnerability | Severity |\n")
            md.append("|-----------|---------|---------------|----------|\n")
            for sca in sorted(sca_findings, key=lambda x: (x.get('vulnerability') is None, x.get('sdk'))):
                vuln = sca.get("vulnerability")
                if vuln:
                    sev = vuln["severity"]
                    sev_icon = {"Critical":"", "High":"", "Medium":"🟡", "Low":""}.get(sev, "")
                    v_str = f"{sev_icon} {vuln['cve_desc']}"
                else:
                    sev = "Info"
                    v_str = "None detected"
                md.append(f"| {sca['sdk']} | {sca.get('version', 'Unknown')} | {v_str} | {sev} |\n")
            md.append("\n")

        #  Deobfuscation Section 
        deobf_findings = findings.get("Deobfuscation", {}).get("detected_methods", [])
        if deobf_findings:
            md.append("---\n\n##  Advanced Deobfuscation / String Encryption\n\n")
            md.append("The following methods were statically identified as potential string decryption routines. Hook them with Frida to dump all dynamically decrypted strings at runtime.\n\n")
            md.append("| Target Class | Target Method | Reason | X-Refs | Severity |\n")
            md.append("|--------------|---------------|--------|--------|----------|\n")
            for m in sorted(deobf_findings, key=lambda x: x.get('xref_count', 0), reverse=True):
                sev = m.get("severity", "Info")
                sev_icon = {"Critical":"", "High":"", "Medium":"🟡", "Low":""}.get(sev, "")
                md.append(f"| `{m['class']}` | `{m['method']}` | {m['reason']} | {m['xref_count']} | {sev_icon} {sev} |\n")
            
            md.append("\n**Recommended Frida Hook Example:**\n")
            md.append("```javascript\n")
            md.append(deobf_findings[0]["frida_hook"])
            md.append("\n```\n\n")

        #  Findings with Reproduction 
        md.append("---\n\n##  Findings & Reproduction Steps\n\n")

        _ORDER = [
            ("JWT",          "JWT Tokens — Hardcoded Authentication"),
            ("Secret",       "Hardcoded Secrets & Credentials"),
            ("WebView",      "WebView Vulnerabilities"),
            ("ICC",          "Inter-Component Communication Flows"),
            ("DataStorage",  "Insecure Data Storage"),
            ("Manifest",     "Exported Components"),
            ("Endpoint",     "API Endpoints"),
        ]

        finding_num = 0
        for key, title in _ORDER:
            data_val = enriched.get(key)
            items = []
            if isinstance(data_val, list):
                items = data_val
            elif isinstance(data_val, dict) and key == "Manifest":
                items = data_val.get("exported_components", [])
            elif isinstance(data_val, dict) and key == "Endpoint":
                items = [e for e in data_val.get("urls", []) if e.get("categories")]

            if not items:
                continue

            md.append(f"### {title}\n\n")
            for item in items[:20]:
                repro = item.get("reproduction", {})
                if not repro:
                    continue
                finding_num += 1
                sev   = item.get("confidence") or item.get("risk") or "Medium"
                emoji = _SEV_EMOJI.get(sev, "")
                threat = repro.get("threat", "Unknown threat")
                md.append(f"#### {finding_num}. {emoji} {threat}\n\n")
                md.append(f"**Severity:** {sev}  \n")
                if repro.get("cvss"):
                    md.append(f"**CVSS:** `{repro['cvss']}`  \n")
                md.append(f"**Impact:** {repro.get('impact','')}  \n\n")

                # Evidence
                evidence_val = (
                    item.get("value") or item.get("name") or
                    item.get("url") or item.get("component") or ""
                )
                if evidence_val:
                    md.append(f"**Evidence:** `{str(evidence_val)[:120]}`  \n\n")

                # JWT claims
                if repro.get("claims"):
                    md.append(f"**Decoded Claims:**\n```json\n{repro['claims'][:400]}\n```\n\n")

                # Steps
                if repro.get("steps"):
                    md.append("**Reproduction Steps:**\n")
                    for i, step in enumerate(repro["steps"], 1):
                        md.append(f"{i}. {step}\n")
                    md.append("\n")

                # PoC
                if repro.get("poc"):
                    md.append(f"**PoC:**\n```bash\n{repro['poc']}\n```\n\n")

                # Remediation
                remed = _REMEDIATION.get(key, _REMEDIATION.get("Secret", ""))
                if remed:
                    md.append(f">  **Remediation:** {remed}\n\n")

                md.append("---\n\n")

        md.append("\n*Report generated by APKGraph v2.0 — Android Attack Surface Intelligence Platform*\n")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("".join(md))
        print(f"[+] Markdown report: {output_path}")

    # 
    def generate_html(self, output_path: str):
        findings      = self.data["findings"]
        risk          = self.data["risk"]
        paths         = self.data["attack_paths"]
        apk_meta      = self.data.get("apk_meta", {})
        graph_summary = self.data.get("graph_summary", {})
        enriched      = enrich_findings(findings, apk_meta.get("package", ""))

        score  = risk["score"]
        rating = risk["rating"]
        gauge_color = _SEV_COLOR.get(rating, "#95a5a6")

        secret_count   = len(enriched.get("Secret") or [])
        jwt_count      = len(enriched.get("JWT") or [])
        exported_count = len((enriched.get("Manifest") or {}).get("exported_components") or [])
        webview_count  = len(enriched.get("WebView") or [])
        endpoint_count = len((enriched.get("Endpoint") or {}).get("urls") or [])
        icc_count      = len(enriched.get("ICC") or [])

        #  Build finding cards HTML 
        finding_cards_html = self._build_finding_cards(enriched, apk_meta.get("package",""))
        attack_paths_html  = self._build_attack_paths(paths)

        #  Build bypass recommendations HTML 
        bypass_recs = self.data.get("bypass_recs", {})
        bypass_html = self._build_bypass_html(bypass_recs)

        #  Build Frida Hook Match HTML 
        frida_hook_html = self._build_frida_hook_html(findings.get("FridaHookAnalysis", {}))

        #  Build SCA HTML 
        sca_html = self._build_sca_html(findings.get("SDKFingerprint", []))

        #  Build Deobfuscation HTML 
        deobf_html = self._build_deobf_html(findings.get("Deobfuscation", {}).get("detected_methods", []))
        #  Pre-build score breakdown table 
        breakdown_rows_html = ""
        for factor, pts in sorted((risk.get("breakdown") or {}).items(), key=lambda x: -x[1]):
            if pts > 0:
                label = factor.replace("_", " ").title()
                breakdown_rows_html += f"<tr><td>{label}</td><td>{pts}</td></tr>"

        #  Export Backend Probing scripts 
        self._export_backend_probes(enriched, output_path)

        graph_json_str = json.dumps(self.data.get("graph", {}))
        graph_b64 = base64.b64encode(graph_json_str.encode('utf-8')).decode('utf-8')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APKGraph Report — {apk_meta.get('app_name','App')}</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
:root {{
  --bg:#0d1117; --card:#161b22; --card2:#1c2128; --border:#30363d;
  --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
  --crit:#f85149; --high:#d29922; --med:#e3b341; --low:#3fb950;
  --code-bg:#161b22; --radius:8px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:0}}
a{{color:var(--accent);text-decoration:none}}
code,pre{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.82rem}}

/*  Header  */
.header{{background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);border-bottom:1px solid var(--border);padding:2rem 2.5rem}}
.header-inner{{max-width:1200px;margin:0 auto;display:flex;justify-content:space-between;align-items:flex-start;gap:2rem;flex-wrap:wrap}}
.brand{{font-size:1.6rem;font-weight:800;color:var(--accent);letter-spacing:-.5px}}
.brand span{{color:var(--muted);font-weight:400;font-size:1rem}}
.meta-grid{{display:grid;grid-template-columns:auto auto;gap:.2rem .8rem;font-size:.82rem;margin-top:.5rem}}
.meta-grid dt{{color:var(--muted)}}
.meta-grid dd{{color:var(--text);font-weight:500}}

/*  Gauge  */
.gauge-wrap{{text-align:center;min-width:180px}}
.gauge-score{{font-size:4.5rem;font-weight:900;color:{gauge_color};line-height:1}}
.gauge-label{{font-size:1rem;color:{gauge_color};font-weight:700;text-transform:uppercase;letter-spacing:1px;margin:.3rem 0}}
.gauge-bar{{height:8px;background:var(--border);border-radius:4px;width:160px;margin:.6rem auto 0;overflow:hidden}}
.gauge-fill{{height:100%;background:{gauge_color};width:{score}%;border-radius:4px}}

/*  Main layout  */
.main{{max-width:1200px;margin:0 auto;padding:2rem 2.5rem}}

/*  Stat Cards  */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem;margin:1.5rem 0 2rem}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;text-align:center}}
.card-num{{font-size:2rem;font-weight:800;color:var(--accent)}}
.card-label{{font-size:.72rem;color:var(--muted);margin-top:.2rem;text-transform:uppercase;letter-spacing:.5px}}

/*  Section headings  */
h2{{font-size:1.1rem;font-weight:700;color:var(--text);margin:2rem 0 1rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}}
h3{{font-size:.95rem;font-weight:600;color:var(--muted);margin:1.5rem 0 .5rem;text-transform:uppercase;letter-spacing:.5px}}

/*  Finding Card  */
.finding{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1rem;overflow:hidden}}
.finding-header{{display:flex;align-items:center;gap:.8rem;padding:.85rem 1.1rem;cursor:pointer;user-select:none}}
.finding-header:hover{{background:var(--card2)}}
.finding-num{{color:var(--muted);font-size:.75rem;font-weight:600;min-width:24px}}
.finding-title{{flex:1;font-weight:600;font-size:.9rem}}
.badge{{display:inline-block;padding:.2rem .55rem;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px}}
.badge-Critical{{background:#f8514920;color:var(--crit);border:1px solid #f8514940}}
.badge-High{{background:#d2992220;color:var(--high);border:1px solid #d2992240}}
.badge-Medium{{background:#e3b34120;color:var(--med);border:1px solid #e3b34140}}
.badge-Low{{background:#3fb95020;color:var(--low);border:1px solid #3fb95040}}
.chevron{{color:var(--muted);transition:transform .2s;font-size:.7rem}}
.finding-body{{display:none;padding:1.1rem;border-top:1px solid var(--border)}}
.finding-body.open{{display:block}}

/*  Finding body sections  */
.field-grid{{display:grid;grid-template-columns:140px 1fr;gap:.4rem .8rem;font-size:.82rem;margin-bottom:1rem}}
.field-grid dt{{color:var(--muted);font-weight:500}}
.field-grid dd{{color:var(--text);word-break:break-all}}
.evidence-block{{background:var(--code-bg);border:1px solid var(--border);border-radius:4px;padding:.6rem .9rem;font-family:monospace;font-size:.78rem;color:#79c0ff;word-break:break-all;margin:.3rem 0 1rem}}

/*  Steps  */
.steps{{margin:.3rem 0 1rem;padding-left:1.2rem}}
.steps li{{font-size:.83rem;margin:.3rem 0;color:var(--muted)}}
.steps li code{{color:var(--accent);background:var(--code-bg);padding:.05rem .3rem;border-radius:3px}}

/*  PoC block  */
.poc-wrap{{position:relative;margin:.5rem 0 1rem}}
.poc-label{{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:.3rem;display:flex;justify-content:space-between;align-items:center}}
.copy-btn{{background:var(--card2);border:1px solid var(--border);color:var(--muted);padding:.15rem .5rem;border-radius:4px;cursor:pointer;font-size:.7rem;transition:all .15s}}
.copy-btn:hover{{color:var(--text);border-color:var(--accent)}}
.poc{{background:#0d1117;border:1px solid var(--border);border-radius:4px;padding:.8rem 1rem;overflow-x:auto;white-space:pre;color:#a5d6ff;font-size:.78rem;line-height:1.5}}

/*  CVSS  */
.cvss{{font-size:.72rem;color:var(--muted);margin-top:.3rem;font-family:monospace}}

/*  Remediation  */
.remediation{{background:#3fb95010;border:1px solid #3fb95030;border-radius:4px;padding:.6rem .9rem;font-size:.82rem;color:#3fb950;margin-top:.8rem}}
.remediation::before{{content:' Remediation: ';font-weight:700}}

/*  Attack path cards  */
.path-card{{background:var(--card);border-radius:var(--radius);padding:1rem 1.2rem;margin-bottom:.8rem;border-left:3px solid}}
.path-card-crit{{border-color:var(--crit)}}
.path-card-high{{border-color:var(--high)}}
.path-card-med{{border-color:var(--med)}}
.path-title{{font-weight:700;margin-bottom:.3rem}}
.path-meta{{font-size:.78rem;color:var(--muted);margin-bottom:.4rem}}
.path-desc{{font-size:.83rem;color:var(--text)}}
.path-steps{{font-family:monospace;font-size:.75rem;color:var(--accent);margin-top:.4rem}}

/*  Score breakdown table  */
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{background:var(--card2);padding:.5rem .7rem;text-align:left;border-bottom:2px solid var(--border);color:var(--muted);text-transform:uppercase;font-size:.72rem;letter-spacing:.5px}}
td{{padding:.4rem .7rem;border-bottom:1px solid var(--border)}}
tr:last-child td{{border-bottom:none}}

/*  Footer  */
.footer{{text-align:center;padding:2rem;color:var(--muted);font-size:.78rem;border-top:1px solid var(--border);margin-top:3rem}}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div>
      <div class="brand">APKGraph <span>v2.0</span></div>
      <div style="font-size:.82rem;color:var(--muted);margin:.3rem 0 .8rem">Android Attack Surface Intelligence Platform</div>
      <dl class="meta-grid">
        <dt>Application</dt><dd>{apk_meta.get('app_name','N/A')}</dd>
        <dt>Package</dt>    <dd>{apk_meta.get('package','N/A')}</dd>
        <dt>Version</dt>    <dd>{apk_meta.get('version_name','N/A')} (code {apk_meta.get('version_code','N/A')})</dd>
        <dt>SDK</dt>        <dd>min {apk_meta.get('min_sdk','N/A')} → target {apk_meta.get('target_sdk','N/A')}</dd>
        <dt>Generated</dt>  <dd>{self.timestamp}</dd>
      </dl>
    </div>
    <div class="gauge-wrap">
      <div class="gauge-score">{score}</div>
      <div class="gauge-label">{rating}</div>
      <div class="gauge-bar"><div class="gauge-fill"></div></div>
    </div>
  </div>
</div>

<div class="main">

  <div class="cards">
    <div class="card"><div class="card-num">{secret_count}</div><div class="card-label">Secrets</div></div>
    <div class="card"><div class="card-num">{jwt_count}</div><div class="card-label">JWT Tokens</div></div>
    <div class="card"><div class="card-num">{exported_count}</div><div class="card-label">Exported Comps</div></div>
    <div class="card"><div class="card-num">{webview_count}</div><div class="card-label">WebView Issues</div></div>
    <div class="card"><div class="card-num">{endpoint_count}</div><div class="card-label">Endpoints</div></div>
    <div class="card"><div class="card-num">{icc_count}</div><div class="card-label">ICC Flows</div></div>
    <div class="card"><div class="card-num">{len(paths)}</div><div class="card-label">Attack Paths</div></div>
    <div class="card" style="border-color:var(--accent)"><div class="card-num" style="color:var(--accent)">{len(findings.get('FridaHookAnalysis', {}).get('hooked_scripts_matched', []))}</div><div class="card-label">Verified Hooks</div></div>
  </div>

  <h2>Attack Surface Knowledge Graph</h2>
  <p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">
    Interactive visualization of all vulnerabilities and their paths throughout the application. Drag nodes to explore.
  </p>
  <div class="kg-controls" style="margin-bottom: 15px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
    <input type="text" id="kg-search" placeholder="Search class or vuln..." style="padding: 6px; border-radius: 4px; border: 1px solid var(--border); background: var(--bg); color: var(--fg); min-width: 200px;">
    <button id="kg-search-btn" style="padding: 6px 12px; cursor: pointer; background: var(--accent); color: var(--bg); border: none; border-radius: 4px; font-weight: bold;">Search</button>
    
    <div style="border-left: 1px solid var(--border); height: 20px; margin: 0 5px;"></div>
    
    <label style="font-size: 0.9rem; cursor: pointer;"><input type="checkbox" id="filter-critical"> High/Critical Only</label>
    <label style="font-size: 0.9rem; cursor: pointer;"><input type="checkbox" id="filter-packages" checked> Show Packages</label>
    <span style="font-size: 0.8rem; color: var(--muted); margin-left: auto;"> Double-click a package to collapse/expand its children</span>
  </div>

  <div style="display: flex; gap: 10px; margin-bottom:2rem; height:600px;">
    <div id="kg-network" style="flex: 3; background:var(--card2); border:1px solid var(--border); border-radius:var(--radius);"></div>
    <div id="kg-panel" style="flex: 1; background:var(--card); border:1px solid var(--border); border-radius:var(--radius); padding: 15px; display: none; overflow-y: auto;">
      <h3 id="kg-panel-title" style="margin-top:0; color:var(--accent); font-size: 1.1rem; border-bottom: 1px solid var(--border); padding-bottom: 10px;">Node Info</h3>
      <div id="kg-panel-content" style="font-size: 0.85rem; word-break: break-all; color: var(--fg); line-height: 1.5;"></div>
    </div>
  </div>

  <script>
    // Safely decode the base64 JSON payload to prevent script injection crashes
    const graphData = JSON.parse(atob("{graph_b64}"));
    
    // Parse networkx json to vis.js format
    const rawNodes = graphData.nodes || [];
    const rawLinks = graphData.links || graphData.edges || [];

    const nodes = new vis.DataSet(rawNodes.map(n => {{
      let color = "#58a6ff"; // default accent
      let shape = "dot";
      
      if (n.type === "Application") {{ color = "#d29922"; shape = "star"; }}
      else if (["Secret", "Endpoint", "DeepLink", "WebView", "SSLPinning", "RootDetection"].includes(n.type)) {{ color = "#f85149"; shape = "hexagon"; }}
      else if (["ExportedComponent", "HiddenComponent"].includes(n.type)) {{ color = "#e3b341"; shape = "triangle"; }}
      else if (n.type === "IntentHijack") {{ color = "#f85149"; shape = "diamond"; }}
      else if (n.type === "Package") {{ color = "#8b949e"; shape = "dot"; }}
      else if (n.type === "Class") {{ color = "#c9d1d9"; shape = "box"; }}
      
      let riskVal = n.risk || n.severity || n.confidence || "";
      return {{
        id: n.id,
        type: n.type,
        risk: riskVal,
        label: n.type + "\\n" + (n.value ? (typeof n.value === 'object' ? JSON.stringify(n.value).substring(0, 25) : String(n.value).substring(0, 25)) : ""),
        title: "ID: " + n.id + "\\nValue: " + (n.value ? (typeof n.value === 'object' ? JSON.stringify(n.value) : String(n.value)) : "") + "\\nType: " + n.type + (riskVal ? "\\nRisk: " + riskVal : ""),
        color: color,
        shape: shape,
        size: shape === "star" ? 30 : (n.type === "Package" ? 10 : 15),
        font: n.type === "Class" ? {{ color: "#24292e" }} : undefined
      }};
    }}));

    const edges = new vis.DataSet(rawLinks.map(l => {{
      let isCrossModule = ["may_authenticate_to", "may_invoke", "may_authorize", "may_inject_via"].includes(l.relation);
      return {{
        from: l.source,
        to: l.target,
        label: l.relation || "",
        arrows: 'to',
        dashes: isCrossModule,
        width: isCrossModule ? 2 : 1,
        font: {{ size: 10, color: isCrossModule ? '#f85149' : '#8b949e', align: 'top' }},
        color: {{ color: isCrossModule ? '#f85149' : '#30363d', highlight: '#58a6ff' }}
      }};
    }}));

    const container = document.getElementById('kg-network');
    const data = {{ nodes: nodes, edges: edges }};
    const options = {{
      layout: {{
        hierarchical: {{
          direction: 'LR',
          sortMethod: 'directed',
          nodeSpacing: 80,
          levelSeparation: 200,
          treeSpacing: 100
        }}
      }},
      physics: {{ enabled: false }},
      nodes: {{ font: {{ color: '#e6edf3', size: 12 }} }},
      edges: {{ smooth: {{ type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.4 }} }},
      interaction: {{ hover: true, tooltipDelay: 200, zoomView: true, dragNodes: true }}
    }};
    const network = new vis.Network(container, data, options);
    
    // Feature 1: Interactive Node Click
    network.on("click", function (params) {{
      if (params.nodes.length > 0) {{
        const nodeId = params.nodes[0];
        const nodeData = nodes.get(nodeId);
        document.getElementById('kg-panel').style.display = 'block';
        document.getElementById('kg-panel-title').innerText = nodeData.type || "Node";
        let content = "<strong>Label:</strong> " + (nodeData.label || "").replace(/\\n/g, ' ') + "<br><br>";
        if (nodeData.title) {{ content += nodeData.title.replace(/\\n/g, '<br>'); }}
        document.getElementById('kg-panel-content').innerHTML = content;
      }} else {{
        document.getElementById('kg-panel').style.display = 'none';
      }}
    }});

    // Feature 2: Double Click to Collapse
    network.on("doubleClick", function (params) {{
      if (params.nodes.length === 1) {{
        const nodeId = params.nodes[0];
        const nodeData = nodes.get(nodeId);
        if (nodeData.type === 'Package' || nodeData.type === 'Class' || nodeData.type === 'Application') {{
           let isCollapsed = nodeData.collapsed || false;
           function getDescendants(id) {{
             let desc = [];
             edges.get({{filter: e => e.from === id}}).forEach(e => {{
               desc.push(e.to);
               desc = desc.concat(getDescendants(e.to));
             }});
             return desc;
           }}
           let children = getDescendants(nodeId);
           let updates = [];
           children.forEach(c => updates.push({{id: c, hidden: !isCollapsed}}) );
           nodes.update(updates);
           nodes.update({{id: nodeId, collapsed: !isCollapsed, font: {{color: !isCollapsed ? '#f85149' : (nodeData.type === 'Class' ? '#24292e' : '#e6edf3')}}}});
        }}
      }}
    }});

    // Feature 3: Search Bar
    let currentSearchQuery = "";
    let currentSearchIndex = 0;
    let matchedNodesCache = [];

    document.getElementById('kg-search-btn').addEventListener('click', () => {{
      const q = document.getElementById('kg-search').value.toLowerCase();
      if (!q) return;
      
      if (q !== currentSearchQuery) {{
          currentSearchQuery = q;
          currentSearchIndex = 0;
          matchedNodesCache = nodes.get({{
              filter: function(item) {{
                  return (item.label && item.label.toLowerCase().includes(q)) || 
                         (item.title && item.title.toLowerCase().includes(q));
              }}
          }});
      }} else {{
          currentSearchIndex++;
          if (currentSearchIndex >= matchedNodesCache.length) {{
              currentSearchIndex = 0;
          }}
      }}

      if (matchedNodesCache.length > 0) {{
        let targetNode = matchedNodesCache[currentSearchIndex];
        // Unhide if hidden
        if (targetNode.hidden) {{
            nodes.update({{id: targetNode.id, hidden: false}});
        }}
        network.focus(targetNode.id, {{ scale: 1.2, animation: true }});
        network.selectNodes([targetNode.id]);
        network.emit("click", {{nodes: [targetNode.id]}});
        
        document.getElementById('kg-search-btn').innerText = `Next (${{currentSearchIndex + 1}}/${{matchedNodesCache.length}})`;
      }} else {{
        alert("No matching nodes found.");
        document.getElementById('kg-search-btn').innerText = "Search";
      }}
    }});

    document.getElementById('kg-search').addEventListener('input', () => {{
        document.getElementById('kg-search-btn').innerText = "Search";
        currentSearchQuery = "";
    }});

    // Feature 4: Filters
    function applyFilters() {{
      const hideLow = document.getElementById('filter-critical').checked;
      const hidePkgs = !document.getElementById('filter-packages').checked;
      let updates = [];
      nodes.forEach(n => {{
         let hidden = false;
         if (hidePkgs && (n.type === 'Package' || n.type === 'Class' || n.type === 'Application')) {{
             hidden = true;
         }}
         if (hideLow && ["Secret", "Endpoint", "DeepLink", "WebView", "SSLPinning", "RootDetection", "IntentHijack"].includes(n.type)) {{
            let r = (n.risk || "").toLowerCase();
            let isCrit = r.includes('high') || r.includes('critical');
            if (!isCrit) hidden = true;
         }}
         updates.push({{id: n.id, hidden: hidden}});
      }});
      nodes.update(updates);
    }}
    
    document.getElementById('filter-critical').addEventListener('change', applyFilters);
    document.getElementById('filter-packages').addEventListener('change', applyFilters);

  </script>

  {frida_hook_html}
  
  {deobf_html}

  {sca_html}

  <h2>Attack Path Predictions</h2>
  {attack_paths_html}

  <h2>Threats &amp; Reproduction Steps</h2>
  <p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">
    Click any finding to expand exact reproduction steps and ready-to-run PoC commands.
  </p>
  {finding_cards_html}

  <h2>Risk Score Breakdown</h2>
  <table>
    <tr><th>Factor</th><th>Points</th></tr>
    {breakdown_rows_html}
  </table>

</div>

<div class="footer">APKGraph v2.0 — Android Attack Surface Intelligence Platform · {self.timestamp}</div>

<script>
// Toggle finding cards
document.querySelectorAll('.finding-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body    = h.nextElementSibling;
    const chevron = h.querySelector('.chevron');
    const open    = body.classList.toggle('open');
    chevron.textContent = open ? '▲' : '▼';
  }});
}});

// Copy PoC to clipboard
document.querySelectorAll('.copy-btn').forEach(btn => {{
  btn.addEventListener('click', e => {{
    e.stopPropagation();
    const code = btn.closest('.poc-wrap').querySelector('.poc').textContent;
    navigator.clipboard.writeText(code).then(() => {{
      btn.textContent = '✓ Copied';
      setTimeout(() => btn.textContent = 'Copy', 1500);
    }});
  }});
}});
</script>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML report:     {output_path}")

    #  HTML building helpers 
    def _build_attack_paths(self, paths: list) -> str:
        if not paths:
            return '<p style="color:var(--muted);font-size:.85rem">No attack paths predicted.</p>'
        html = ""
        for p in paths:
            conf = p.get("confidence", "")
            css_cls = {"Critical": "crit", "High": "high", "Medium": "med"}.get(conf, "med")
            
            # Escape HTML characters to prevent XSS/truncation bugs when rendering JSON strings
            steps = []
            for step in p.get("steps", []):
                steps.append(self._esc(step))
            steps_str = "  →  ".join(steps)
            
            color = _SEV_COLOR.get(conf, "#95a5a6")
            html += f"""
<div class="path-card path-card-{css_cls}">
  <div class="path-title">{p['name']}
    <span class="badge badge-{conf}" style="margin-left:.5rem">{conf}</span>
  </div>
  <div class="path-meta">CVSS Impact: <strong>{p.get('cvss_impact','N/A')}</strong></div>
  <div class="path-desc">{p['description']}</div>
  <div class="path-steps">{steps_str}</div>
</div>"""
        return html

    def _build_deobf_html(self, deobf_findings: list) -> str:
        if not deobf_findings:
            return ""
            
        rows = ""
        for m in sorted(deobf_findings, key=lambda x: x.get('xref_count', 0), reverse=True):
            sev = m.get("severity", "Info")
            css_cls = {"Critical": "badge-Critical", "High": "badge-High", "Medium": "badge-Medium", "Low": "badge-Low"}.get(sev, "badge-Low")
            rows += f"""
            <tr>
              <td><code>{self._esc(m['class'])}</code></td>
              <td><code>{self._esc(m['method'])}</code></td>
              <td>{self._esc(m['reason'])}</td>
              <td>{m['xref_count']}</td>
              <td><span class='badge {css_cls}'>{sev}</span></td>
            </tr>
            """
            
        return f"""
        <h2>Advanced Deobfuscation / String Encryption</h2>
        <p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">
          The following methods were statically identified as potential string decryption routines. Hook them with Frida to dump all dynamically decrypted strings at runtime.
        </p>
        <div style="background:var(--card); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom: 1rem;">
          <table style="width:100%; border-collapse:collapse; text-align:left;">
            <thead>
              <tr>
                <th>Target Class</th>
                <th>Target Method</th>
                <th>Reason</th>
                <th>X-Refs</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
        <p style="font-size:.82rem;color:var(--muted);margin-bottom:.5rem;margin-top:1rem;font-weight:bold;">Recommended Frida Hook Example:</p>
        <pre style="background:#0d1117;border:1px solid var(--border);padding:1rem;border-radius:var(--radius);overflow-x:auto;margin-bottom:2rem;color:var(--text);font-family:monospace;font-size:0.75rem;">{self._esc(deobf_findings[0]["frida_hook"])}</pre>
        """

    def _build_sca_html(self, sca_findings: list) -> str:
        if not sca_findings:
            return ""
        
        rows = ""
        for sca in sorted(sca_findings, key=lambda x: (x.get('vulnerability') is None, x.get('sdk'))):
            vuln = sca.get("vulnerability")
            if vuln:
                sev = vuln["severity"]
                css_cls = {"Critical": "badge-Critical", "High": "badge-High", "Medium": "badge-Medium", "Low": "badge-Low"}.get(sev, "badge-Low")
                v_html = f"<div style='margin-bottom:4px'><span class='badge {css_cls}'>{sev}</span></div><div style='font-size:0.8rem;color:var(--text)'>{self._esc(vuln['cve_desc'])}</div>"
            else:
                v_html = "<span style='color:var(--muted);font-size:0.8rem'>None detected</span>"
                
            rows += f"""
            <tr>
              <td style="font-weight:600;color:var(--accent)">{self._esc(sca['sdk'])}</td>
              <td><code>{self._esc(sca.get('version', 'Unknown'))}</code></td>
              <td>{v_html}</td>
            </tr>
            """
            
        return f"""
        <h2>Software Composition Analysis</h2>
        <div style="background:var(--card); border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; margin-bottom: 2rem;">
          <table style="width:100%; border-collapse:collapse; text-align:left;">
            <thead>
              <tr>
                <th>Component</th>
                <th>Version</th>
                <th>Vulnerabilities</th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
        """

    def _export_backend_probes(self, enriched_findings: dict, output_base: str):
        """Generates a text file of all endpoints and a shell script to pass them to vulcanx or other DAST tools."""
        endpoints = enriched_findings.get("Endpoint", {}).get("urls", [])
        if not endpoints:
            return
            
        urls = [e.get("url") for e in endpoints if e.get("url")]
        
        # 1. Write raw endpoints list
        endpoints_file = f"{output_base}_endpoints.txt"
        with open(endpoints_file, "w") as f:
            for u in set(urls):
                f.write(u + "\n")
                
        # 2. Write vulcanx/sqlmap launcher script
        launcher_file = f"{output_base}_backend_scan.sh"
        with open(launcher_file, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Auto-generated Backend API Probing script for {output_base}\n\n")
            f.write(f'echo "[*] Launching API scanner against {len(set(urls))} endpoints extracted from APK..."\n\n')
            f.write(f'# Example: Run ffuf or sqlmap on all endpoints\n')
            f.write(f'# while read url; do\n')
            f.write(f'#   ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt\n')
            f.write(f'# done < {os.path.basename(endpoints_file)}\n\n')
            f.write(f'echo "[*] Ensure you have permission to actively scan these backend APIs before uncommenting the loop!"\n')
            
        import stat
        os.chmod(launcher_file, os.stat(launcher_file).st_mode | stat.S_IEXEC)

    def _build_finding_cards(self, enriched: dict, package: str) -> str:
        html    = ""
        counter = 0

        sections = [
            ("Manifest",    "M1: Improper Platform Usage (Exported Components)", lambda d: d.get("exported_components",[]) if isinstance(d,dict) else []),
            ("WebView",     "M1 & M7: Client Code Quality (WebViews)", lambda d: d if isinstance(d, list) else []),
            ("DataStorage", "M2: Insecure Data Storage",lambda d: d if isinstance(d, list) else []),
            ("Endpoint",    "M3: Insecure Communication (Endpoints)",       lambda d: [e for e in d.get("urls",[]) if e.get("categories")] if isinstance(d,dict) else []),
            ("SSLPinning",  "M3: Insecure Communication (SSL Pinning)", lambda d: d.get("implementations",[]) if isinstance(d, dict) else []),
            ("Secret",      "M4 & M10: Extraneous Functionality (Hardcoded Secrets)",   lambda d: d if isinstance(d, list) else []),
            ("JWT",         "M4: Insecure Authentication (JWT)",          lambda d: d if isinstance(d, list) else []),
            ("Crypto",      "M5: Insufficient Cryptography", lambda d: d if isinstance(d, list) else []),
            ("IntentHijacking", "M1: Improper Platform Usage (Intent Hijacking)", lambda d: d if isinstance(d, list) else []),
            ("RootDetection", "M8 & M9: Reverse Engineering (Anti-Analysis)", lambda d: d.get("implementations",[]) if isinstance(d, dict) else []),
            ("HiddenFunction", "M10: Extraneous Functionality", lambda d: d if isinstance(d, list) else []),
            ("ICC",         " Cross-Component Taint Flows",     lambda d: d if isinstance(d, list) else []),
        ]

        for key, section_title, extractor in sections:
            items = extractor(enriched.get(key) or [])
            if not items:
                continue

            html += f'<h3>{section_title}</h3>'
            shown = 0
            for item in items:
                repro = item.get("reproduction", {})
                
                if shown >= 30:
                    remaining = len(items) - shown
                    html += f'<p style="font-size:.78rem;color:var(--muted);margin:.5rem 0 1rem">... and {remaining} more findings (see JSON report)</p>'
                    break

                counter += 1
                shown   += 1

                sev    = item.get("confidence") or item.get("risk") or item.get("severity") or "Medium"
                
                # Fallback extraction for items without reproduction blocks
                threat = repro.get("threat") or item.get("vulnerability") or item.get("type") or item.get("description") or "Security Finding"
                impact = repro.get("impact") or item.get("note") or item.get("reason") or "Potential security risk detected statically."
                cvss   = repro.get("cvss", "")
                steps  = repro.get("steps", [])
                poc    = repro.get("poc", "")

                # Evidence value
                evidence = (
                    item.get("value") or item.get("snippet") or item.get("name") or
                    item.get("url") or item.get("component") or item.get("description") or ""
                )
                evidence_str = str(evidence)[:200]

                # Location / Path extraction
                loc_parts = []
                if item.get("file"): loc_parts.append(str(item.get("file")))
                elif item.get("path"): loc_parts.append(str(item.get("path")))
                
                if item.get("class"): 
                    cls = str(item.get("class"))
                    if item.get("method"):
                        cls += f" -> {item.get('method')}()"
                    loc_parts.append(cls)
                elif item.get("locations"):
                    locs = item.get("locations")
                    if isinstance(locs, list) and len(locs) > 0:
                        loc_parts.append(str(locs[0]))
                    else:
                        loc_parts.append(str(locs))
                elif item.get("location"):
                    loc = item.get("location")
                    if isinstance(loc, list) and len(loc) > 0:
                        loc_parts.append(str(loc[0]))
                    else:
                        loc_parts.append(str(loc))
                elif item.get("usage_method"):
                    loc_parts.append(str(item.get("usage_method")))
                    if item.get("sink_path"):
                        loc_parts.append(f"Sink: {item.get('sink_path')}")
                elif item.get("source_method"):
                    loc_parts.append(str(item.get("source_method")))
                    if item.get("sink_path"):
                        loc_parts.append(f"Sink: {item.get('sink_path')}")
                elif item.get("activity"):
                    loc_parts.append(str(item.get("activity")))
                elif item.get("name") and not evidence:
                    # Fallback for Manifest Exported Components
                    loc_parts.append(str(item.get("name")))
                    
                loc_str = " | ".join(loc_parts)

                # JWT special fields
                claims_html = ""
                if repro.get("claims"):
                    claims_preview = repro["claims"][:500]
                    claims_html = f"""
<div class="poc-label">Decoded JWT Claims</div>
<div class="poc">{self._esc(claims_preview)}</div>"""
                    if repro.get("weak_alg"):
                        claims_html += f'<div style="color:var(--crit);font-size:.75rem;margin:.3rem 0"> Weak algorithm ({repro.get("algorithm","?")}) — signing secret can be brute-forced offline</div>'

                # Steps HTML
                steps_html = ""
                if steps:
                    steps_html = '<ol class="steps">' + "".join(
                        f'<li>{self._esc(s)}</li>' for s in steps
                    ) + '</ol>'

                # PoC block
                poc_html = ""
                if poc:
                    poc_html = f"""
<div class="poc-wrap">
  <div class="poc-label">
    <span>PoC / Reproduction Command</span>
    <button class="copy-btn">Copy</button>
  </div>
  <pre class="poc">{self._esc(poc)}</pre>
</div>"""

                # Remediation
                remed = _REMEDIATION.get(key, "")
                remed_html = f'<div class="remediation">{remed}</div>' if remed else ""

                html += f"""
<div class="finding">
  <div class="finding-header">
    <span class="finding-num">#{counter}</span>
    <span class="finding-title">{self._esc(threat)}</span>
    <span class="badge badge-{sev}">{sev}</span>
    <span class="chevron">▼</span>
  </div>
  <div class="finding-body">
    <dl class="field-grid">
      <dt>Severity</dt><dd><span class="badge badge-{sev}">{sev}</span></dd>
      {'<dt>CVSS Vector</dt><dd><span class="cvss">' + cvss + '</span></dd>' if cvss else ''}
      <dt>Impact</dt><dd>{self._esc(impact)}</dd>
      {'<dt>Location</dt><dd><code style="background:#f1f1f1;padding:2px 5px;border-radius:3px;color:#d32f2f">' + self._esc(loc_str) + '</code></dd>' if loc_str else ''}
    </dl>
    {'<div class="poc-label">Evidence</div><div class="evidence-block">' + self._esc(evidence_str) + '</div>' if evidence_str else ''}
    {claims_html}
    {'<div class="poc-label">Exploitation Steps</div>' + steps_html if steps_html else ''}
    {poc_html}
    {remed_html}
  </div>
</div>"""

        return html

    def _build_bypass_html(self, bypass_recs: dict) -> str:
        if not bypass_recs:
            return '<p style="color:var(--muted);font-size:.85rem">No bypasses recommended (no protections detected).</p>'
        
        html = ""
        for cat, rec in bypass_recs.items():
            if not rec.get("detected"):
                continue
                
            title = {
                "ssl": "SSL Pinning Bypass",
                "root": "Root Detection Bypass",
                "proxy": "Proxy Detection Bypass",
                "emulator": "Emulator Bypass",
            }.get(cat, f"{cat.title()} Bypass")
            
            # Remove hardcoded script lists and replace with a generic message
            scripts = rec.get("scripts", [])
            script_list_html = "<ul><li><strong>Universal Bypass Module</strong>: Dynamically generated bypass hooks based on detected protections.</li></ul>"
            
            steps = rec.get("manual_steps", [])
            steps_html = ""
            if steps:
                steps_html = '<ol class="steps">' + "".join(f"<li>{self._esc(s)}</li>" for s in steps) + "</ol>"
                
            frida_cmd = rec.get("frida_cmd", "")
            cmd_html = ""
            if frida_cmd:
                cmd_html = f"""
<div class="poc-wrap" style="margin-top:1rem">
  <div class="poc-label"><span>Frida Command</span><button class="copy-btn">Copy</button></div>
  <pre class="poc" style="border-color:var(--accent)">{self._esc(frida_cmd)}</pre>
</div>"""

            html += f"""
<div class="path-card" style="border-color:var(--accent); background:var(--card2)">
  <div class="path-title" style="color:var(--accent)">{title}</div>
  <div class="path-meta">Detected: <strong>{self._esc(rec.get('detail',''))}</strong></div>
  <div style="font-size:.82rem; margin: .8rem 0 .4rem; font-weight:600">Recommended Scripts:</div>
  <div style="font-size:.82rem; color:var(--muted)">{script_list_html}</div>
  <div style="font-size:.82rem; margin: .8rem 0 .4rem; font-weight:600">Instructions:</div>
  {steps_html}
  {cmd_html}
</div>"""
        return html

    def _build_frida_hook_html(self, hook_data: dict) -> str:
        matched = hook_data.get("hooked_scripts_matched", [])
        if not matched:
            return ""
            
        html = "<h2>Statically Verified Frida Hooks</h2>"
        html += '<p style="font-size:0.9rem; color:var(--muted)">The following Frida scripts in your repository hook classes that were statically verified to exist within this specific APK.</p>'
        
        for script in matched:
            is_high = script.get("confidence") == "High"
            border_col = "var(--danger)" if is_high else "var(--warning)"
            title_col  = "var(--danger)" if is_high else "var(--warning)"
            
            classes_html = ", ".join(f"<code>{c}</code>" for c in script.get("classes_found_in_apk", []))
            
            # Embed the JS content directly in the HTML report
            js_content = script.get("script_content", "/* Script content not available */")
            
            html += f"""
<div class="path-card" style="border-color:{border_col}; background:var(--card2)">
  <div class="path-title" style="color:{title_col}">Statically Verified Hook</div>
  <div class="path-meta">Hooks verified: <strong>{script.get('matched_targets')}/{script.get('total_targets')} targets found in APK</strong></div>
  <div style="font-size:.82rem; margin: .8rem 0 .4rem; font-weight:600">Classes hooked in this APK:</div>
  <div style="font-size:.82rem; color:var(--muted); margin-bottom: 1rem;">{classes_html}</div>
  <div style="font-size:.82rem; margin: .8rem 0 .4rem; font-weight:600">Frida Hook Content:</div>
  <pre class="poc" style="border-color:{border_col}; max-height: 400px; overflow-y: auto;">{self._esc(js_content)}</pre>
</div>"""

        return html

    @staticmethod
    def _esc(s: str) -> str:
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    @staticmethod
    def _sanitize(findings: dict) -> dict:
        return json.loads(json.dumps(findings, default=str))
