"""
BypassEngine v1.0
------------------
Loads Frida bypass scripts from a directory, parses their metadata
(from @name, @bypass, @targets comments), and produces recommendations
based on detected protections.

Users can drop their own .js Frida scripts into frida_scripts/.
The engine auto-discovers and indexes them.

Finding types matched:
  SSL Pinning     → ssl_pinning_universal.js (or user script)
  Root Detection  → root_detection_bypass.js
  Proxy Detection → proxy_detection_bypass.js
  Emulator        → emulator_detection_bypass.js
"""
import os
import re
import json
from pathlib import Path

_SCRIPT_META_RE = {
    "name":         re.compile(r'@name\s+(.+)'),
    "bypass":       re.compile(r'@bypass\s+(.+)'),
    "targets":      re.compile(r'@targets\s+(.+)'),
    "description":  re.compile(r'@description\s+(.+)'),
    "frida_version":re.compile(r'@frida_version\s+(.+)'),
    "usage":        re.compile(r'@usage\s+(.+)'),
}

_BYPASS_KEYWORDS = {
    "ssl":     ["ssl", "pinning", "certificate", "tls", "trustmanager", "okhttp"],
    "root":    ["root", "rootbeer", "magisk", "supersu", "safetynet"],
    "proxy":   ["proxy", "vpn", "mitm", "traffic"],
    "emulator":["emulator", "avd", "build", "fingerprint", "imei"],
    "frida":   ["frida", "xposed", "substrate", "anti-frida"],
    "biometric":["biometric", "fingerprint_auth", "faceid"],
}


def _find_scripts_dir() -> Path:
    """Look for frida_scripts/ relative to the APKGraph package root."""
    candidates = [
        Path(__file__).parent.parent.parent / "frida_scripts",
        Path.cwd() / "frida_scripts",
        Path(os.environ.get("APKGRAPH_SCRIPTS", "")) if os.environ.get("APKGRAPH_SCRIPTS") else None,
    ]
    for c in candidates:
        if c and c.exists():
            return c
    return None


def _parse_script_meta(js_path: Path) -> dict:
    """Extract @name, @bypass, @targets etc. from JS file header."""
    meta = {"file": js_path.name, "path": str(js_path), "raw_keywords": []}
    try:
        content = js_path.read_text(encoding="utf-8", errors="replace")[:4000]
        for field, pattern in _SCRIPT_META_RE.items():
            m = pattern.search(content)
            if m:
                meta[field] = m.group(1).strip()

        # Extract all lowercase words for keyword matching
        meta["raw_keywords"] = list(set(re.findall(r'[a-zA-Z]{4,}', content.lower())))
    except Exception:
        pass
    return meta


def _classify_script(meta: dict) -> list:
    """Return a list of bypass categories this script applies to."""
    categories = []
    text_to_check = " ".join([
        meta.get("bypass", ""),
        meta.get("targets", ""),
        meta.get("name", ""),
        meta.get("description", ""),
        " ".join(meta.get("raw_keywords", [])[:100]),
    ]).lower()

    for category, keywords in _BYPASS_KEYWORDS.items():
        if any(kw in text_to_check for kw in keywords):
            categories.append(category)
    return categories


class BypassEngine:
    """
    Loads all Frida scripts, indexes them by bypass category,
    and generates recommendations based on what was detected.
    """

    def __init__(self):
        self.scripts_dir = _find_scripts_dir()
        self.script_index: dict = {}   # category -> list of script meta
        self.all_scripts:  list = []
        self._load()

    def _load(self):
        if not self.scripts_dir:
            return
        for js_file in sorted(self.scripts_dir.glob("*.js")):
            meta       = _parse_script_meta(js_file)
            categories = _classify_script(meta)
            meta["categories"] = categories
            self.all_scripts.append(meta)
            for cat in categories:
                self.script_index.setdefault(cat, []).append(meta)

    def get_all_scripts(self) -> list:
        return self.all_scripts

    def recommend(self, findings: dict, package_name: str = "com.target.app") -> dict:
        """
        Given all_findings, produce a bypass recommendation dict:
        {
          category: {
            "detected":    bool,
            "detail":      str,
            "scripts":     [script_meta, ...],
            "frida_cmd":   str,
            "manual_steps": [str, ...],
          }
        }
        """
        recs = {}

        # ── SSL Pinning ────────────────────────────────────────────────────
        ssl_data = findings.get("SSLPinning") or {}
        if isinstance(ssl_data, dict) and ssl_data.get("pinning"):
            impls = ssl_data.get("implementations", [])
            recs["ssl"] = {
                "detected": True,
                "detail":   f"{len(impls)} pinning implementation(s) found: " +
                            ", ".join(i["name"] for i in impls[:3]),
                "severity": ssl_data.get("overall_severity", "High"),
                "scripts":  self.script_index.get("ssl", []),
                "frida_cmd": self._frida_cmd("ssl", package_name),
                "hardcoded_pins": ssl_data.get("hardcoded_pins", []),
                "manual_steps": [
                    "Set HTTP proxy on device: adb shell settings put global http_proxy <ip>:8080",
                    "Install Burp CA cert on device (Settings → Security → Install Cert)",
                    "Run Frida bypass script (see command below)",
                    "Verify traffic visible in Burp Suite proxy",
                    "For NSC-based pinning: also patch res/xml/network_security_config.xml with apktool",
                ],
            }

        # ── Root Detection ────────────────────────────────────────────────
        root_data = findings.get("RootDetection") or {}
        if isinstance(root_data, dict) and root_data.get("detected"):
            recs["root"] = {
                "detected": True,
                "detail":   "Root indicators: " + ", ".join(root_data.get("indicators", [])),
                "severity": "High",
                "scripts":  self.script_index.get("root", []),
                "frida_cmd": self._frida_cmd("root", package_name),
                "safetynet":      root_data.get("safetynet", False),
                "play_integrity": root_data.get("play_integrity", False),
                "custom_methods": root_data.get("custom_methods", []),
                "su_paths":       root_data.get("su_path_checks", []),
                "manual_steps": [
                    "Run Frida bypass script (see command below)",
                    "If Magisk is installed, try Magisk Hide / DenyList for the target app",
                    "If SafetyNet present: use MagiskHide Props Config to spoof CTS profile",
                    "If Play Integrity present: harder — may need custom ROM or Shamiko module",
                    "For custom isRooted() methods: dynamic Frida hook (script auto-enumerates)",
                ],
            }

        # ── Proxy Detection ───────────────────────────────────────────────
        proxy_data = findings.get("ProxyDetection") or {}
        if isinstance(proxy_data, dict) and proxy_data.get("detected"):
            recs["proxy"] = {
                "detected": True,
                "detail":   f"{len(proxy_data.get('techniques',[]))} proxy detection technique(s)",
                "severity": "High",
                "scripts":  self.script_index.get("proxy", []),
                "frida_cmd": self._frida_cmd("proxy", package_name),
                "techniques": proxy_data.get("techniques", []),
                "manual_steps": [
                    "Run proxy_detection_bypass.js via Frida (see command below)",
                    "Use iptables redirect instead of system proxy:",
                    "  adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <burp_ip>:8080",
                    "Or use ProxyDroid app with transparent proxy mode",
                    "Combine with SSL bypass script for full interception",
                ],
            }

        # ── User-provided scripts (custom categories) ─────────────────────
        for script in self.all_scripts:
            cats = script.get("categories", [])
            if not any(c in recs for c in cats):
                # Script covers something not already in recs
                for cat in cats:
                    if cat not in ("ssl", "root", "proxy", "emulator"):
                        recs.setdefault(cat, {
                            "detected":  None,
                            "detail":    f"User script available: {script.get('name','unknown')}",
                            "scripts":   [script],
                            "frida_cmd": "",
                            "manual_steps": [],
                        })

        return recs

    def _frida_cmd(self, category: str, package: str) -> str:
        """Generate the Frida command to run the best script for this category."""
        scripts = self.script_index.get(category, [])
        if not scripts:
            return f"# No script found for {category}. Drop a .js file in frida_scripts/"

        # Prefer built-in scripts first
        builtin = [s for s in scripts if "APKGraph Built-in" in s.get("description", "") or
                   s["file"] in ("ssl_pinning_universal.js", "root_detection_bypass.js", "proxy_detection_bypass.js")]
        best = builtin[0] if builtin else scripts[0]

        script_path = best["path"]
        return (
            f"# Spawn with bypass:\n"
            f"frida -U -f {package} -l \"{script_path}\" --no-pause\n\n"
            f"# Or attach to running process:\n"
            f"frida -U {package} -l \"{script_path}\"\n\n"
            f"# List available scripts:\n"
            f"ls {self.scripts_dir}/*.js"
        )

    def add_user_script(self, js_path: str) -> dict:
        """
        Index a user-provided script at js_path.
        Returns the parsed metadata.
        """
        path = Path(js_path)
        if not path.exists():
            return {"error": f"File not found: {js_path}"}
        meta       = _parse_script_meta(path)
        categories = _classify_script(meta)
        meta["categories"] = categories
        meta["user_provided"] = True
        self.all_scripts.append(meta)
        for cat in categories:
            self.script_index.setdefault(cat, []).append(meta)
        return meta

    def list_scripts_summary(self) -> list:
        """Return a summary list for display in CLI/report."""
        return [
            {
                "file":        s["file"],
                "name":        s.get("name", s["file"]),
                "bypass":      s.get("bypass", "unknown"),
                "targets":     s.get("targets", ""),
                "categories":  s.get("categories", []),
                "user":        s.get("user_provided", False),
            }
            for s in self.all_scripts
        ]
