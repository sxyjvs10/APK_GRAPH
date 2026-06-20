import markdown
from weasyprint import HTML

md_text = """
# APKGraph v2.0 - Overview
## Android Attack Surface Intelligence Platform

APKGraph has been vastly upgraded to v2.0. It is a high-efficiency Mobile Application Security Testing (MAST) platform designed to transform Android applications into a complete attack surface graph. Instead of producing thousands of isolated findings, APKGraph correlates components and predicts potential attack paths.

### New Features in v2.0:

#### 1. 22 Specialized Intelligence Engines
- **App & Configuration**: Manifest, WebView, Environment Discovery, and SDK Fingerprint Analyzers.
- **Data & Secrets**: Secret, JWT, Endpoint, and Data Storage Analyzers.
- **Networking & Crypto**: Crypto, SSL Pinning, Network Security Config, and Proxy Detection Analyzers.
- **Anti-Reversing & Evasion**: Root Detection, Deobfuscation, Hidden Function, and Frida Hook Analyzers.
- **Component Interactions**: Deep Link, Inter-Component Communication (ICC), and Intent Hijacking Analyzers.
- **Native & Cross-Platform**: Cross-Platform (React Native), Native Library (`.so`), and YARA Scanner Analyzers.

#### 2. Hybrid Dynamic Execution (Auto-Pwn)
Bridges the static-to-dynamic gap. APKGraph automatically orchestrates `frida` over USB/ADB to hook your live Android application and bypass security protections.

#### 3. Knowledge Graph & Correlation
Automatically correlates findings from all 22 engines into a comprehensive Knowledge Graph (Nodes/Edges).

#### 4. Automated Backend Probing & Fuzzing Generation
Generates two actionable artifacts for your live testing:
1. `_endpoints.txt`: A clean dictionary of every backend route.
2. `_backend_scan.sh`: A pre-formatted BASH script ready to be fed directly into `ffuf` or `sqlmap`.
3. `intent_fuzzer.py`: Generates custom Python fuzzer scripts tailored to the exported components found in the target APK.

#### 5. Risk Scorer & Bypass Recommender
Calculates an overall risk score/rating and recommends security bypasses for specific protections.

#### 6. Next-Gen Reporting
Generates comprehensive JSON, Markdown, and beautifully styled HTML reports containing all findings, CVSS severities, and copy-ready PoC reproduction steps.
"""

html_text = f"""
<!DOCTYPE html>
<html>
<head>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }}
h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #34495e; }}
h3 {{ color: #e74c3c; margin-top: 30px; }}
h4 {{ color: #2980b9; }}
ul {{ padding-left: 20px; }}
li {{ margin-bottom: 10px; }}
code {{ background-color: #f1f1f1; padding: 2px 5px; border-radius: 4px; font-family: monospace; color: #c0392b; }}
</style>
</head>
<body>
{markdown.markdown(md_text)}
</body>
</html>
"""

HTML(string=html_text).write_pdf("APKGraph Overview v2.pdf")
print("Generated APKGraph Overview v2.pdf")
