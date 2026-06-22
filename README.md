<div align="center">
  <h1>🛡️ APKGraph v3.0</h1>
  <p><strong>Next-Generation Android Attack Surface Intelligence Platform</strong></p>
  <p>
    <a href="https://github.com/sxyjvs10/APK_GRAPH/releases"><img src="https://img.shields.io/badge/version-3.0-blue.svg?style=flat-square" alt="Version"></a>
    <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.8+-green.svg?style=flat-square" alt="Python Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-purple.svg?style=flat-square" alt="License"></a>
  </p>
</div>

<br/>

APKGraph is a high-efficiency Mobile Application Security Testing (MAST) platform designed to transform Android applications into a complete attack surface graph. Instead of producing thousands of isolated findings, APKGraph correlates components and predicts potential attack paths, helping security researchers and bug bounty hunters focus on actionable intelligence.

---

## 🚀 Key Features

- **Multi-Layered Analysis**: Deep extraction of Manifest, DEX, Resources, and Native JNI components.
- **Hybrid Dynamic Execution (Auto-Pwn)**: Bridges the static-to-dynamic gap by actively hooking devices via Frida and ADB.
- **31 Specialized Intelligence Engines**: Unmatched client-side vulnerability detection capabilities.
  - **App & Configuration**: Manifest, WebView, Environment Discovery, and SDK Fingerprint Analyzers.
  - **Data & Secrets**: Secret, JWT, Endpoint, Data Storage, Custom YAML, and **String Reconstructor** Analyzers.
  - **Networking & Crypto**: Crypto, SSL Pinning, Network Security Config, and Proxy Detection Analyzers.
  - **Anti-Reversing & Evasion**: Root Detection, Deobfuscation, Hidden Function, and Frida Hook Analyzers.
  - **Component Interactions**: Deep Link, Inter-Component Communication (ICC), and Intent Hijacking Analyzers.
  - **Native & Cross-Platform**: Cross-Platform (React Native), Native Library (`.so`), and YARA Scanner Analyzers.
  - **✨ Advanced Exploitation (New)**: **Phantom API Endpoint Hunter**, **Permission Gap (Supply Chain) Analyzer**, **Dead Code Resurrection Engine**.
  - **✨ Client-Side Protections (New)**: **Signature Integrity**, **Logcat Information Leakage**, **Screenshot Prevention**, and **Tapjacking** Analyzers.
- **Custom YAML Rules Engine (Nuclei-style)**: Support for dynamically loading external signature sets. Comes bundled with 250+ advanced, high-fidelity regex rules (including full Gitleaks integration) tailored for Web3, modern cloud APIs, and crypto secrets with built-in smart noise filtering.
- **Knowledge Graph & Correlation**: Automatically correlates findings from all 31 engines into a comprehensive Knowledge Graph (Nodes/Edges).
- **Attack Path Prediction**: Automatically predicts exploitation chains (e.g., Deep Link -> Auth Bypass -> Data Leakage) based on the Knowledge Graph.
- **Risk Scorer & Bypass Recommender**: Calculates an overall risk score/rating and recommends security bypasses for specific protections.
- **Intent Fuzzer Generator**: Automatically generates Python fuzzer scripts tailored to the exported components found in the target APK.
- **Automated Reporting**: Generates comprehensive JSON, Markdown, and beautiful HTML reports containing all findings, CVSS severities, interactive network graphs, and copy-ready PoC reproduction steps.

## 🏗️ Architecture

1. **APK Processing Layer**: Artifact extraction using Androguard.
2. **Intelligence Engine**: Parallel execution of 31 analysis modules.
3. **Correlation Engine**: Building the knowledge graph (Nodes/Edges).
4. **Prediction Engine**: Attack path generation.
5. **Dynamic Runner**: Orchestrating ADB and Frida for runtime hooks.
6. **Report Generator**: HTML rendering.

## ⚙️ Installation

### Prerequisites
- Python 3.8+
- `adb` and `frida-tools` (Required for Hybrid Dynamic Analysis)

### Setup
```bash
# Clone the repository
git clone https://github.com/username/apkgraph.git
cd apkgraph

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install .
```

## 🛠️ Usage

### Quick Scan (Default HTML Output)
```bash
apkgraph <path_to_apk> -o report
```
*Outputs `report.html` and automatically prints a clickable link to open it.*

### Advanced Options
```bash
apkgraph <path_to_apk> --rules rules/ --dynamic --fuzz
```
- `--rules`: Supply a path to a directory containing custom `.yaml` or `.yml` signature files. The engine will intelligently filter noise (like hashes and 3rd-party libs) from custom rule outputs.
- `--dynamic`: Auto-generates `apkgraph_deobf_hook.js` and launches Frida on your attached USB/Emulator device to dynamically dump decrypted strings.
- `--fuzz`: Automatically writes an `intent_fuzzer.py` script specifically built for the exported activities in the target APK.
- `--format all`: Exports `.html`, `.json`, and `.md` reports.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
