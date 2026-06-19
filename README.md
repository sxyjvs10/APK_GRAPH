# APKGraph v2.0

**Enterprise Android Attack Surface Intelligence Platform**

APKGraph is a high-efficiency Mobile Application Security Testing (MAST) platform designed to transform Android applications into a complete attack surface graph. Instead of producing thousands of isolated findings, APKGraph correlates components and predicts potential attack paths, helping security researchers and bug bounty hunters focus on actionable intelligence.

## 🚀 Key Features

- **Multi-Layered Analysis**: Deep extraction of Manifest, DEX, Resources, and Native JNI components.
- **Hybrid Dynamic Execution (Auto-Pwn)**: Bridges the static-to-dynamic gap by actively hooking devices via Frida and ADB.
- **22 Specialized Intelligence Engines**:
  - **Cross-Boundary Taint Tracker**: Traces user input from Dalvik boundaries (e.g., DeepLinks/ContentProviders) straight into C++ JNI code (`[NATIVE_JNI_SINK]`).
  - **Cross-Platform Support**: Scans and parses `index.android.bundle` for React Native Javascript exposure.
  - **Deobfuscator Engine**: Detects XOR/AES string decryption loops and automatically drops Frida `onLeave` hooks to dump decrypted strings at runtime.
  - **SCA & Yara Scanner**: Scans for known software components and malware signatures using bundled YARA rules.
  - **Native Library Analyzer**: Analyzes `.so` binaries for hidden strings and API secrets.
  - **Secret & JWT Analyzers**: API keys, AWS secrets, and hardcoded JWT extraction with Base64 heuristics.
  - **Deep Link & ICC Analyzers**: Maps Intent flows and URI schemes.
  - **Backend API Export**: Automatically extracts all endpoints into an `_endpoints.txt` and generates a ready-to-run `.sh` script for fuzzing via `ffuf` or `sqlmap`.
- **Attack Path Prediction**: Automatically predicts exploitation chains (e.g., Deep Link -> Auth Bypass -> Data Leakage).
- **Automated HTML Reporting**: Generates a single, beautiful HTML file containing all findings, CVSS severities, and copy-ready PoC reproduction steps.

## 🏗️ Architecture

1. **APK Processing Layer**: Artifact extraction using Androguard.
2. **Intelligence Engine**: Parallel execution of 22 analysis modules.
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
apkgraph <path_to_apk> --dynamic --fuzz
```
- `--dynamic`: Auto-generates `apkgraph_deobf_hook.js` and launches Frida on your attached USB/Emulator device to dynamically dump decrypted strings.
- `--fuzz`: Automatically writes an `intent_fuzzer.py` script specifically built for the exported activities in the target APK.
- `--format all`: Exports `.html`, `.json`, and `.md` reports.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
