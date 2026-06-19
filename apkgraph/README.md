# APKGraph v2.0 - Android Attack Surface Intelligence Platform

APKGraph is an advanced, automated static analysis and attack surface mapping tool for Android applications. It goes beyond basic string matching by constructing a comprehensive Knowledge Graph of an application's internal components, analyzing data flows, and automatically predicting potential attack paths.

## Features

- **Multi-Engine Analysis:** Utilizes 20 distinct intelligence engines to analyze everything from Manifest configurations to hardcoded secrets and cryptographic implementations.
- **Knowledge Graph Generation:** Correlates findings into a directed graph (nodes and edges) to understand how different vulnerabilities interact (e.g., Deep Link -> Exported Component -> Insecure WebView).
- **Attack Path Prediction:** Automatically calculates paths an attacker could take to chain low-severity findings into high-impact exploits.
- **Intent Fuzzer Generation:** Optionally generates standalone Python scripts capable of actively fuzzing the target application's exported components via ADB.
- **Comprehensive Reporting:** Outputs findings in JSON, Markdown, and HTML formats, including a normalized CVSS-style risk score.

## Architecture & Engines

APKGraph uses a modular engine system. Key engines include:
*   `CryptoAnalyzer`: Detects weak algorithms, static IVs, and hardcoded key material via taint analysis.
*   `SecretAnalyzer`: Identifies exposed API keys, tokens, and infrastructure credentials using entropy checks to reduce noise.
*   `SSLPinningAnalyzer`: Analyzes custom `TrustManager` implementations and OkHttp configurations for pinning bypasses.
*   `IntentHijackingAnalyzer`: Tracks implicit intent flows that could be intercepted by malicious apps.
*   `DataStorageAnalyzer`: Maps insecure local storage mechanisms (e.g., `SharedPreferences`, internal files).
*   `RootDetectionAnalyzer` & `ProxyDetectionAnalyzer`: Identifies defensive mechanisms implemented by the application.

## Installation

### Linux / macOS
```bash
git clone https://github.com/<your-username>/apkgraph.git
cd apkgraph
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows
APKGraph includes a robust batch script (`apkgraph.bat`) designed specifically for Windows environments. It completely automates the Python setup so you don't have to manually manage virtual environments.

**Prerequisites:**
1. Install [Python 3.8+](https://www.python.org/downloads/windows/). **Important:** During installation, ensure you check the box that says **"Add Python to PATH"**.

**Setup & Usage:**
1. Open **Command Prompt** or **Windows Terminal**.
2. Navigate to the downloaded APKGraph folder:
   ```cmd
   cd path\to\apkgraph
   ```
3. Run the batch script against your target APK:
   ```cmd
   apkgraph.bat "target_app.apk" -o scan_results
   ```

*On the very first run, `apkgraph.bat` will automatically create an isolated Python virtual environment, download all required dependencies (like Androguard, NetworkX, Frida, and Yara), and then start the scan. Subsequent runs will launch instantly.*

## Usage

The tool requires an APK file to scan. It will automatically decompile the APK, run all intelligence engines, build the Knowledge Graph, and output the reports.

### Basic Scan
Run a standard analysis against a target APK:
```bash
apkgraph "target_app.apk" -o scan_results
```
*(On Windows, use `apkgraph.bat "target_app.apk" -o scan_results`)*

### Verbose Mode
Enable verbose output to see real-time engine processing and detailed stack traces:
```bash
apkgraph "target_app.apk" -o scan_results -v
```

### Generate Intent Fuzzer
Use the `--fuzz` flag to instruct the tool to generate an active exploit fuzzer script based on the findings. This script can be run against a connected emulator or physical device via ADB to test exported components:
```bash
apkgraph "target_app.apk" -o scan_results --fuzz
```

## Output Artifacts

After a successful scan, APKGraph generates the following artifacts in the output directory:
1.  **JSON Report (`<output>.json`)**: Raw, machine-readable findings and graph data.
2.  **Markdown Report (`<output>.md`)**: A structured, readable report suitable for documentation or GitHub.
3.  **HTML Report (`<output>.html`)**: An interactive visual report for easy review.
4.  **Fuzzer Script (`<output>_fuzzer.py`)**: *(If `--fuzz` was used)* A ready-to-run Python script for ADB interaction.

## Disclaimer

**Educational and Authorized Use Only.**
APKGraph is designed to assist security researchers, penetration testers, and developers in identifying and mitigating vulnerabilities within applications they own or have explicit authorization to test. Do not use this tool against targets without prior mutual consent.
