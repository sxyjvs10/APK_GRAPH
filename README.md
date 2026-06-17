# APKGraph

**Android Attack Surface Intelligence Platform**

APKGraph is a high-efficiency tool designed to transform Android applications into a complete attack surface graph. Instead of producing thousands of isolated findings, APKGraph correlates components and predicts potential attack paths, helping security researchers and bug bounty hunters focus on actionable intelligence.

## Key Features

- **Multi-Layered Analysis**: Deep extraction of Manifest, DEX, Resources, and Analysis artifacts.
- **12 Specialized Intelligence Modules**:
  - **Manifest Analyzer**: Exported components, dangerous permissions.
  - **Secret Analyzer**: API keys, AWS secrets, hardcoded credentials.
  - **Endpoint Analyzer**: URL extraction, GraphQL/WebSocket detection.
  - **Deep Link Analyzer**: URI schemes, App Links, Intent filters.
  - **Crypto Analyzer**: Weak algorithms (MD5, SHA1) and insecure configurations.
  - **JWT Module**: Detection and decoding of hardcoded JWTs.
  - **WebView Analyzer**: Insecure WebView settings (JS enabled, file access).
  - **Root Detection & SSL Pinning**: Identification of hardening controls.
- **Knowledge Graph Engine**: Correlates findings into a relational model using NetworkX.
- **Attack Path Prediction**: Automatically predicts exploitation chains (e.g., Deep Link -> Auth Bypass -> Data Leakage).
- **Risk Scoring**: Provides a normalized risk score (0-100) and rating (Low to Critical).
- **Professional Reporting**: Generates detailed JSON and Markdown reports.

## Architecture

APKGraph follows a modular architecture as outlined in the [APKGraph Overview.pdf](./APKGraph%20Overview.pdf):

1. **APK Processing Layer**: Artifact extraction using Androguard.
2. **Intelligence Engine**: Parallel execution of analysis modules.
3. **Correlation Engine**: Building the knowledge graph.
4. **Prediction Engine**: Attack path generation.
5. **Report Generator**: Final output production.

## Installation

### Prerequisites
- Python 3.8+

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

## Usage

After installation, you can run the tool directly or using the provided launcher.

### Simple Launcher (Linux/macOS)
```bash
chmod +x apkgraph.sh
./apkgraph.sh <path_to_apk> -o my_report
```

### Direct CLI
```bash
apkgraph <path_to_apk> --output report
```

### Command Options
- `APK_PATH`: Path to the target .apk file.
- `-o, --output`: Base name for the generated reports (default: `report`).

## Output
- `report.json`: Full structured data and graph nodes/links.
- `report.md`: Professional executive summary of findings and attack paths.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
