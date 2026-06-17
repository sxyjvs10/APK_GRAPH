import click
import sys
from rich.console import Console
from apkgraph.core.processing import APKProcessor
from apkgraph.engines.manifest import ManifestAnalyzer
from apkgraph.engines.secret import SecretAnalyzer
from apkgraph.engines.endpoint import EndpointAnalyzer
from apkgraph.engines.deeplink import DeepLinkAnalyzer
from apkgraph.engines.crypto import CryptoAnalyzer
from apkgraph.engines.ssl_pinning import SSLPinningAnalyzer
from apkgraph.engines.root_detection import RootDetectionAnalyzer
from apkgraph.engines.webview import WebViewAnalyzer
from apkgraph.engines.hidden_function import HiddenFunctionAnalyzer
from apkgraph.engines.sdk_fingerprint import SDKFingerprintAnalyzer
from apkgraph.engines.jwt import JWTAnalyzer
from apkgraph.engines.environment import EnvironmentDiscoveryAnalyzer
from apkgraph.core.graph import KnowledgeGraph
from apkgraph.core.predictor import AttackPathPredictor
from apkgraph.core.scorer import RiskScorer
from apkgraph.core.reporter import ReportGenerator

console = Console()

@click.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('--output', '-o', default='report', help='Output base name for reports')
def main(apk_path, output):
    console.print("[bold blue]APKGraph - Android Attack Surface Intelligence Platform[/bold blue]")
    
    try:
        # 1. APK Processing
        processor = APKProcessor(apk_path)
        apk_data = processor.process()
        
        # 2. Intelligence Modules
        console.print("[yellow][*] Running Intelligence Engines...[/yellow]")
        all_findings = {}
        
        modules = {
            "Manifest": ManifestAnalyzer,
            "Secret": SecretAnalyzer,
            "Endpoint": EndpointAnalyzer,
            "DeepLink": DeepLinkAnalyzer,
            "Crypto": CryptoAnalyzer,
            "SSLPinning": SSLPinningAnalyzer,
            "RootDetection": RootDetectionAnalyzer,
            "WebView": WebViewAnalyzer,
            "HiddenFunction": HiddenFunctionAnalyzer,
            "SDKFingerprint": SDKFingerprintAnalyzer,
            "JWT": JWTAnalyzer,
            "Environment": EnvironmentDiscoveryAnalyzer
        }

        for name, module_class in modules.items():
            console.print(f"  [cyan][>][/cyan] {name} Engine")
            analyzer = module_class(apk_data)
            all_findings[name] = analyzer.analyze()
        
        # 3. Knowledge Graph
        console.print("[yellow][*] Building Knowledge Graph...[/yellow]")
        kg = KnowledgeGraph()
        kg.correlate(all_findings)
        
        # 4. Attack Path Prediction
        console.print("[yellow][*] Predicting Attack Paths...[/yellow]")
        predictor = AttackPathPredictor(kg.graph)
        paths = predictor.predict()
        
        # 5. Risk Scoring
        console.print("[yellow][*] Calculating Risk Score...[/yellow]")
        scorer = RiskScorer(all_findings, paths)
        risk = scorer.calculate()
        
        # 6. Reporting
        report_data = {
            "findings": all_findings,
            "attack_paths": paths,
            "risk": risk,
            "graph": kg.get_graph_data()
        }
        
        reporter = ReportGenerator(report_data)
        reporter.generate_json(f"{output}.json")
        reporter.generate_markdown(f"{output}.md")
        
        console.print(f"[bold green][+] Analysis Complete! Risk Rating: {risk['rating']} ({risk['score']}/100)[/bold green]")

    except Exception as e:
        console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
