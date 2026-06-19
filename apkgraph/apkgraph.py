"""
APKGraph v2.0 - Android Attack Surface Intelligence Platform
"""
import sys
import os
import json
import time
import click
import concurrent.futures
from concurrent.futures import TimeoutError as FutureTimeoutError

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

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
from apkgraph.engines.icc import ICCAnalyzer
from apkgraph.engines.data_storage import DataStorageAnalyzer
from apkgraph.engines.network_security_config import NetworkSecurityConfigAnalyzer
from apkgraph.engines.intent_hijacking import IntentHijackingAnalyzer
from apkgraph.engines.proxy_detection import ProxyDetectionAnalyzer
from apkgraph.engines.frida_hooks import FridaHookAnalyzer
from apkgraph.engines.native_lib import NativeLibraryAnalyzer
from apkgraph.engines.yara_scanner import YaraScannerAnalyzer
from apkgraph.engines.deobfuscator import DeobfuscationAnalyzer
from apkgraph.engines.cross_platform import CrossPlatformAnalyzer

from apkgraph.core.graph import KnowledgeGraph
from apkgraph.core.predictor import AttackPathPredictor
from apkgraph.core.scorer import RiskScorer
from apkgraph.core.bypass_engine import BypassEngine
from apkgraph.core.reporter import ReportGenerator
from apkgraph.core.dynamic import DynamicRunner
from apkgraph.core.fuzzer_gen import IntentFuzzerGenerator

console = Console()

ALL_MODULES = {
    "Manifest":              ManifestAnalyzer,
    "Secret":                SecretAnalyzer,
    "Endpoint":              EndpointAnalyzer,
    "DeepLink":              DeepLinkAnalyzer,
    "Crypto":                CryptoAnalyzer,
    "SSLPinning":            SSLPinningAnalyzer,
    "RootDetection":         RootDetectionAnalyzer,
    "WebView":               WebViewAnalyzer,
    "HiddenFunction":        HiddenFunctionAnalyzer,
    "SDKFingerprint":        SDKFingerprintAnalyzer,
    "JWT":                   JWTAnalyzer,
    "Environment":           EnvironmentDiscoveryAnalyzer,
    "ICC":                   ICCAnalyzer,
    "DataStorage":           DataStorageAnalyzer,
    "NetworkSecurityConfig": NetworkSecurityConfigAnalyzer,
    "IntentHijacking":       IntentHijackingAnalyzer,
    "ProxyDetection":        ProxyDetectionAnalyzer,
    "FridaHookAnalysis":     FridaHookAnalyzer,
    "NativeLibrary":         NativeLibraryAnalyzer,
    "YaraScanner":           YaraScannerAnalyzer,
    "Deobfuscation":         DeobfuscationAnalyzer,
    "CrossPlatform":         CrossPlatformAnalyzer,
}

_PHASE_APK_LOAD    = 10
_PHASE_ENGINES     = 70
_PHASE_GRAPH       =  5
_PHASE_PREDICTOR   =  5
_PHASE_SCORER      =  3
_PHASE_REPORTS     =  7

_RATING_COLOR = {
    "Critical":      "bold red",
    "High":          "bold orange3",
    "Medium":        "bold yellow",
    "Low":           "bold green",
    "Informational": "bold blue",
}

@click.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--output",  "-o", default="report",
              help="Output report prefix (default: 'report')")
@click.option("--format",  "-f", "fmt", default="html",
              help="Output format: json, md, html, all (default: 'html')")
@click.option("--modules", "-m", default="all",
              help="Comma-separated engine names, or 'all'.")
@click.option("--timeout", "-t", default=120, type=int,
              help="Analysis timeout in seconds")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose debug logging")
@click.option("--dynamic", "-d", is_flag=True, default=False,
              help="Enable Hybrid Dynamic Execution (Auto-Pwn via ADB/Frida)")
@click.option("--fuzz", is_flag=True, default=False,
              help="Generate an Intent Fuzzer script for exported components")
def main(apk_path, output, fmt, modules, timeout, verbose, dynamic, fuzz):
    """
    APKGraph v2.0 — Android Attack Surface Intelligence Platform
    """
    console.print()
    console.print("╭──────────────────────────────────────────────────────────────────╮", style="bold blue")
    console.print("│  [bold white]APKGraph v2.0[/]  |  [cyan]Android Attack Surface Intelligence Platform[/]  │", style="bold blue")
    console.print("╰──────────────────────────────────────────────────────────────────╯", style="bold blue")
    console.print()

    if modules.lower() == "all":
        selected_modules = ALL_MODULES
    else:
        selected_names = [x.strip() for x in modules.split(",")]
        selected_modules = {}
        for name in selected_names:
            if name in ALL_MODULES:
                selected_modules[name] = ALL_MODULES[name]
            else:
                console.print(f"[bold red][!] Unknown module: {name}[/]")
                sys.exit(1)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("[progress.elapsed]{task.elapsed}s"),
            console=console
        ) as progress:
            task = progress.add_task("[bold cyan]Phase 1/7: Extracting & Decompiling APK...[/]", total=100)

            # ── 1. Load APK ────────────────────────────────────────────────────────
            processor = APKProcessor(apk_path)
            apk_meta = processor.process()
            
            app_name = apk_meta.get("app_name", "Unknown")
            app_pkg  = apk_meta.get("package", "unknown")
            sdk_min  = apk_meta.get("min_sdk", "?")
            sdk_tgt  = apk_meta.get("target_sdk", "?")

            progress.update(task, advance=_PHASE_APK_LOAD, 
                            description=f"[bold cyan]Phase 2/7: Running {len(selected_modules)} Engines...[/]")

            console.print(f"[*] Processing APK: [bold white]{os.path.basename(apk_path)}[/]")
            console.print(f"  Package [bold cyan]{app_pkg}[/]  {app_name}  SDK {sdk_min}→{sdk_tgt}\n")

            # ── 2. Run Engines Parallel ────────────────────────────────────────────
            all_findings  = {}
            engine_status = {}
            total_engines = len(selected_modules)
            completed_engines = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, total_engines)) as executor:
                future_to_name = {}
                for name, module_class in selected_modules.items():
                    analyzer = module_class(apk_meta)
                    future = executor.submit(analyzer.analyze)
                    future_to_name[future] = name

                for future in concurrent.futures.as_completed(future_to_name):
                    name = future_to_name[future]
                    try:
                        result = future.result(timeout=timeout)
                        all_findings[name]  = result
                        engine_status[name] = "ok"
                    except FutureTimeoutError:
                        engine_status[name] = "timeout"
                        all_findings[name]  = {"error": "timeout"}
                    except Exception as exc:
                        engine_status[name] = "error"
                        all_findings[name]  = {"error": str(exc)}
                        if verbose:
                            console.print(f"[red]Error in {name}: {exc}[/]")

                    completed_engines += 1
                    step_advance = _PHASE_ENGINES / total_engines
                    progress.update(task, advance=step_advance)

            # ── 3. Knowledge Graph ─────────────────────────────────────────────────
            progress.update(task, description="[bold cyan]Phase 3/7: Knowledge Graph...[/]")
            kg = KnowledgeGraph()
            kg.correlate(all_findings)
            graph_summary = f"Nodes {kg.graph.number_of_nodes()} Edges {kg.graph.number_of_edges()}"
            progress.update(task, advance=_PHASE_GRAPH)

            # ── 4. Attack Paths ────────────────────────────────────────────────────
            progress.update(task, description="[bold cyan]Phase 4/7: Attack Paths...[/]")
            predictor = AttackPathPredictor(kg.graph)
            paths = predictor.predict()
            progress.update(task, advance=_PHASE_PREDICTOR)

            # ── 5. Risk Scorer ─────────────────────────────────────────────────────
            progress.update(task, description="[bold cyan]Phase 5/7: Scoring...[/]")
            scorer = RiskScorer(all_findings, paths)
            risk = scorer.calculate()
            progress.update(task, advance=_PHASE_SCORER)

            # ── 6. Bypass Recommender ──────────────────────────────────────────────
            progress.update(task, description="[bold cyan]Phase 6/7: Bypass Recommender...[/]")
            try:
                be = BypassEngine()
                bypass_recs = be.recommend(all_findings, apk_meta.get("package", "com.target.app"))
            except Exception as e:
                bypass_recs = {}
                if verbose:
                    console.print(f"[yellow]  BypassEngine warning: {e}[/yellow]")

            # ── 7. Reports ─────────────────────────────────────────────────────────
            progress.update(task, description="[bold cyan]Phase 7/7: Reports...[/]")
            report_data = {
                "findings":      all_findings,
                "attack_paths":  paths,
                "risk":          risk,
                "graph":         kg.get_graph_data(),
                "graph_summary": graph_summary,
                "apk_meta":      apk_meta,
                "bypass_recs":   bypass_recs,
            }

            reporter = ReportGenerator(report_data)
            if fmt in ("json", "all"):
                reporter.generate_json(f"{output}.json")
                console.print(f"[+] JSON report:     [cyan]{output}.json[/]")
            if fmt in ("md", "all"):
                reporter.generate_markdown(f"{output}.md")
                console.print(f"[+] Markdown report: [cyan]{output}.md[/]")
            if fmt in ("html", "all"):
                reporter.generate_html(f"{output}.html")
                console.print(f"[+] HTML report:     [cyan]{output}.html[/]")
            
            progress.update(task, completed=100, description="[bold green]Scan complete ✔[/]")

        # ── Output summary table ────────────────────────────────────────────────
        console.print("\n")
        table = Table(title="Engine Results", show_header=True, header_style="bold magenta")
        table.add_column("#", justify="right")
        table.add_column("Engine")
        table.add_column("Status")
        table.add_column("Findings", justify="right")

        for idx, (eng_name, eng_stat) in enumerate(engine_status.items(), 1):
            stat_str = "[green]✔ ok[/]" if eng_stat == "ok" else f"[red]✖ {eng_stat}[/]"
            res = all_findings.get(eng_name, {})
            # try to find a count
            count = 0
            if isinstance(res, dict):
                count = len(res) if "error" not in res else 0
            elif isinstance(res, list):
                count = len(res)
            
            table.add_row(str(idx), eng_name, stat_str, str(count))

        console.print(table, justify="center")
        console.print()

        r_col = _RATING_COLOR.get(risk['rating'], "bold white")
        console.print(f"╭{'─'*28} [bold green]✔ Analysis Complete[/] {'─'*29}╮")
        console.print(f"│    Risk Score  {str(risk['score']).rjust(3)}/100   Rating [{r_col}]{risk['rating'].ljust(43)}[/]│")
        console.print(f"│    Attack Paths {str(len(paths)).ljust(10)} Graph {graph_summary.ljust(40)}│")
        console.print(f"╰{'─'*78}╯")
        console.print()

        if fuzz:
            console.print("\n[*] Generating Intent Fuzzer script...")
            fuzzer = IntentFuzzerGenerator(apk_meta, all_findings)
            script_path = fuzzer.generate(output)
            if script_path:
                console.print(f"[bold green][+] Fuzzer generated at: {script_path}[/bold green]")
                console.print(f"    (Run with: python3 {script_path})")
            else:
                console.print("[yellow]⚠ No exported components found to fuzz.[/yellow]")

        if dynamic:
            runner = DynamicRunner(apk_path, apk_meta.get("package", "com.target.app"), bypass_recs, all_findings)
            if runner.check_prerequisites():
                runner.start_autopwn()
                
        # ── Final Report Link ───────────────────────────────────────────────────
        if fmt in ("html", "all"):
            abs_path = os.path.abspath(f"{output}.html")
            console.print(f"\n[bold green]🔗 HTML Report available at:[/] [underline cyan]file://{abs_path}[/]\n")

    except Exception as e:
        console.print(f"\n[bold red]✖ Analysis failed: {str(e)}[/]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
