"""
Hybrid Dynamic Execution Engine v1.0
------------------------------------
Bridges the gap between Static Analysis and Dynamic Application Security Testing (DAST).
Automatically connects to a device via ADB, ensures the APK is installed,
and auto-injects the highest-confidence Frida bypass scripts identified during the static phase.
"""
import subprocess
import time
import os
import shutil
from rich.console import Console

console = Console()

class DynamicRunner:
    def __init__(self, apk_path: str, package_name: str, bypass_recs: dict, all_findings: dict):
        self.apk_path = apk_path
        self.package_name = package_name
        self.bypass_recs = bypass_recs
        self.all_findings = all_findings
        self.device_connected = False

    def _run_cmd(self, cmd: list) -> str:
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            return result.stdout.strip()
        except Exception:
            return ""

    def check_prerequisites(self) -> bool:
        """Check if adb and frida are available, and a device is connected."""
        console.print("\n[bold cyan]── Hybrid Dynamic Execution (Auto-Pwn) ──[/]")
        
        # Check adb
        adb_path = shutil.which("adb") or shutil.which("adb.exe")
        if not adb_path and not os.path.exists("adb.exe"):
            console.print("[red]❌ ADB not found in PATH or current directory.[/]")
            return False
            
        # Check frida
        if not shutil.which("frida") and not shutil.which("frida.exe"):
            console.print("[red]❌ frida-tools not found in PATH.[/]")
            return False
            
        # Check connected devices
        adb_devices = self._run_cmd(["adb", "devices"])
        device_count = sum(1 for line in adb_devices.split("\n") if "device" in line and "List" not in line)
        if device_count == 0:
            console.print("[red]❌ No Android device connected via ADB.[/]")
            return False
            
        console.print("[green]✔ Prerequisite checks passed (ADB + Frida + Device connected)[/]")
        self.device_connected = True
        return True

    def install_target(self):
        """Ensure the APK is installed on the device."""
        console.print(f"[*] Checking if {self.package_name} is installed...")
        packages = self._run_cmd(["adb", "shell", "pm", "list", "packages", self.package_name])
        
        if self.package_name not in packages:
            console.print(f"[*] Installing {self.apk_path} on device...")
            install_result = self._run_cmd(["adb", "install", "-r", self.apk_path])
            if "Success" in install_result:
                console.print("[green]✔ Installation successful[/]")
            else:
                console.print(f"[yellow]⚠ Installation might have failed: {install_result}[/]")
        else:
            console.print("[green]✔ Target app already installed[/]")

    def start_autopwn(self):
        """Build the ultimate Frida command using the recommended scripts and launch it."""
        if not self.device_connected:
            return
            
        self.install_target()
        
        scripts_to_load = []
        for cat, rec in self.bypass_recs.items():
            if rec.get("detected") and rec.get("scripts"):
                # Take the highest confidence script for this category
                best_script = rec["scripts"][0]["path"]
                if best_script not in scripts_to_load:
                    scripts_to_load.append(best_script)
                    
        # Add dynamic string dumping hooks if deobfuscation targets were found
        deobf = self.all_findings.get("Deobfuscation", {}).get("detected_methods", [])
        if deobf:
            console.print(f"[bold cyan][*] Generating auto-deobfuscation script for {len(deobf)} target methods...[/]")
            deobf_script_path = os.path.join(os.path.dirname(self.apk_path), "apkgraph_deobf_hook.js")
            with open(deobf_script_path, "w") as f:
                f.write("setTimeout(function() {\n")
                f.write("  console.log('[+] APKGraph String Deobfuscator Loaded!');\n")
                for method in deobf:
                    f.write(f"  try {{ {method['frida_hook']} }} catch(e) {{ }}\n")
                f.write("}, 2000);\n")
            scripts_to_load.append(deobf_script_path)
                    
        if not scripts_to_load:
            console.print("[yellow]⚠ No static protections found that require a bypass script. Spawning app normally.[/]")
        
        # Build frida command
        cmd = ["frida", "-U", "-f", self.package_name]
        for script in scripts_to_load:
            if os.path.exists(script):
                cmd.extend(["-l", script])
            else:
                console.print(f"[yellow]⚠ Warning: Recommended bypass script {script} not found on disk.[/]")
            
        cmd_str = " ".join(cmd)
        console.print(f"\n[bold green]🚀 Launching Auto-Pwn Hybrid Execution![/]")
        console.print(f"   [dim]{cmd_str}[/]")
        console.print("[yellow]   (Press Ctrl+C to stop the dynamic session)[/yellow]\n")
        
        try:
            # We use Popen without pipes so the user can interact with the Frida REPL
            subprocess.run(cmd)
        except KeyboardInterrupt:
            console.print("\n[bold green]✔ Dynamic execution session ended.[/]")
        except Exception as e:
            console.print(f"[bold red]❌ Failed to run Frida: {e}[/]")
