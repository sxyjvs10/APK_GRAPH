import os
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

class APKProcessor:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.dvms = []
        self.analysis = None

    def process(self):
        print(f"[*] Processing APK: {self.apk_path}")
        self.apk = APK(self.apk_path)
        
        # Load DEX files
        for dex in self.apk.get_all_dex():
            self.dvms.append(DEX(dex))
        
        # Static Analysis
        self.analysis = Analysis()
        for dvm in self.dvms:
            self.analysis.add(dvm)
        
        self.analysis.create_xref()
        
        return {
            "apk": self.apk,
            "dvms": self.dvms,
            "analysis": self.analysis,
            "manifest": self.apk.get_android_manifest_xml(),
            "package": self.apk.get_package(),
            "resources": self.apk.get_files()
        }
