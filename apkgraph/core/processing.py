"""
APKProcessor v2.0
-----------------
Fixes:
- CRITICAL: analysis.create_xref() is now called, enabling all taint/XREF analysis.
- Parallel DEX byte loading using ThreadPoolExecutor.
- Richer apk_data dict: app_name, min_sdk, target_sdk, cert_info, resource_files.
- Deduplication on raw_strings (was already a set, now explicit).
"""
import os
import sys
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

#  Silence ALL androguard output (it uses loguru, not standard logging) 
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except Exception:
    pass

# Also silence via standard logging for any handlers that use it
logging.disable(logging.CRITICAL)
for _name in list(logging.root.manager.loggerDict):
    if _name.startswith("androguard"):
        logging.getLogger(_name).setLevel(logging.CRITICAL)
        logging.getLogger(_name).propagate = False
logging.disable(logging.NOTSET)  # Re-enable for non-androguard loggers


def _parse_dex(dex_bytes: bytes) -> DEX:
    """Parse a single DEX byte blob - runs in thread pool."""
    return DEX(dex_bytes)


class APKProcessor:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = None
        self.dvms = []
        self.analysis = None

    def process(self) -> dict:
        print(f"[*] Processing APK: {self.apk_path}")
        self.apk = APK(self.apk_path)
        package_name = self.apk.get_package()

        # --- Parallel DEX Parsing ---
        all_dex_bytes = list(self.apk.get_all_dex())
        if len(all_dex_bytes) > 1:
            with ThreadPoolExecutor(max_workers=min(len(all_dex_bytes), 4)) as ex:
                self.dvms = list(ex.map(_parse_dex, all_dex_bytes))
        else:
            self.dvms = [_parse_dex(b) for b in all_dex_bytes]

        # --- String Extraction (fast path: DEX string tables) ---
        raw_strings: set[str] = set()
        for dvm in self.dvms:
            for s in dvm.get_strings():
                raw_strings.add(s)

        # --- XREF Analysis (CRITICAL FIX: was missing create_xref() call) ---
        self.analysis = Analysis()
        for dvm in self.dvms:
            self.analysis.add(dvm)
        self.analysis.create_xref()  # ← THE BUG FIX — without this, all taint analysis returns []

        # --- APK Metadata ---
        try:
            app_name = self.apk.get_app_name()
        except Exception:
            app_name = package_name

        try:
            cert_sha256 = None
            certs = self.apk.get_certificates()
            if certs:
                cert_sha256 = hashlib.sha256(certs[0].dump()).hexdigest()
        except Exception:
            cert_sha256 = None

        # --- Resource file list (for NetworkSecurityConfig, etc.) ---
        resource_files = list(self.apk.get_files())

        return {
            "apk": self.apk,
            "dvms": self.dvms,
            "analysis": self.analysis,
            "manifest": self.apk.get_android_manifest_xml(),
            "package": package_name,
            "app_name": app_name,
            "version_name": self.apk.get_androidversion_name() or "unknown",
            "version_code": self.apk.get_androidversion_code() or "unknown",
            "min_sdk": self.apk.get_min_sdk_version() or "unknown",
            "target_sdk": self.apk.get_target_sdk_version() or "unknown",
            "cert_sha256": cert_sha256,
            "resources": resource_files,
            "raw_strings": list(raw_strings),
        }
