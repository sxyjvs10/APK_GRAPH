"""
BaseIntelligenceModule v2.0
---------------------------
- Extended is_library() with broader prefix coverage (React Native, Cordova, Unity, etc.)
- Added get_resource_bytes() helper for engines that need to read embedded resource files.
- Added severity constants for consistent risk labelling.
"""
from abc import ABC, abstractmethod

# Canonical severity constants shared by all engines
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH     = "High"
SEVERITY_MEDIUM   = "Medium"
SEVERITY_LOW      = "Low"
SEVERITY_INFO     = "Info"

# Expanded library prefix list — keeps all engines noise-free
_LIBRARY_PREFIXES = frozenset([
    "Landroid/", "Landroidx/", "Lcom/google/", "Lcom/android/",
    "Lkotlin/", "Lkotlinx/", "Lorg/jetbrains/",
    # Networking
    "Lcom/squareup/", "Lokhttp3/", "Lretrofit2/",
    # Social / Analytics
    "Lcom/facebook/", "Lcom/mixpanel/", "Lcom/amplitude/",
    "Lcom/appsflyer/", "Lio/branch/", "Lcom/onesignal/",
    # Game engines / runtime
    "Lcom/unity3d/", "Lcom/epicgames/",
    # Cloud
    "Lcom/amazon/", "Lcom/amazonaws/", "Lcom/microsoft/",
    "Lcom/google/protobuf/", "Lcom/google/gson/",
    # UI / Animation
    "Lcom/airbnb/lottie/", "Lcom/bumptech/glide/", "Lcom/squareup/picasso/",
    # React Native / Cordova / Flutter
    "Lcom/facebook/react/", "Lorg/apache/cordova/", "Lio/flutter/",
    # Testing (should never appear in prod APKs, but filter if present)
    "Lorg/junit/", "Lorg/mockito/", "Lorg/robolectric/",
    # Apache / Guava / Jackson
    "Lorg/apache/", "Lcom/google/common/", "Lcom/fasterxml/jackson/",
])


class BaseIntelligenceModule(ABC):
    def __init__(self, apk_data: dict):
        self.apk_data = apk_data
        self.findings = []

    @abstractmethod
    def analyze(self):
        """Perform analysis and return findings."""
        pass

    def get_findings(self):
        return self.findings

    # ------------------------------------------------------------------
    # Manifest helpers
    # ------------------------------------------------------------------
    def is_exported(self, component_name: str) -> bool:
        """Check if a component is exported in the AndroidManifest."""
        manifest_xml = self.apk_data["manifest"]
        for application in manifest_xml.findall("application"):
            for tag in ("activity", "service", "receiver", "provider"):
                for component in application.findall(tag):
                    name = component.get(
                        "{http://schemas.android.com/apk/res/android}name"
                    )
                    if name == component_name or self._normalize_name(name) == component_name:
                        exported = component.get(
                            "{http://schemas.android.com/apk/res/android}exported"
                        )
                        if exported:
                            return exported.lower() == "true"
                        # Implicit export: has intent-filter
                        return len(component.findall("intent-filter")) > 0
        return False

    def _normalize_name(self, name: str) -> str:
        if not name:
            return ""
        if name.startswith("."):
            return self.apk_data["package"] + name
        return name

    # ------------------------------------------------------------------
    # Library / noise filtering
    # ------------------------------------------------------------------
    def is_library(self, class_name: str) -> bool:
        """Return True if class_name belongs to a known third-party library."""
        if not class_name:
            return False
        return any(class_name.startswith(p) for p in _LIBRARY_PREFIXES)

    # ------------------------------------------------------------------
    # Resource helper
    # ------------------------------------------------------------------
    def get_resource_bytes(self, resource_path: str) -> bytes | None:
        """
        Read an embedded resource from the APK zip.
        Returns raw bytes or None if not found.
        """
        try:
            apk = self.apk_data["apk"]
            return apk.get_file(resource_path)
        except Exception:
            return None
