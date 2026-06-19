"""
SDKFingerprintAnalyzer v3.0 (SCA Engine)
-----------------------------------------
Upgrades:
- Now acts as a Software Composition Analysis (SCA) engine.
- Extracts exact library versions from META-INF and .properties files.
- Checks versions against a database of known vulnerable components.
- Highlights high-risk outdated dependencies (e.g., vulnerable OkHttp, Firebase).
"""
import re
from apkgraph.core.engine import BaseIntelligenceModule, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW

# Dict: name → package_prefix (unique substring in class path)
_SDK_CATALOG = {
    "Firebase":          "com/google/firebase",
    "Firebase Crashlytics": "com/google/firebase/crashlytics",
    "Firebase Analytics":   "com/google/firebase/analytics",
    "Firebase Auth":        "com/google/firebase/auth",
    "AWS SDK":           "com/amazonaws",
    "Azure SDK":         "com/microsoft/azure",
    "OneSignal":         "com/onesignal",
    "Mixpanel":          "com/mixpanel",
    "Amplitude":         "com/amplitude",
    "Branch SDK":        "io/branch",
    "AppsFlyer":         "com/appsflyer",
    "Segment Analytics": "com/segment/analytics",
    "Retrofit":          "retrofit2",
    "OkHttp":            "okhttp3",
    "Glide":             "com/bumptech/glide",
    "Picasso":           "com/squareup/picasso",
    "Lottie":            "com/airbnb/lottie",
    "Gson":              "com/google/gson",
    "Jackson":           "com/fasterxml/jackson",
    "ExoPlayer":         "com/google/android/exoplayer2",
    "Guava":             "com/google/common",
    "RxJava":            "io/reactivex",
    "Dagger":            "dagger",
    "Hilt":              "dagger/hilt",
    "Room":              "androidx/room",
    "WorkManager":       "androidx/work",
}

# Heuristics for known vulnerable component versions
_KNOWN_VULNERABILITIES = {
    "okhttp3": {
        "name": "OkHttp",
        "vuln_regex": r"^(1\.|2\.|3\.[0-9]\.|3\.1[0-2]\.)",
        "desc": "CVE-2021-0341: TLS verification bypass in versions < 3.12.13.",
        "severity": SEVERITY_HIGH,
    },
    "firebase-messaging": {
        "name": "Firebase Cloud Messaging",
        "vuln_regex": r"^(1[0-9]\.|2[0-1]\.)",
        "desc": "Outdated Firebase Messaging SDK versions < 22.0.0 have pending deprecation/security issues.",
        "severity": SEVERITY_MEDIUM,
    },
    "retrofit": {
        "name": "Retrofit",
        "vuln_regex": r"^(1\.|2\.[0-4]\.)",
        "desc": "Retrofit versions < 2.5.0 have request forgery flaws.",
        "severity": SEVERITY_MEDIUM,
    },
    "play-core": {
        "name": "Google Play Core",
        "vuln_regex": r"^(1\.[0-6]\.)",
        "desc": "CVE-2020-8913: Google Play Core Library local arbitrary code execution. Update to 1.7.2+.",
        "severity": SEVERITY_HIGH,
    }
}

class SDKFingerprintAnalyzer(BaseIntelligenceModule):
    def analyze(self) -> list[dict]:
        analysis = self.apk_data["analysis"]
        apk = self.apk_data.get("apk")
        
        # 1. Base Class Identification
        class_names: set[str] = {cls.name for cls in analysis.get_classes()}
        detected: dict[str, dict] = {}
        
        for cls_name in class_names:
            for sdk_name, prefix in _SDK_CATALOG.items():
                if sdk_name in detected:
                    continue
                if prefix in cls_name:
                    detected[sdk_name] = {
                        "sdk": sdk_name,
                        "package_prefix": prefix,
                        "example_class": cls_name,
                        "version": "Unknown (Inferred from bytecode)",
                        "vulnerability": None
                    }

        # 2. Precise Version Extraction from META-INF / Properties
        if apk:
            files = apk.get_files()
            for f in files:
                f_lower = f.lower()
                if "version" in f_lower or "properties" in f_lower or "pom.xml" in f_lower:
                    try:
                        data = apk.get_file(f).decode('utf-8', errors='ignore')
                        lines = [l.strip() for l in data.split('\n') if l.strip() and not l.startswith('#')]
                        
                        # Parse properties
                        version = None
                        client = None
                        for line in lines:
                            if line.startswith("version="):
                                version = line.split("=", 1)[1].strip()
                            elif line.startswith("client="):
                                client = line.split("=", 1)[1].strip()
                                
                        if version and client:
                            # Update or add
                            sdk_display_name = next((k for k, v in _SDK_CATALOG.items() if v in client or client in v), client.replace('-', ' ').title())
                            
                            # Check CVEs
                            vuln_info = None
                            for v_id, v_data in _KNOWN_VULNERABILITIES.items():
                                if v_id in client.lower():
                                    if re.match(v_data["vuln_regex"], version):
                                        vuln_info = {
                                            "cve_desc": v_data["desc"],
                                            "severity": v_data["severity"]
                                        }

                            detected[client] = {
                                "sdk": sdk_display_name,
                                "package_prefix": client,
                                "version": version,
                                "vulnerability": vuln_info
                            }
                    except Exception:
                        pass

        self.findings = list(detected.values())
        return self.findings
