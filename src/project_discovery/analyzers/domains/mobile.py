"""Cross-platform mobile project, manifest and permission inventory."""
from __future__ import annotations

import json
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.parsers.expat import ExpatError  # plistlib raises it for malformed XML property lists

from ...core.safe_parsers import safe_xml_fromstring
from ...core.source_utils import describe_error, open_verified_binary, read_bytes_bounded, read_text_bounded
from ...models import FileRecord, Finding
from ..base import Analyzer

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_PRIVACY_KEYS = (
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSPhotoLibraryUsageDescription", "NSContactsUsageDescription",
    "NSBluetoothAlwaysUsageDescription", "NSFaceIDUsageDescription",
    "NSLocalNetworkUsageDescription", "NSHealthShareUsageDescription",
)
_MOBILE_SOURCE_EXTENSIONS = {".swift", ".m", ".mm", ".kt", ".kts", ".dart"}


class MobileIntelligenceAnalyzer(Analyzer):
    """Inspect Android/iOS/Flutter/React Native declarations without building apps."""

    name = "mobile-intelligence"
    domains = ("mobile", "privacy")
    languages = ("Android XML", "Gradle", "Swift", "Objective-C", "Kotlin", "Dart", "JSON", "Plist")

    def supports(self, record: FileRecord) -> bool:
        if record.error:
            return False
        name = Path(record.path).name.lower()
        parts = {part.lower() for part in Path(record.path).parts}
        return (
            name in {
                "androidmanifest.xml", "info.plist", "pubspec.yaml", "package.json",
                "app.json", "podfile", "project.pbxproj", "network_security_config.xml",
                "google-services.json", "google-services.plist",
            }
            or record.path.lower().endswith(".entitlements")
            or name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}
            and bool(parts & {"android", "app"})
            or record.extension in _MOBILE_SOURCE_EXTENSIONS
            and bool(parts & {"ios", "android", "lib", "app", "src"})
        )

    def analyze(self, path: Path, record: FileRecord) -> list[Finding]:
        name = Path(record.path).name.lower()
        if name == "androidmanifest.xml":
            return self._android_manifest(path, record)
        if name == "info.plist":
            return self._plist(path, record, entitlements=False)
        if record.path.lower().endswith(".entitlements"):
            return self._plist(path, record, entitlements=True)
        if name == "network_security_config.xml":
            return self._network_security(path, record)
        if name in {"package.json", "app.json"}:
            return self._json_manifest(path, record)
        if name == "pubspec.yaml":
            return self._flutter_manifest(path, record)
        if name == "podfile":
            return self._podfile(path, record)
        if name == "project.pbxproj":
            return self._xcode_project(path, record)
        if name in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
            return self._gradle(path, record)
        if name in {"google-services.json", "google-services.plist"}:
            return [Finding(
                "mobile",
                f"Mobile service configuration present: {record.path}",
                "A platform service configuration file is present. Configuration values "
                "and identifiers are intentionally not copied into the report.",
                confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
            )]
        return self._mobile_source(path, record)

    def _read_xml(self, path: Path, record: FileRecord):
        try:
            return safe_xml_fromstring(read_bytes_bounded(
                path, 16 * 1024 * 1024, expected_identity=record.analysis_identity,
            )), None
        except (OSError, ValueError, ET.ParseError) as exc:
            return None, Finding(
                "mobile", f"Mobile XML parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )

    def _android_manifest(self, path: Path, record: FileRecord) -> list[Finding]:
        root, error = self._read_xml(path, record)
        if error:
            return [error]
        package = root.attrib.get("package", "unspecified")
        permissions = sorted({
            element.attrib.get(_ANDROID_NS + "name", "")
            for element in root
            if element.tag.rsplit("}", 1)[-1] in {
                "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"
            }
        } - {""})
        components = []
        risky = []
        for element in root.iter():
            kind = element.tag.rsplit("}", 1)[-1]
            if kind in {"activity", "activity-alias", "service", "receiver", "provider"}:
                component = element.attrib.get(_ANDROID_NS + "name", "unnamed")
                exported = element.attrib.get(_ANDROID_NS + "exported")
                components.append(f"{kind}: {component} (exported={exported or 'implicit'})")
                if exported == "true":
                    risky.append((kind, component, "exported component"))
        app = next(
            (element for element in root if element.tag.rsplit("}", 1)[-1] == "application"),
            None,
        )
        if app is not None:
            for key, label in (
                ("usesCleartextTraffic", "cleartext traffic enabled"),
                ("debuggable", "debuggable application"),
                ("allowBackup", "application backup enabled"),
            ):
                if app.attrib.get(_ANDROID_NS + key, "").lower() == "true":
                    risky.append(("application", key, label))
        findings = [Finding(
            "mobile",
            f"Android application manifest: {package}",
            f"Detected {len(permissions)} declared permission(s) and "
            f"{len(components)} application component(s).",
            confidence="CONFIRMED",
            evidence=[record.path]
            + [f"permission: {item}" for item in permissions[:100]]
            + components[:100],
            analyzer=self.name,
        )]
        findings.extend(Finding(
            "security",
            f"Android manifest review: {label}",
            "Review the effective component exposure and application security policy.",
            confidence="INFERRED",
            evidence=[record.path, f"{kind}: {component}"],
            analyzer=self.name,
        ) for kind, component, label in risky)
        return findings

    def _plist(self, path: Path, record: FileRecord, entitlements: bool) -> list[Finding]:
        try:
            with open_verified_binary(path, record.analysis_identity) as stream:
                data = plistlib.load(stream)
        except (OSError, plistlib.InvalidFileException, ValueError, ExpatError) as exc:
            return [Finding(
                "mobile", f"Apple property list parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if not isinstance(data, dict):
            return []
        if entitlements:
            enabled = sorted(
                key for key, value in data.items()
                if value is True and key in {"get-task-allow", "com.apple.developer.networking.networkextension"}
            )
            groups = {
                key: len(value) for key, value in data.items()
                if key in {
                    "com.apple.security.application-groups",
                    "keychain-access-groups",
                    "com.apple.developer.associated-domains",
                } and isinstance(value, list)
            }
            findings = [Finding(
                "mobile",
                f"iOS entitlements: {record.path}",
                f"Detected {len(data)} entitlement key(s) and group declarations: "
                + ", ".join(f"{key}={count}" for key, count in sorted(groups.items())),
                confidence="CONFIRMED",
                evidence=[record.path] + [f"enabled entitlement: {key}" for key in enabled],
                analyzer=self.name,
            )]
            if data.get("get-task-allow") is True:
                findings.append(Finding(
                    "security",
                    f"iOS debug entitlement enabled: {record.path}",
                    "get-task-allow is true. Confirm this is not present in a distribution profile.",
                    confidence="INFERRED", evidence=[record.path], analyzer=self.name,
                ))
            return findings

        privacy = sorted(key for key in _PRIVACY_KEYS if key in data)
        ats = data.get("NSAppTransportSecurity")
        arbitrary = isinstance(ats, dict) and (
            ats.get("NSAllowsArbitraryLoads") is True
            or ats.get("NSAllowsArbitraryLoadsInWebContent") is True
        )
        findings = [Finding(
            "mobile",
            f"iOS application property list: {record.path}",
            f"Detected {len(privacy)} privacy usage-description key(s), "
            f"{len(data.get('UIBackgroundModes', [])) if isinstance(data.get('UIBackgroundModes'), list) else 0} "
            "background mode(s), and app transport security configuration.",
            confidence="CONFIRMED",
            evidence=[record.path] + [f"privacy declaration: {key}" for key in privacy],
            analyzer=self.name,
        )]
        if arbitrary:
            findings.append(Finding(
                "security",
                f"App Transport Security relaxed: {record.path}",
                "An NSAllowsArbitraryLoads setting is enabled. Review exceptions and restrict "
                "cleartext or non-compliant transport to narrowly scoped requirements.",
                confidence="INFERRED", evidence=[record.path], analyzer=self.name,
            ))
        return findings

    def _network_security(self, path: Path, record: FileRecord) -> list[Finding]:
        root, error = self._read_xml(path, record)
        if error:
            return [error]
        risky = []
        for element in root.iter():
            if element.attrib.get("cleartextTrafficPermitted", "").lower() == "true":
                risky.append("cleartextTrafficPermitted")
            if element.tag.rsplit("}", 1)[-1] == "certificates" and element.attrib.get("src") == "user":
                risky.append("user certificate trust anchor")
        return [Finding(
            "security",
            f"Android network security configuration: {record.path}",
            "Detected network trust settings: " + ", ".join(risky or ["no selected risky setting"]),
            confidence="CONFIRMED" if risky else "INFERRED",
            evidence=[record.path],
            analyzer=self.name,
        )]

    def _json_manifest(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            data = json.loads(read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            ))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [Finding(
                "mobile", f"Mobile JSON manifest parse error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if not isinstance(data, dict):
            return []
        dependencies = {}
        for group in ("dependencies", "devDependencies"):
            dependencies.update(data.get(group, {}) if isinstance(data.get(group), dict) else {})
        names = set(dependencies)
        frameworks = []
        for package, label in (
            ("react-native", "React Native"), ("expo", "Expo"),
            ("@capacitor/core", "Capacitor"), ("@ionic/angular", "Ionic Angular"),
            ("nativescript", "NativeScript"),
        ):
            if package in names:
                frameworks.append(label)
        if not frameworks and record.path.lower().endswith("package.json"):
            return []
        return [Finding(
            "mobile",
            f"Mobile application manifest: {record.path}",
            "Detected mobile framework(s): " + (", ".join(frameworks) or "platform metadata")
            + f"; {len(dependencies)} declared package dependencies.",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _flutter_manifest(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "mobile", f"Flutter manifest read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        if not re.search(r"(?m)^dependencies\s*:", source):
            return []
        deps = re.findall(r"(?m)^[ \t]{2}([A-Za-z0-9_]+)\s*:", source)
        return [Finding(
            "mobile",
            f"Flutter project manifest: {record.path}",
            f"Detected Flutter dependency section with {len(deps)} dependency key(s).",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _podfile(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "mobile", f"Podfile read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        platform = re.findall(r"(?im)^[ \t]*platform\s*:ios\s*,\s*['\"]([^'\"]+)", source)
        pods = re.findall(r"(?im)^[ \t]*pod\s+['\"]([^'\"]+)", source)
        return [Finding(
            "mobile", f"iOS CocoaPods manifest: {record.path}",
            f"Detected iOS deployment target(s): {', '.join(platform) or 'unspecified'}; "
            f"{len(pods)} pod declaration(s).",
            confidence="CONFIRMED",
            evidence=[record.path] + [f"pod: {name}" for name in pods[:100]],
            analyzer=self.name,
        )]

    def _gradle(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "mobile", f"Android Gradle manifest read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        markers = [
            label for pattern, label in (
                (r"com\.android\.(?:application|library)", "Android Gradle plugin"),
                (r"minSdk(?:Version)?\s*[= ]", "minimum SDK declaration"),
                (r"targetSdk(?:Version)?\s*[= ]", "target SDK declaration"),
                (r"buildTypes", "build type configuration"),
                (r"signingConfigs", "signing configuration"),
            ) if re.search(pattern, source)
        ]
        if not markers:
            return []
        return [Finding(
            "mobile", f"Android Gradle configuration: {record.path}",
            "Detected: " + ", ".join(markers) + ". Build scripts are not evaluated.",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _xcode_project(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "mobile", f"Xcode project read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        targets = len(re.findall(r"\bPBXNativeTarget\b", source))
        bundle_ids = len(re.findall(r"\bPRODUCT_BUNDLE_IDENTIFIER\s*=", source))
        return [Finding(
            "mobile", f"Xcode project configuration: {record.path}",
            f"Detected {targets} native target declaration(s) and {bundle_ids} bundle identifier setting(s).",
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]

    def _mobile_source(self, path: Path, record: FileRecord) -> list[Finding]:
        try:
            source = read_text_bounded(
                path, 16 * 1024 * 1024,
                expected_identity=record.analysis_identity,
            )
        except (OSError, UnicodeDecodeError) as exc:
            return [Finding(
                "mobile", f"Mobile source read error: {record.path}",
                describe_error(exc), confidence="UNKNOWN", severity="LOW",
                evidence=[record.path], analyzer=self.name,
            )]
        markers = []
        for pattern, label in (
            (r"@UIApplicationMain|@main\s+struct\s+\w+\s*:\s*App", "SwiftUI/UIKit application entry"),
            (r"@AndroidEntryPoint|class\s+\w+\s*:\s*(?:Application|Activity|Fragment)", "Android application component"),
            (r"WidgetsFlutterBinding|runApp\s*\(", "Flutter application entry"),
        ):
            if re.search(pattern, source):
                markers.append(label)
        if not markers:
            return []
        return [Finding(
            "mobile", f"Mobile application source markers: {record.path}",
            "Detected: " + ", ".join(markers),
            confidence="CONFIRMED", evidence=[record.path], analyzer=self.name,
        )]
