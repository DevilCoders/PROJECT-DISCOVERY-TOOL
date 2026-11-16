import plistlib
from pathlib import Path

from project_discovery.analyzers.domains.mobile import MobileIntelligenceAnalyzer
from project_discovery.models import FileRecord


def _record(path: Path, relative: str) -> FileRecord:
    return FileRecord(relative, path.stat().st_size, path.suffix.lower(), "Configuration")


def test_android_manifest_permissions_and_risky_settings(tmp_path: Path):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<application android:usesCleartextTraffic="true" android:debuggable="true">'
        '<activity android:name=".MainActivity" android:exported="true"/>'
        '</application></manifest>',
        encoding="utf-8",
    )
    findings = MobileIntelligenceAnalyzer().analyze(
        path, _record(path, "app/src/main/AndroidManifest.xml")
    )
    assert any("Android application manifest" in item.title for item in findings)
    assert any("cleartext traffic enabled" in item.title for item in findings)
    assert any("exported component" in item.title for item in findings)


def test_ios_info_plist_privacy_and_transport_settings(tmp_path: Path):
    path = tmp_path / "Info.plist"
    with path.open("wb") as stream:
        plistlib.dump({
            "CFBundleIdentifier": "com.example.app",
            "NSCameraUsageDescription": "camera",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        }, stream)
    findings = MobileIntelligenceAnalyzer().analyze(
        path, _record(path, "ios/App/Info.plist")
    )
    assert any("iOS application property list" in item.title for item in findings)
    assert any("App Transport Security relaxed" in item.title for item in findings)


def test_ios_entitlements_detect_debug_profile(tmp_path: Path):
    path = tmp_path / "App.entitlements"
    with path.open("wb") as stream:
        plistlib.dump({"get-task-allow": True, "keychain-access-groups": ["group.example"]}, stream)
    findings = MobileIntelligenceAnalyzer().analyze(
        path, _record(path, "ios/App/App.entitlements")
    )
    assert any("debug entitlement enabled" in item.title for item in findings)


def test_react_native_package_manifest_and_gradle(tmp_path: Path):
    package = tmp_path / "package.json"
    package.write_text(
        '{"dependencies":{"react-native":"0.75.0","expo":"51.0.0"}}',
        encoding="utf-8",
    )
    findings = MobileIntelligenceAnalyzer().analyze(
        package, _record(package, "package.json")
    )
    assert "React Native" in findings[0].detail
    assert "Expo" in findings[0].detail

    gradle = tmp_path / "build.gradle"
    gradle.write_text(
        "plugins { id 'com.android.application' }\n"
        "android { defaultConfig { minSdk 26; targetSdk 35 } }\n",
        encoding="utf-8",
    )
    assert MobileIntelligenceAnalyzer().analyze(
        gradle, _record(gradle, "android/app/build.gradle")
    )


def test_non_mobile_package_json_is_ignored(tmp_path: Path):
    path = tmp_path / "package.json"
    path.write_text('{"dependencies":{"express":"4.0"}}', encoding="utf-8")
    assert MobileIntelligenceAnalyzer().analyze(
        path, _record(path, "package.json")
    ) == []


def test_malformed_xml_property_list_is_a_parse_error(tmp_path: Path):
    # Regression: plistlib raises ExpatError for malformed XML, which escaped the analyzer.
    path = tmp_path / "Info.plist"
    path.write_text('<?xml version="1.0"?><plist version="1.0"><dict><key>A</key>', encoding="utf-8")
    findings = MobileIntelligenceAnalyzer().analyze(path, _record(path, "ios/App/Info.plist"))
    assert [(item.confidence, item.title) for item in findings] == [
        ("UNKNOWN", "Apple property list parse error: ios/App/Info.plist"),
    ]
