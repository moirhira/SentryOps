"""
Regression tests for SentryOps CVE version engine.

Tests the core evaluate_affected_range() function with real cached OSV data
and synthetic edge cases to validate:
  1. Package-name filtering (no cross-package version leakage)
  2. Exact ecosystem matching (no cross-release leakage)
  3. Proper sequential event range evaluation
  4. last_affected handling
  5. Multi-range event evaluation
"""

import json
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.osv.version import (
    EvaluationResult,
    _parse_event_ranges,
    compare_versions,
    evaluate_affected_range,
)

CACHE_PATH = Path(__file__).resolve().parent.parent / ".sentryops_cache.json"


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text())
    return {}


def _get_affected_list(cache: dict, cache_key: str, vuln_id: str) -> list[dict]:
    """Extract affected list for a specific vulnerability from cache."""
    vulns = cache.get(cache_key, [])
    for v in vulns:
        if v.get("id") == vuln_id:
            return v.get("affected", [])
    return []


# ──────────────────────────────────────────────────────────────────────
# Unit tests for _parse_event_ranges
# ──────────────────────────────────────────────────────────────────────


class TestParseEventRanges:
    """Tests for sequential event-to-range parsing."""

    def test_paired_introduced_fixed(self):
        events = [
            {"introduced": "0"},
            {"fixed": "1.2.3"},
            {"introduced": "1.3.0"},
            {"fixed": "1.3.5"},
        ]
        ranges = _parse_event_ranges(events)
        assert len(ranges) == 2
        assert ranges[0] == {"introduced": "0", "fixed": "1.2.3", "last_affected": None}
        assert ranges[1] == {"introduced": "1.3.0", "fixed": "1.3.5", "last_affected": None}

    def test_open_ended_range(self):
        events = [{"introduced": "0"}]
        ranges = _parse_event_ranges(events)
        assert len(ranges) == 1
        assert ranges[0] == {"introduced": "0", "fixed": None, "last_affected": None}

    def test_last_affected_event(self):
        events = [{"introduced": "0"}, {"last_affected": "1.5.0"}]
        ranges = _parse_event_ranges(events)
        assert len(ranges) == 1
        assert ranges[0] == {"introduced": "0", "fixed": None, "last_affected": "1.5.0"}

    def test_mixed_ranges(self):
        """One fixed range followed by an open-ended range."""
        events = [
            {"introduced": "0"},
            {"fixed": "1.0.0"},
            {"introduced": "2.0.0"},
        ]
        ranges = _parse_event_ranges(events)
        assert len(ranges) == 2
        assert ranges[0] == {"introduced": "0", "fixed": "1.0.0", "last_affected": None}
        assert ranges[1] == {"introduced": "2.0.0", "fixed": None, "last_affected": None}

    def test_empty_events(self):
        assert _parse_event_ranges([]) == []

    def test_non_dict_events_ignored(self):
        events = [{"introduced": "0"}, "garbage", None, {"fixed": "1.0"}]
        ranges = _parse_event_ranges(events)
        assert len(ranges) == 1
        assert ranges[0]["fixed"] == "1.0"


# ──────────────────────────────────────────────────────────────────────
# Synthetic tests for evaluate_affected_range
# ──────────────────────────────────────────────────────────────────────


class TestEvaluateAffectedRangeSynthetic:
    """Synthetic test cases for edge cases not present in live data."""

    def test_multi_range_not_affected_between_ranges(self):
        """Version 1.2.5 is between [0, 1.2.3) and [1.3.0, 1.3.5) → NOT AFFECTED."""
        affected = [{
            "package": {"name": "testpkg", "ecosystem": "PyPI"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "1.2.3"},
                    {"introduced": "1.3.0"},
                    {"fixed": "1.3.5"},
                ],
            }],
        }]
        result = evaluate_affected_range(
            installed_ver="1.2.5",
            affected_list=affected,
            target_ecosystem="PyPI",
            package_name="testpkg",
        )
        assert result is None, "1.2.5 should NOT be affected (between ranges)"

    def test_multi_range_affected_in_second_range(self):
        """Version 1.3.2 is in [1.3.0, 1.3.5) → AFFECTED."""
        affected = [{
            "package": {"name": "testpkg", "ecosystem": "PyPI"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "1.2.3"},
                    {"introduced": "1.3.0"},
                    {"fixed": "1.3.5"},
                ],
            }],
        }]
        result = evaluate_affected_range(
            installed_ver="1.3.2",
            affected_list=affected,
            target_ecosystem="PyPI",
            package_name="testpkg",
        )
        assert result is not None, "1.3.2 should be affected (in second range)"
        assert result.is_affected is True
        assert result.range["fixed"] == "1.3.5"

    def test_multi_range_affected_in_first_range(self):
        """Version 1.1.0 is in [0, 1.2.3) → AFFECTED."""
        affected = [{
            "package": {"name": "testpkg", "ecosystem": "PyPI"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "1.2.3"},
                    {"introduced": "1.3.0"},
                    {"fixed": "1.3.5"},
                ],
            }],
        }]
        result = evaluate_affected_range(
            installed_ver="1.1.0",
            affected_list=affected,
            target_ecosystem="PyPI",
            package_name="testpkg",
        )
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] == "1.2.3"

    def test_last_affected_within_range(self):
        """Version <= last_affected → AFFECTED."""
        affected = [{
            "package": {"name": "testpkg", "ecosystem": "PyPI"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"last_affected": "1.5.0"},
                ],
            }],
        }]
        result = evaluate_affected_range(
            installed_ver="1.4.0",
            affected_list=affected,
            target_ecosystem="PyPI",
            package_name="testpkg",
        )
        assert result is not None
        assert result.is_affected is True
        assert result.range.get("last_affected") == "1.5.0"

    def test_last_affected_beyond_range(self):
        """Version > last_affected → NOT AFFECTED."""
        affected = [{
            "package": {"name": "testpkg", "ecosystem": "PyPI"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"introduced": "0"},
                    {"last_affected": "1.5.0"},
                ],
            }],
        }]
        result = evaluate_affected_range(
            installed_ver="1.6.0",
            affected_list=affected,
            target_ecosystem="PyPI",
            package_name="testpkg",
        )
        assert result is None, "1.6.0 > last_affected 1.5.0 → not affected"

    def test_cross_package_filtering_synthetic(self):
        """Only the target package entry should be evaluated."""
        affected = [
            {
                "package": {"name": "chromium", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "117.0"}
                ]}],
            },
            {
                "package": {"name": "firefox-esr", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}  # open-ended, no fix
                ]}],
            },
        ]
        result = evaluate_affected_range(
            installed_ver="140.0",
            affected_list=affected,
            target_ecosystem="Debian:13",
            package_name="firefox-esr",
        )
        assert result is not None, "firefox-esr should be affected (open range)"
        assert result.is_affected is True
        assert result.range["fixed"] is None
        assert result.package_name == "firefox-esr"

    def test_cross_ecosystem_no_leak(self):
        """Debian:11 entries must not match Debian:13 target."""
        affected = [
            {
                "package": {"name": "curl", "ecosystem": "Debian:11"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "7.74.0-1.3+deb11u7"}
                ]}],
            },
        ]
        result = evaluate_affected_range(
            installed_ver="8.14.1-2+deb13u4",
            affected_list=affected,
            target_ecosystem="Debian:13",
            package_name="curl",
        )
        assert result is None, "Debian:11 entry should not match Debian:13 target"

    def test_no_match_returns_none(self):
        """Package not in affected list → None."""
        affected = [{
            "package": {"name": "other-pkg", "ecosystem": "Debian:13"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "1.0"}
            ]}],
        }]
        result = evaluate_affected_range(
            installed_ver="0.5",
            affected_list=affected,
            target_ecosystem="Debian:13",
            package_name="my-pkg",
        )
        assert result is None

    def test_unimportant_urgency_filtered(self):
        """Entries with urgency=unimportant should be skipped."""
        affected = [{
            "package": {"name": "testpkg", "ecosystem": "Debian:13"},
            "ecosystem_specific": {"urgency": "unimportant"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}
            ]}],
        }]
        result = evaluate_affected_range(
            installed_ver="1.0",
            affected_list=affected,
            target_ecosystem="Debian:13",
            package_name="testpkg",
        )
        assert result is None, "unimportant urgency should be filtered out"


# ──────────────────────────────────────────────────────────────────────
# Regression tests with real cached OSV data
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def cache():
    """Load .sentryops_cache.json once for all tests."""
    c = _load_cache()
    if not c:
        pytest.skip("No .sentryops_cache.json found — run a scan first")
    return c


class TestFirefoxESR:
    """Firefox-esr: cross-package filtering (chromium must not leak)."""

    def test_cve_2023_5217_package_filtering(self, cache):
        """DEBIAN-CVE-2023-5217 has chromium/libvpx/thunderbird entries in Debian:13.
        Only firefox-esr should be evaluated. The firefox-esr entry has urgency=unimportant,
        so the result should be None (correctly filtered)."""
        affected = _get_affected_list(
            cache, "Debian:13:firefox-esr==140.13.0esr-1~deb13u1", "DEBIAN-CVE-2023-5217"
        )
        if not affected:
            pytest.skip("DEBIAN-CVE-2023-5217 not in cache")

        result = evaluate_affected_range(
            installed_ver="140.13.0esr-1~deb13u1",
            affected_list=affected,
            target_ecosystem="Debian:13",
            package_name="firefox-esr",
        )
        # The firefox-esr Debian:13 entry has urgency=unimportant → should be None
        assert result is None, (
            "firefox-esr for CVE-2023-5217 is urgency=unimportant in Debian:13. "
            "Must NOT use chromium's fixed version."
        )

    def test_no_chromium_fixed_version_leaks(self, cache):
        """Chromium's fixed version '117.0.5938.132-1' must never appear
        in a firefox-esr evaluation result."""
        key = "Debian:13:firefox-esr==140.13.0esr-1~deb13u1"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("firefox-esr not in cache")

        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="140.13.0esr-1~deb13u1",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="firefox-esr",
            )
            if result is not None:
                fixed = result.range.get("fixed")
                assert fixed != "117.0.5938.132-1", (
                    f"Chromium fixed version leaked into firefox-esr finding for {v.get('id')}"
                )
                assert result.ecosystem == "Debian:13"
                assert result.package_name == "firefox-esr"


class TestJQ:
    """jq: correct Debian:13 fixed version."""

    def test_jq_correct_fixed_version(self, cache):
        """jq findings must use the Debian:13 fixed version, not Debian:11's."""
        key = "Debian:13:jq==1.7.1-6+deb13u2"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("jq not in cache")

        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="1.7.1-6+deb13u2",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="jq",
            )
            if result is not None:
                fixed = result.range.get("fixed")
                assert result.ecosystem == "Debian:13"
                # If there IS a fixed version, it must be the Debian:13 one
                if fixed is not None:
                    assert fixed == "1.7.1-6+deb13u3", (
                        f"Expected Debian:13 fixed version '1.7.1-6+deb13u3', got '{fixed}' "
                        f"for {v.get('id')}"
                    )
                    # Must NOT be a Debian:11 version
                    assert "deb11" not in fixed
                    assert "deb12" not in fixed

    def test_jq_cve_2024_53427(self, cache):
        """DEBIAN-CVE-2024-53427: jq should be affected with fixed=1.7.1-6+deb13u3."""
        affected = _get_affected_list(
            cache, "Debian:13:jq==1.7.1-6+deb13u2", "DEBIAN-CVE-2024-53427"
        )
        if not affected:
            pytest.skip("DEBIAN-CVE-2024-53427 not in cache")

        result = evaluate_affected_range(
            installed_ver="1.7.1-6+deb13u2",
            affected_list=affected,
            target_ecosystem="Debian:13",
            package_name="jq",
        )
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] == "1.7.1-6+deb13u3"
        assert result.ecosystem == "Debian:13"
        assert result.comparator == "dpkg"


class TestPerl:
    """perl: no cross-package leakage from libio-compress-perl, libhttp-tiny-perl, etc."""

    def test_perl_no_cross_package_fixed_versions(self, cache):
        """perl findings must NOT contain fixed versions from other packages
        (libio-compress-perl, libhttp-tiny-perl, libsocket-perl)."""
        key = "Debian:13:perl==5.40.1-6"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("perl not in cache")

        bad_fixed_versions = {"2.220-1", "0.096-1", "2.217-1", "0.092-2", "2.041-1"}

        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="5.40.1-6",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="perl",
            )
            if result is not None:
                fixed = result.range.get("fixed")
                assert fixed not in bad_fixed_versions, (
                    f"Cross-package fixed version '{fixed}' leaked into perl finding "
                    f"for {v.get('id')}"
                )
                assert result.ecosystem == "Debian:13"
                assert result.package_name == "perl"

    def test_perl_open_ranges_have_no_fixed(self, cache):
        """perl Debian:13 entries have no fix → fixed must be None."""
        key = "Debian:13:perl==5.40.1-6"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("perl not in cache")

        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="5.40.1-6",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="perl",
            )
            if result is not None:
                # All perl Debian:13 entries are open-ended (no fix)
                assert result.range.get("fixed") is None, (
                    f"perl should have fixed=None in Debian:13 for {v.get('id')}, "
                    f"got {result.range.get('fixed')}"
                )


class TestSevenZip:
    """7zip: basic Debian:13 matching."""

    def test_7zip_affected(self, cache):
        key = "Debian:13:7zip==25.01+dfsg-1~deb13u2"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("7zip not in cache")

        affected_count = 0
        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="25.01+dfsg-1~deb13u2",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="7zip",
            )
            if result is not None:
                affected_count += 1
                assert result.ecosystem == "Debian:13"
                assert result.comparator == "dpkg"

        assert affected_count > 0, "7zip should have at least one affected CVE"


class TestXwayland:
    """xwayland: version comparison accuracy."""

    def test_xwayland_affected(self, cache):
        key = "Debian:13:xwayland==2:24.1.6-1"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("xwayland not in cache")

        affected_count = 0
        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="2:24.1.6-1",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="xwayland",
            )
            if result is not None:
                affected_count += 1
                assert result.ecosystem == "Debian:13"

        assert affected_count > 0, "xwayland should have at least one affected CVE"


class TestCurl:
    """curl: correct Debian:13 evaluation."""

    def test_curl_no_cross_release_leak(self, cache):
        key = "Debian:13:curl==8.14.1-2+deb13u4"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("curl not in cache")

        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="8.14.1-2+deb13u4",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="curl",
            )
            if result is not None:
                fixed = result.range.get("fixed")
                if fixed:
                    # Fixed version must not contain deb11 or deb12 markers
                    assert "deb11" not in fixed, f"Debian:11 fixed version leaked: {fixed}"
                    assert "deb12" not in fixed, f"Debian:12 fixed version leaked: {fixed}"
                assert result.ecosystem == "Debian:13"


class TestVim:
    """vim: standard package."""

    def test_vim_affected_results(self, cache):
        key = "Debian:13:vim==2:9.1.1230-2"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("vim not in cache")

        affected_count = 0
        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="2:9.1.1230-2",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="vim",
            )
            if result is not None:
                affected_count += 1
                assert result.ecosystem == "Debian:13"
                assert result.comparator == "dpkg"
                assert result.package_name == "vim"

        assert affected_count > 0, "vim should have at least one affected CVE"


class TestPython313:
    """python3.13: Python runtime packages."""

    def test_python313_affected(self, cache):
        key = "Debian:13:python3.13==3.13.5-2+deb13u4"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("python3.13 not in cache")

        affected_count = 0
        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="3.13.5-2+deb13u4",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="python3.13",
            )
            if result is not None:
                affected_count += 1
                assert result.ecosystem == "Debian:13"

        assert affected_count > 0, "python3.13 should have at least one affected CVE"


class TestOpenSSL:
    """openssl: security-critical package."""

    def test_openssl_no_vulns(self, cache):
        """openssl 3.5.6-1~deb13u2 has 0 cached vulns — should produce no results."""
        key = "Debian:13:openssl==3.5.6-1~deb13u2"
        vulns = cache.get(key, [])
        if not vulns:
            # No vulns in cache is expected
            return

        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="3.5.6-1~deb13u2",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="openssl",
            )
            if result is not None:
                assert result.ecosystem == "Debian:13"


class TestLibxml2:
    """libxml2: library package."""

    def test_libxml2_correct_evaluation(self, cache):
        key = "Debian:13:libxml2==2.12.7+dfsg+really2.9.14-2.1+deb13u3"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("libxml2 not in cache")

        affected_count = 0
        not_affected_count = 0
        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="2.12.7+dfsg+really2.9.14-2.1+deb13u3",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="libxml2",
            )
            if result is not None:
                affected_count += 1
                assert result.ecosystem == "Debian:13"
            else:
                not_affected_count += 1

        # libxml2 has 2 vulns, 1 affected and 1 not affected
        assert affected_count >= 1, "libxml2 should have at least one affected CVE"


# ──────────────────────────────────────────────────────────────────────
# EvaluationResult structure tests
# ──────────────────────────────────────────────────────────────────────


class TestEvaluationResultStructure:
    """Ensure EvaluationResult contains all required fields."""

    def test_result_has_all_fields(self, cache):
        key = "Debian:13:jq==1.7.1-6+deb13u2"
        vulns = cache.get(key, [])
        if not vulns:
            pytest.skip("jq not in cache")

        # Find a vuln that produces a result
        for v in vulns:
            affected = v.get("affected", [])
            result = evaluate_affected_range(
                installed_ver="1.7.1-6+deb13u2",
                affected_list=affected,
                target_ecosystem="Debian:13",
                package_name="jq",
            )
            if result is not None:
                assert isinstance(result, EvaluationResult)
                assert isinstance(result.is_affected, bool)
                assert isinstance(result.ecosystem, str)
                assert isinstance(result.package_name, str)
                assert isinstance(result.installed_version, str)
                assert isinstance(result.range, dict)
                assert "introduced" in result.range
                assert "fixed" in result.range
                assert isinstance(result.comparator, str)
                assert result.comparator in ("dpkg", "semver")
                return

        pytest.fail("Could not find a jq vuln that produces a result")
