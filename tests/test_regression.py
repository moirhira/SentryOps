"""
SentryOps Vulnerability Engine — Regression Test Suite

Validates the 10 reference packages against known OSV ground-truth data.
Each test constructs realistic affected-entry fixtures matching the actual
Debian:13 and PyPI advisory structures retrieved from OSV.dev, then asserts
that evaluate_affected_range() produces the correct result.

Run:
    python3 -m pytest tests/test_regression.py -v

Ground-truth data collected 2026-08-15 from https://api.osv.dev
"""

import pytest
from scanner.osv.version import evaluate_affected_range, compare_debian_versions


# ─── Helpers ───────────────────────────────────────────────────────────────

def make_affected(ecosystem, name, urgency, events_list):
    """Build an OSV-style affected entry."""
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "ecosystem_specific": {"urgency": urgency},
        "ranges": [{"type": "ECOSYSTEM", "events": events_list}],
    }


# ─── 1. firefox-esr ───────────────────────────────────────────────────────
# OSV returns 2 vulns, BOTH have urgency=unimportant → should be filtered out.

class TestFirefoxEsr:
    INSTALLED = "140.13.0esr-1~deb13u1"
    ECOSYSTEM = "Debian:13"
    PKG = "firefox-esr"

    def test_unimportant_urgency_filtered(self):
        """firefox-esr: all Debian:13 entries are urgency=unimportant → not affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "unimportant",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (unimportant), got {result}"

    def test_cross_release_isolation(self):
        """firefox-esr: Debian:11 advisory must NOT match Debian:13 target."""
        affected = [
            make_affected("Debian:11", self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": "117.0.5938.132-1~deb11u1"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (cross-release), got {result}"


# ─── 2. jq ─────────────────────────────────────────────────────────────────
# jq has multiple CVEs with fixed=1.7.1-6+deb13u3, installed=1.7.1-6+deb13u2.

class TestJq:
    INSTALLED = "1.7.1-6+deb13u2"
    FIXED = "1.7.1-6+deb13u3"
    ECOSYSTEM = "Debian:13"
    PKG = "jq"

    def test_affected_installed_lt_fixed(self):
        """jq: installed 1.7.1-6+deb13u2 < fixed 1.7.1-6+deb13u3 → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None, "Expected affected"
        assert result.is_affected is True
        assert result.range["fixed"] == self.FIXED
        assert result.comparator == "dpkg"

    def test_patched_installed_ge_fixed(self):
        """jq: installed == fixed → patched (not affected)."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.FIXED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (patched), got {result}"

    def test_unimportant_jq_filtered(self):
        """jq: urgency=unimportant entries should be filtered."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "unimportant",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (unimportant), got {result}"


# ─── 3. perl ───────────────────────────────────────────────────────────────
# perl has unfixed (open-ended) ranges in Debian:13 + some unimportant entries.

class TestPerl:
    INSTALLED = "5.40.1-6"
    ECOSYSTEM = "Debian:13"
    PKG = "perl"

    def test_open_ended_range_affected(self):
        """perl: introduced=0, no fixed → affected (unpatched)."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None, "Expected affected"
        assert result.is_affected is True
        assert result.range["fixed"] is None
        assert result.comparator == "dpkg"

    def test_unimportant_perl_filtered(self):
        """perl: urgency=unimportant entries should be filtered."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "unimportant",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None

    def test_no_cross_package_leakage(self):
        """perl: advisory for a different package name must not match."""
        affected = [
            make_affected(self.ECOSYSTEM, "libperl-dev", "not yet assigned",
                          [{"introduced": "0"}, {"fixed": "2.220-1"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (wrong package), got {result}"


# ─── 4. 7zip ───────────────────────────────────────────────────────────────
# 7zip has a mix: some unimportant, some not-yet-assigned, all open-ended.

class Test7zip:
    INSTALLED = "25.01+dfsg-1~deb13u2"
    ECOSYSTEM = "Debian:13"
    PKG = "7zip"

    def test_unimportant_filtered(self):
        """7zip: urgency=unimportant → not affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "unimportant",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None

    def test_open_ended_affected(self):
        """7zip: urgency=not-yet-assigned, no fixed → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] is None

    def test_no_deb12_fixed_leakage(self):
        """7zip: Debian:12 fixed version must NOT be used on Debian:13 target."""
        affected = [
            make_affected("Debian:12", self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": "22.01+really26.02+dfsg-0+deb12u1"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (cross-release), got {result}"


# ─── 5. xwayland ──────────────────────────────────────────────────────────
# xwayland has DUAL affected entries for Debian:13: one with fixed, one without.
# This is the key multi-range priority test.

class TestXwayland:
    INSTALLED = "2:24.1.6-1"
    FIXED = "2:24.1.8-1"
    ECOSYSTEM = "Debian:13"
    PKG = "xwayland"

    def _dual_affected(self):
        return [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}]),
        ]

    def test_affected_installed_lt_fixed(self):
        """xwayland: installed < fixed → affected with correct fixed version."""
        result = evaluate_affected_range(self.INSTALLED, self._dual_affected(), self.ECOSYSTEM, self.PKG)
        assert result is not None, "Expected affected"
        assert result.is_affected is True
        assert result.range["fixed"] == self.FIXED

    def test_patched_installed_eq_fixed(self):
        """xwayland: installed == fixed → patched (NOT affected, despite open-ended range)."""
        result = evaluate_affected_range(self.FIXED, self._dual_affected(), self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (patched), got {result}"

    def test_patched_installed_gt_fixed(self):
        """xwayland: installed >> fixed → patched."""
        result = evaluate_affected_range("2:25.0.0-1", self._dual_affected(), self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (patched), got {result}"

    def test_cross_release_deb11_isolation(self):
        """xwayland: Debian:11 advisory must NOT match Debian:13 target."""
        affected = [
            make_affected("Debian:11", self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": "2:1.20.11-1+deb11u16"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None


# ─── 6. curl ───────────────────────────────────────────────────────────────
# curl has advisories with fixed versions AND open-ended advisories.

class TestCurl:
    INSTALLED = "8.12.1-4"
    ECOSYSTEM = "Debian:13"
    PKG = "curl"

    def test_affected_with_fixed(self):
        """curl: installed < fixed → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": "8.14.1-2+deb13u1"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] == "8.14.1-2+deb13u1"

    def test_open_ended_affected(self):
        """curl: open-ended range → affected (unpatched)."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] is None

    def test_patched_curl(self):
        """curl: installed >= fixed → patched."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": "8.14.1-2+deb13u1"}]),
        ]
        result = evaluate_affected_range("8.14.1-2+deb13u1", affected, self.ECOSYSTEM, self.PKG)
        assert result is None


# ─── 7. vim ────────────────────────────────────────────────────────────────
# vim: fixed=2:9.1.1230-2+deb13u1, installed=2:9.1.1230-2 → affected.

class TestVim:
    INSTALLED = "2:9.1.1230-2"
    FIXED = "2:9.1.1230-2+deb13u1"
    ECOSYSTEM = "Debian:13"
    PKG = "vim"

    def test_affected_installed_lt_fixed(self):
        """vim: installed < fixed → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] == self.FIXED

    def test_patched(self):
        """vim: installed == fixed → patched."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.FIXED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None

    def test_open_ended_affected(self):
        """vim: open-ended range with no fixed → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] is None


# ─── 8. openssl ────────────────────────────────────────────────────────────
# openssl 3.5.0-1 has advisories with fixed=3.5.4-1~deb13u2.

class TestOpenssl:
    INSTALLED = "3.5.0-1"
    FIXED = "3.5.4-1~deb13u2"
    ECOSYSTEM = "Debian:13"
    PKG = "openssl"

    def test_affected_installed_lt_fixed(self):
        """openssl: installed < fixed → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] == self.FIXED

    def test_patched(self):
        """openssl: installed >= fixed → patched."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.FIXED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None


# ─── 9. libxml2 ────────────────────────────────────────────────────────────
# libxml2: installed version IS the fixed version → patched.

class TestLibxml2:
    INSTALLED = "2.12.7+dfsg+really2.9.14-2.1+deb13u3"
    FIXED = "2.12.7+dfsg+really2.9.14-2.1+deb13u3"
    ECOSYSTEM = "Debian:13"
    PKG = "libxml2"

    def test_patched_installed_eq_fixed(self):
        """libxml2: installed == fixed → patched."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None, f"Expected None (patched), got {result}"

    def test_older_libxml2_affected(self):
        """libxml2: older version < fixed → affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "not yet assigned",
                          [{"introduced": "0"}, {"fixed": self.FIXED}]),
        ]
        result = evaluate_affected_range("2.12.7+dfsg+really2.9.14-2.1+deb13u2", affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True

    def test_unimportant_filtered(self):
        """libxml2: urgency=unimportant → not affected."""
        affected = [
            make_affected(self.ECOSYSTEM, self.PKG, "unimportant",
                          [{"introduced": "0"}]),
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is None


# ─── 10. requests (PyPI) ──────────────────────────────────────────────────
# PyPI ecosystem uses semver, not dpkg.

class TestRequests:
    INSTALLED = "2.31.0"
    ECOSYSTEM = "PyPI"
    PKG = "requests"

    def test_affected_lt_fixed(self):
        """requests: installed 2.31.0 < fixed 2.32.4 → affected (semver)."""
        affected = [
            {
                "package": {"ecosystem": self.ECOSYSTEM, "name": self.PKG},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.32.4"}
                ]}],
            },
        ]
        result = evaluate_affected_range(self.INSTALLED, affected, self.ECOSYSTEM, self.PKG)
        assert result is not None
        assert result.is_affected is True
        assert result.range["fixed"] == "2.32.4"
        assert result.comparator == "semver"

    def test_patched(self):
        """requests: installed >= fixed → patched."""
        affected = [
            {
                "package": {"ecosystem": self.ECOSYSTEM, "name": self.PKG},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.32.4"}
                ]}],
            },
        ]
        result = evaluate_affected_range("2.32.4", affected, self.ECOSYSTEM, self.PKG)
        assert result is None


# ─── Debian Version Comparator Unit Tests ──────────────────────────────────

class TestDebianVersionComparator:
    """Unit tests for dpkg --compare-versions wrapper."""

    def test_epoch_comparison(self):
        assert compare_debian_versions("2:24.1.6-1", "lt", "2:24.1.8-1") is True
        assert compare_debian_versions("2:24.1.8-1", "ge", "2:24.1.6-1") is True

    def test_backport_suffix(self):
        assert compare_debian_versions("1.7.1-6+deb13u2", "lt", "1.7.1-6+deb13u3") is True
        assert compare_debian_versions("1.7.1-6+deb13u3", "ge", "1.7.1-6+deb13u3") is True

    def test_tilde_suffix(self):
        # ~ sorts BEFORE anything (Debian policy §5.6.12)
        assert compare_debian_versions("25.01+dfsg-1~deb13u2", "gt", "22.01+really26.02+dfsg-0+deb12u1") is True

    def test_deb13u_vs_deb13u(self):
        assert compare_debian_versions("2:9.1.1230-2", "lt", "2:9.1.1230-2+deb13u1") is True
        assert compare_debian_versions("2:9.1.1230-2+deb13u1", "ge", "2:9.1.1230-2") is True

    def test_complex_libxml2(self):
        assert compare_debian_versions(
            "2.12.7+dfsg+really2.9.14-2.1+deb13u2", "lt",
            "2.12.7+dfsg+really2.9.14-2.1+deb13u3"
        ) is True

    def test_equal_versions(self):
        assert compare_debian_versions("3.5.0-1", "eq", "3.5.0-1") is True
        assert compare_debian_versions("3.5.0-1", "lt", "3.5.0-1") is False

    def test_empty_version_handling(self):
        assert compare_debian_versions("", "lt", "1.0") is False
        assert compare_debian_versions("1.0", "lt", "") is False
