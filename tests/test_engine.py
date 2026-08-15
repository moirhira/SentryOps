"""
Regression Test Suite for SentryOps Vulnerability Engine
Verifies ecosystem scoping, package-name isolation, dpkg version comparison,
and structured match formatting across 10 representative test packages.
"""

import unittest
from scanner.osv.version import compare_debian_versions, evaluate_affected_range


class TestVulnerabilityEngine(unittest.TestCase):

    def test_01_firefox_esr_no_cross_release_leak(self):
        """1. firefox-esr on Debian 13 must not leak Debian 11 fixed version (117.0.5938.132-1~deb11u1)."""
        sample_affected = [
            {
                "package": {"name": "firefox-esr", "ecosystem": "Debian:11"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "117.0.5938.132-1~deb11u1"}]}]
            },
            {
                "package": {"name": "firefox-esr", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="140.13.0esr-1~deb13u1",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="firefox-esr"
        )
        self.assertIsNotNone(res)
        self.assertTrue(res.is_affected)
        self.assertEqual(res.ecosystem, "Debian:13")
        self.assertIsNone(res.range["fixed"])
        self.assertEqual(res.comparator, "dpkg")

    def test_02_jq_clean_debian13_fix(self):
        """2. jq 1.7.1-6+deb13u2 must cleanly match fixed version 1.7.1-6+deb13u3 in Debian 13."""
        sample_affected = [
            {
                "package": {"name": "jq", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.7.1-6+deb13u3"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="1.7.1-6+deb13u2",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="jq"
        )
        self.assertIsNotNone(res)
        self.assertTrue(res.is_affected)
        self.assertEqual(res.range["fixed"], "1.7.1-6+deb13u3")
        self.assertEqual(res.comparator, "dpkg")

    def test_03_perl_no_subpackage_leak(self):
        """3. perl 5.40.1-6 must not inherit sub-package ranges (e.g. libio-compress-perl 2.220-1)."""
        sample_affected = [
            {
                "package": {"name": "libio-compress-perl", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.220-1"}]}]
            },
            {
                "package": {"name": "perl", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="5.40.1-6",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="perl"
        )
        self.assertIsNotNone(res)
        self.assertTrue(res.is_affected)
        self.assertEqual(res.package_name, "perl")
        self.assertIsNone(res.range["fixed"])

    def test_04_7zip_no_debian12_leak(self):
        """4. 7zip 25.01+dfsg-1~deb13u2 on Debian 13 must not leak Debian 12 fix version."""
        sample_affected = [
            {
                "package": {"name": "7zip", "ecosystem": "Debian:12"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "22.01+really26.02+dfsg-0+deb12u1"}]}]
            },
            {
                "package": {"name": "7zip", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="25.01+dfsg-1~deb13u2",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="7zip"
        )
        self.assertIsNotNone(res)
        self.assertTrue(res.is_affected)
        self.assertIsNone(res.range["fixed"])

    def test_05_xwayland_priority_fixed_range_patched(self):
        """5. xwayland 2:24.1.6-1 must recognize fixed 2:21.1.16-1.3+deb13u2 as patched and return None."""
        sample_affected = [
            {
                "package": {"name": "xwayland", "ecosystem": "Debian:13"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2:21.1.16-1.3+deb13u2"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}
                ]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="2:24.1.6-1",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="xwayland"
        )
        self.assertIsNone(res)  # Patched!

    def test_06_curl_open_range(self):
        """6. curl 8.11.1-1 open range evaluation in Debian 13."""
        sample_affected = [
            {
                "package": {"name": "curl", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="8.11.1-1",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="curl"
        )
        self.assertIsNotNone(res)
        self.assertTrue(res.is_affected)
        self.assertEqual(res.package_name, "curl")

    def test_07_vim_structured_match(self):
        """7. vim 2:9.1.1230-2 structured match output."""
        sample_affected = [
            {
                "package": {"name": "vim", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="2:9.1.1230-2",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="vim"
        )
        self.assertIsNotNone(res)
        match_dict = res.to_match_dict()
        self.assertEqual(match_dict["ecosystem"], "Debian:13")
        self.assertEqual(match_dict["comparator"], "dpkg")
        self.assertEqual(match_dict["result"], "affected")
        self.assertEqual(match_dict["range"], {"introduced": "0", "fixed": None})

    def test_08_python3_13_version_comparison(self):
        """8. python3.13 version comparison using dpkg."""
        self.assertTrue(compare_debian_versions("3.13.1-1", "lt", "3.13.1-2"))
        self.assertFalse(compare_debian_versions("3.13.1-2", "lt", "3.13.1-1"))

    def test_09_openssl_fixed_range_check(self):
        """9. openssl 3.0.13-1 is affected when fixed version is 3.0.14-1."""
        sample_affected = [
            {
                "package": {"name": "openssl", "ecosystem": "Debian:13"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.14-1"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="3.0.13-1",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="openssl"
        )
        self.assertIsNotNone(res)
        self.assertEqual(res.range["fixed"], "3.0.14-1")

    def test_10_libxml2_unimportant_urgency_filter(self):
        """10. libxml2 entry marked urgency: unimportant must be filtered out."""
        sample_affected = [
            {
                "package": {"name": "libxml2", "ecosystem": "Debian:13"},
                "ecosystem_specific": {"urgency": "unimportant"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
            }
        ]
        res = evaluate_affected_range(
            installed_ver="2.12.7+dfsg+really2.9.14-2.1+deb13u3",
            affected_list=sample_affected,
            target_ecosystem="Debian:13",
            package_name="libxml2"
        )
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
