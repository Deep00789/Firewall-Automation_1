"""Tests for quick-add static leases ("hostname,mac,ip" lines with optional hostname and IP).

Run from the project folder:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Sophos_Dhcp as dhcp  # noqa: E402

SERVER = {
    "name": "v29",
    "params": {"Gateway": "192.168.29.1", "SubnetMask": "255.255.255.0"},
    "dynamic_ranges": ["192.168.29.100-192.168.29.200"],
    "leases": [{"HName": "old", "MAC_Add": "AA:AA:AA:00:00:01", "IpAdd": "192.168.29.2"}],
}


def run(text, server=SERVER, bound_elsewhere=None):
    rows = dhcp.fill_hostnames(dhcp.parse_quick_leases(text))
    return dhcp.validate_new_leases(server, rows, auto_ip=True, bound_elsewhere=bound_elsewhere)


class QuickLeaseTests(unittest.TestCase):
    def test_mac_only_gets_hostname_and_free_ip(self):
        r = run("aa:aa:aa:bb:bb:bb")[0]
        self.assertTrue(r["ok"])
        self.assertEqual((r["HName"], r["MAC_Add"], r["IpAdd"]), ("aaaaaabbbbbb", "AA:AA:AA:BB:BB:BB", "192.168.29.3"))

    def test_separators_are_normalised(self):
        for mac in ("AA-BB-CC-DD-EE-01", "aabbccddee01", "aabb.ccdd.ee01"):
            self.assertEqual(run(mac)[0]["MAC_Add"], "AA:BB:CC:DD:EE:01")

    def test_field_layouts(self):
        a, b, c = run("PC1,AA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02,192.168.29.50\n,AA:BB:CC:DD:EE:03,192.168.29.51")
        self.assertEqual((a["HName"], a["IpAdd"]), ("PC1", "192.168.29.3"))
        self.assertEqual((b["HName"], b["IpAdd"]), ("aabbccddee02", "192.168.29.50"))
        self.assertEqual((c["HName"], c["IpAdd"]), ("aabbccddee03", "192.168.29.51"))

    def test_auto_ip_skips_dynamic_range_and_explicit_ips(self):
        server = dict(SERVER, dynamic_ranges=["192.168.29.3-192.168.29.200"])
        rows = run("AA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02,192.168.29.201", server)
        self.assertEqual([r["IpAdd"] for r in rows], ["192.168.29.202", "192.168.29.201"])

    def test_no_free_ip(self):
        server = dict(SERVER, dynamic_ranges=["192.168.29.2-192.168.29.254"])
        r = run("AA:BB:CC:DD:EE:01", server)[0]
        self.assertFalse(r["ok"])
        self.assertIn("No free IP", r["reason"])

    def test_conflicts_are_skipped_without_using_up_ips(self):
        rows = run("AA:AA:AA:00:00:01\nbad\nAA:BB:CC:DD:EE:01,192.168.29.2\nAA:BB:CC:DD:EE:02\nAA:BB:CC:DD:EE:02")
        self.assertEqual([r["ok"] for r in rows], [False, False, False, True, False])
        self.assertEqual(rows[0]["reason"], "MAC already exists")
        self.assertEqual(rows[1]["reason"], "Invalid MAC address")
        self.assertEqual(rows[2]["reason"], "IP already exists")
        self.assertEqual(rows[3]["IpAdd"], "192.168.29.3")
        self.assertEqual(rows[0]["IpAdd"], "")

    def test_skipped_row_does_not_block_a_later_duplicate_mac(self):
        # Line 1 fails (hostname taken), so line 2 with the same MAC must still be added.
        rows = run("old,AA:BB:CC:DD:EE:01\nPC9,AA:BB:CC:DD:EE:01")
        self.assertEqual(rows[0]["reason"], "Hostname already exists")
        self.assertTrue(rows[1]["ok"])
        self.assertEqual(rows[1]["IpAdd"], "192.168.29.3")

    def test_invalid_explicit_ip_does_not_reserve_it(self):
        rows = run("bad name?,zz,192.168.29.3\nAA:BB:CC:DD:EE:02")
        self.assertFalse(rows[0]["ok"])
        self.assertEqual(rows[1]["IpAdd"], "192.168.29.3")

    def test_explicit_ip_later_in_text_wins_over_auto(self):
        rows = run("AA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02,192.168.29.3")
        self.assertEqual([r["IpAdd"] for r in rows], ["192.168.29.4", "192.168.29.3"])
        self.assertTrue(all(r["ok"] for r in rows))

    def test_mistyped_ip_is_reported_as_ip(self):
        for line in ("AA:BB:CC:DD:EE:01,192.168.29.300", "AA:BB:CC:DD:EE:01,192.168.029.50"):
            self.assertEqual(run(line)[0]["reason"], "Invalid IP address")

    def test_trailing_comma_means_auto_ip(self):
        r = run("AA:BB:CC:DD:EE:01,")[0]
        self.assertTrue(r["ok"])
        self.assertEqual(r["IpAdd"], "192.168.29.3")

    def test_large_subnet_with_huge_dynamic_range_is_fast(self):
        server = dict(SERVER, params={"Gateway": "10.0.0.1", "SubnetMask": "255.0.0.0"},
                      dynamic_ranges=["10.0.0.2-10.255.255.200"], leases=[])
        self.assertEqual(run("AA:BB:CC:DD:EE:01", server)[0]["IpAdd"], "10.255.255.201")

    def test_too_many_fields_and_comments(self):
        rows = run("# comment\n\na,b,c,d")
        self.assertEqual(len(rows), 1)
        self.assertIn("Too many fields", rows[0]["reason"])

    def test_mac_bound_on_another_server(self):
        other = {"name": "v30", "leases": [{"MAC_Add": "aa-bb-cc-dd-ee-01"}]}
        bound = dhcp.macs_bound_elsewhere("v29", [other, SERVER])
        rows = run("AA:BB:CC:DD:EE:01\nAA:BB:CC:DD:EE:02", bound_elsewhere=bound)
        self.assertFalse(rows[0]["ok"])
        self.assertIn("v30", rows[0]["reason"])
        self.assertEqual(rows[1]["IpAdd"], "192.168.29.3")  # the skipped row did not use up .3

    def test_csv_path_unchanged_without_auto_ip(self):
        rows = dhcp.validate_new_leases(SERVER, [{"HName": "x", "MAC_Add": "aabbccddee01", "IpAdd": ""}])
        self.assertEqual(rows[0]["reason"], "Invalid IP address")
        self.assertEqual(rows[0]["MAC_Add"], "AA:BB:CC:DD:EE:01")

if __name__ == "__main__":
    unittest.main()
