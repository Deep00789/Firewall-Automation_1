"""Tests for the VPN documentation validation (gateway pair and subnet selector conflicts).

Run from the project folder:  python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vpndocs  # noqa: E402


def vpn(name, local="192.168.0.0/24", remote="10.0.0.0/24", lgw="1.1.1.1", rgw="2.2.2.2"):
    return dict(name=name, local_gw=lgw, remote_gw=rgw, local_subnet=local, remote_subnet=remote)


class VpnDocsBase(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        vpndocs.FILE = os.path.join(self._dir.name, "vpndocs.json")

    def tearDown(self):
        self._dir.cleanup()

    def assertConflict(self, data, existing_name="Existing"):
        with self.assertRaises(ValueError) as cm:
            vpndocs.add(data)
        self.assertIn("conflicts with existing VPN tunnel", str(cm.exception))
        self.assertIn(existing_name, str(cm.exception))

    def assertAllowed(self, data):
        self.assertEqual(vpndocs.add(data)["name"], data["name"])


class SubnetConflictTests(VpnDocsBase):
    def setUp(self):
        super().setUp()
        vpndocs.add(vpn("Existing", local="192.168.0.0/23", remote="10.0.0.0/16"))

    # distinct gateways everywhere below, so only the subnet rule can fire
    def new(self, name, local, remote):
        return vpn(name, local, remote, lgw="3.3.3.3", rgw="4.4.4.4")

    def test_exact_match_conflicts(self):
        self.assertConflict(self.new("N", "192.168.0.0/23", "10.0.0.0/16"))

    def test_new_inside_existing_conflicts(self):  # /25 falls inside /23
        self.assertConflict(self.new("N", "192.168.0.0/25", "10.0.5.0/24"))

    def test_new_contains_existing_conflicts(self):  # existing /23 falls inside new /16
        self.assertConflict(self.new("N", "192.168.0.0/16", "10.0.0.0/8"))

    def test_partial_overlap_across_a_list_conflicts(self):  # only one network of the new list touches the existing one
        self.assertConflict(self.new("N", "172.16.0.0/24, 192.168.1.0/24", "10.0.9.0/24, 11.0.0.0/24"))

    def test_single_address_inside_network_conflicts(self):
        self.assertConflict(self.new("N", "192.168.1.77", "10.0.200.1"))

    def test_non_overlapping_both_sides_allowed(self):
        self.assertAllowed(self.new("N", "172.16.0.0/24", "172.20.0.0/24"))

    def test_adjacent_networks_do_not_overlap(self):  # 192.168.2.0/24 sits right after 192.168.0.0/23
        self.assertAllowed(self.new("N", "192.168.2.0/24", "10.1.0.0/16"))

    def test_remote_only_overlap_allowed(self):
        self.assertAllowed(self.new("N", "172.16.0.0/24", "10.0.5.0/24"))

    def test_local_only_overlap_allowed(self):
        self.assertAllowed(self.new("N", "192.168.1.0/24", "172.20.0.0/24"))


class AcrossTunnelsTests(VpnDocsBase):
    def test_overlaps_on_different_existing_tunnels_allowed(self):
        vpndocs.add(vpn("LocalOnly", local="192.168.0.0/24", remote="172.30.0.0/24", lgw="5.5.5.5", rgw="6.6.6.6"))
        vpndocs.add(vpn("RemoteOnly", local="172.31.0.0/24", remote="10.0.0.0/24", lgw="7.7.7.7", rgw="8.8.8.8"))
        # local overlaps LocalOnly, remote overlaps RemoteOnly: never the same tunnel
        self.assertAllowed(vpn("N", "192.168.0.0/25", "10.0.0.0/25", lgw="3.3.3.3", rgw="4.4.4.4"))

    def test_conflict_names_the_tunnel_that_matches_both_sides(self):
        vpndocs.add(vpn("Other", local="192.168.0.0/24", remote="172.30.0.0/24", lgw="5.5.5.5", rgw="6.6.6.6"))
        vpndocs.add(vpn("Match", local="192.168.0.0/24", remote="10.0.0.0/24", lgw="7.7.7.7", rgw="8.8.8.8"))
        self.assertConflict(vpn("N", "192.168.0.0/25", "10.0.0.0/25", lgw="3.3.3.3", rgw="4.4.4.4"), existing_name="Match")


class EditAndImportTests(VpnDocsBase):
    def test_editing_a_tunnel_does_not_conflict_with_itself(self):
        rec = vpndocs.add(vpn("Existing"))
        _, changed = vpndocs.update(rec["id"], vpn("Existing") | {"description": "edited"})
        self.assertEqual(changed, ["description"])

    def test_edit_into_a_conflict_is_refused(self):
        vpndocs.add(vpn("Existing", local="192.168.0.0/23", remote="10.0.0.0/16"))
        other = vpndocs.add(vpn("Other", local="172.16.0.0/24", remote="172.20.0.0/24", lgw="3.3.3.3", rgw="4.4.4.4"))
        with self.assertRaises(ValueError) as cm:
            vpndocs.update(other["id"], vpn("Other", "192.168.0.0/25", "10.0.1.0/24", lgw="3.3.3.3", rgw="4.4.4.4"))
        self.assertIn("conflicts with existing VPN tunnel", str(cm.exception))

    def test_csv_import_skips_conflicting_rows_with_the_reason(self):
        csv_text = ("VPN Name,Local GW,Remote GW,Local Subnet,Remote Subnet,Description\n"
                    "A,1.1.1.1,2.2.2.2,192.168.0.0/23,10.0.0.0/16,\n"
                    "B,3.3.3.3,4.4.4.4,192.168.0.0/25,10.0.5.0/24,\n"
                    "C,5.5.5.5,6.6.6.6,172.16.0.0/24,172.20.0.0/24,\n")
        results = vpndocs.import_csv(csv_text)
        self.assertEqual([r["ok"] for r in results], [True, False, True])
        self.assertIn("conflicts with existing VPN tunnel 'A'", results[1]["reason"])


class ExistingRulesStillApplyTests(VpnDocsBase):
    def test_same_gateway_pair_still_refused(self):
        vpndocs.add(vpn("A"))
        with self.assertRaises(ValueError) as cm:
            vpndocs.add(vpn("B", local="172.16.0.0/24", remote="172.20.0.0/24"))  # same gateways, different subnets
        self.assertIn("is already used in VPN 'A'", str(cm.exception))

    def test_same_name_still_refused(self):
        vpndocs.add(vpn("A"))
        with self.assertRaises(ValueError):
            vpndocs.add(vpn("a", "172.16.0.0/24", "172.20.0.0/24", lgw="3.3.3.3", rgw="4.4.4.4"))


if __name__ == "__main__":
    unittest.main()
