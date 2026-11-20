import itertools
import secrets
import unittest

import shamir
from committee import Committee, ShamirScheme, Share
from shamir import PRIME, ShamirError


class TestScheme(unittest.TestCase):
    def test_any_t_of_n_opens(self):
        sch = ShamirScheme(3, 5)
        s = secrets.randbelow(PRIME)
        shares = sch.deal(s)
        for subset in itertools.combinations(shares, 3):
            self.assertEqual(sch.open(list(subset)), s)

    def test_below_threshold_refused(self):
        sch = ShamirScheme(3, 5)
        shares = sch.deal(7)
        with self.assertRaises(ShamirError):
            sch.open(shares[:2])
        with self.assertRaises(ShamirError):
            sch.open([])

    def test_index_out_of_range(self):
        sch = ShamirScheme(2, 3)
        with self.assertRaises(ShamirError):
            sch.open([Share(1, 5), Share(9, 5)])

    def test_bytes(self):
        sch = ShamirScheme(3, 5)
        key = shamir.generate_key()
        self.assertEqual(sch.open_bytes(sch.deal_bytes(key)[:3]), key)

    def test_each_member_gets_one_point(self):
        shares = ShamirScheme(3, 5).deal(5)
        self.assertEqual([s.x for s in shares], [1, 2, 3, 4, 5])


class TestCommittee(unittest.TestCase):
    def setUp(self):
        self.c = Committee(3, 5)
        self.secret = secrets.randbelow(PRIME)
        self.c.deal(self.secret)

    def test_cannot_open_before_deadline(self):
        with self.assertRaises(ShamirError):
            self.c.open()

    def test_opens_after_deadline(self):
        self.c.close_bidding()
        self.assertEqual(self.c.open(), self.secret)

    def test_n_minus_t_offline_still_works(self):
        self.c.close_bidding()
        self.c.nodes[0].online = self.c.nodes[4].online = False
        self.assertEqual(self.c.open(), self.secret)

    def test_t_minus_1_online_fails(self):
        self.c.close_bidding()
        for node in self.c.nodes[:3]:
            node.online = False
        with self.assertRaises(ShamirError):
            self.c.open()

    def test_node_rejects_foreign_share(self):
        with self.assertRaises(ShamirError):
            self.c.nodes[0].receive_share(Share(2, 1))

    def test_unverified_bad_share_gives_wrong_secret(self):
        """Documents the known limitation (no verification yet): a corrupted
        share is NOT detected, reconstruction silently returns a wrong value."""
        self.c.close_bidding()
        good = self.c.nodes[0]._share
        self.c.nodes[0]._share = Share(good.x, (good.y + 1) % PRIME)
        self.assertNotEqual(self.c.open(), self.secret)


if __name__ == "__main__":
    unittest.main(verbosity=2)
