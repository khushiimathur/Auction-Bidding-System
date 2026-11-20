import itertools
import secrets
import unittest

import shamir
from shamir import PRIME, ShamirError, split, reconstruct


class TestSlideExample(unittest.TestCase):
    """Slide example: 3-out-of-5, f(x) = 5 + 3x + 2x^2, secret = 5."""

    SHARES = [(1, 10), (2, 19), (3, 32), (4, 49), (5, 70)]

    def test_all_subsets_of_three_recover_secret(self):
        for subset in itertools.combinations(self.SHARES, 3):
            self.assertEqual(reconstruct(list(subset)), 5)

    def test_more_than_threshold_also_works(self):
        self.assertEqual(reconstruct(self.SHARES[:4]), 5)
        self.assertEqual(reconstruct(self.SHARES), 5)

    def test_two_shares_give_wrong_value(self):
        for subset in itertools.combinations(self.SHARES, 2):
            self.assertNotEqual(reconstruct(list(subset)), 5)

    def test_two_shares_consistent_with_any_secret(self):
        """Threshold property: for ANY guess s, a degree-2 polynomial with
        f(0)=s passes through the 2 known points. So 2 shares reveal nothing."""
        (x1, y1), (x2, y2) = self.SHARES[0], self.SHARES[1]
        for guess in [0, 5, 123, 99999]:
            # reconstruct from the two shares plus a hypothetical third point
            # (0, guess): there is a unique quadratic through all three, so
            # every guess is consistent with the two real shares.
            third_x = 3
            # solve for y3 so that interpolation at 0 yields `guess`
            known = reconstruct([(x1, y1), (x2, y2), (third_x, 0)])
            # reconstruct is linear in y3, so find the coefficient
            delta = (reconstruct([(x1, y1), (x2, y2), (third_x, 1)]) - known) % PRIME
            y3 = ((guess - known) * pow(delta, -1, PRIME)) % PRIME
            self.assertEqual(reconstruct([(x1, y1), (x2, y2), (third_x, y3)]), guess)


class TestRoundTrip(unittest.TestCase):
    def test_random_256_bit_secrets(self):
        for _ in range(50):
            s = secrets.randbelow(PRIME)
            t = secrets.randbelow(6) + 2        # 2..7
            n = t + secrets.randbelow(5)        # t..t+4
            shares = split(s, t, n)
            chosen = secrets.SystemRandom().sample(shares, t)
            self.assertEqual(reconstruct(chosen), s)

    def test_edge_secrets(self):
        for s in [0, 1, PRIME - 1]:
            self.assertEqual(reconstruct(split(s, 3, 5)[:3]), s)

    def test_t_equals_n_and_t_equals_1(self):
        s = secrets.randbelow(PRIME)
        self.assertEqual(reconstruct(split(s, 5, 5)), s)
        self.assertEqual(reconstruct(split(s, 1, 4)[2:3]), s)

    def test_bytes_roundtrip(self):
        key = shamir.generate_key()
        shares = shamir.split_bytes(key, 3, 5)
        self.assertEqual(shamir.reconstruct_bytes(shares[1:4]), key)


class TestValidation(unittest.TestCase):
    def test_bad_parameters(self):
        with self.assertRaises(ShamirError):
            split(5, 6, 5)
        with self.assertRaises(ShamirError):
            split(5, 0, 5)
        with self.assertRaises(ShamirError):
            split(PRIME, 2, 3)
        with self.assertRaises(ShamirError):
            split(-1, 2, 3)

    def test_bad_shares(self):
        with self.assertRaises(ShamirError):
            reconstruct([])
        with self.assertRaises(ShamirError):
            reconstruct([(1, 10), (1, 10), (2, 19)])
        with self.assertRaises(ShamirError):
            reconstruct([(0, 5), (1, 10), (2, 19)])

    def test_shares_are_randomised(self):
        a = split(42, 3, 5)
        b = split(42, 3, 5)
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
