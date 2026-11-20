# Integration tests for shamir_secret_sharing/settlement_seal.py -- the
# minimal adapter composing the EXISTING, UNMODIFIED Shamir
# implementation (shamir.py/committee.py, pulled verbatim from
# origin/feature/shamir-threshold) with the existing `cryptography`
# AEAD dependency. No cryptographic primitive is reimplemented here;
# these tests exercise the SEALING/UNSEALING composition and the
# trustee-bookkeeping this project added on top.

import dataclasses
import sys
import unittest
from pathlib import Path

SHAMIR_DIR = Path(__file__).resolve().parents[1] / "shamir_secret_sharing"
sys.path.insert(0, str(SHAMIR_DIR))

from committee import Share  # noqa: E402
from settlement_seal import (  # noqa: E402
    SettlementSealError,
    SettlementTrusteeStore,
    seal_opening,
    unseal_opening,
)

T, N = 3, 5


def _seal(auction_id="auction-A", submission_index=0, commitment_hex="deadbeef",
          amount=150, randomness=None, t=T, n=N):
    randomness = randomness if randomness is not None else list(range(1, 17))
    return seal_opening(auction_id, submission_index, commitment_hex, amount,
                        randomness, t=t, n=n) + (amount, randomness)


class TestCorrectReconstruction(unittest.TestCase):
    def test_exactly_t_shares_reconstructs(self):
        sealed, shares, amount, randomness = _seal()
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        for s in shares[:T]:
            store.submit_share(s.x, s)
        rec_amount, rec_r = unseal_opening(sealed, store.shares(), T, N)
        self.assertEqual(rec_amount, amount)
        self.assertEqual(rec_r, randomness)

    def test_more_than_t_shares_also_reconstructs(self):
        sealed, shares, amount, randomness = _seal()
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        for s in shares:  # all N
            store.submit_share(s.x, s)
        rec_amount, rec_r = unseal_opening(sealed, store.shares(), T, N)
        self.assertEqual(rec_amount, amount)
        self.assertEqual(rec_r, randomness)

    def test_different_subsets_of_t_all_reconstruct_the_same_value(self):
        sealed, shares, amount, _ = _seal()
        for subset in [shares[0:3], shares[1:4], shares[2:5], [shares[0], shares[2], shares[4]]]:
            store = SettlementTrusteeStore("auction-A", 0, T, N)
            for s in subset:
                store.submit_share(s.x, s)
            rec_amount, _ = unseal_opening(sealed, store.shares(), T, N)
            self.assertEqual(rec_amount, amount)


class TestThresholdRejection(unittest.TestCase):
    def test_below_threshold_is_rejected(self):
        sealed, shares, _, _ = _seal()
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        for s in shares[:T - 1]:
            store.submit_share(s.x, s)
        with self.assertRaises(SettlementSealError):
            unseal_opening(sealed, store.shares(), T, N)

    def test_zero_shares_is_rejected(self):
        sealed, _, _, _ = _seal()
        with self.assertRaises(SettlementSealError):
            unseal_opening(sealed, [], T, N)


class TestTrusteeValidation(unittest.TestCase):
    def test_duplicate_trustee_identical_share_is_idempotent(self):
        _, shares, _, _ = _seal()
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        store.submit_share(shares[0].x, shares[0])
        store.submit_share(shares[0].x, shares[0])  # same share again: no-op
        self.assertEqual(store.collected_count(), 1)

    def test_duplicate_trustee_conflicting_share_is_rejected(self):
        _, shares, _, _ = _seal()
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        store.submit_share(shares[0].x, shares[0])
        conflicting = Share(shares[0].x, shares[0].y + 1)
        with self.assertRaises(SettlementSealError):
            store.submit_share(shares[0].x, conflicting)

    def test_invalid_trustee_id_out_of_range_is_rejected(self):
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        with self.assertRaises(SettlementSealError):
            store.submit_share(0, Share(0, 123))
        with self.assertRaises(SettlementSealError):
            store.submit_share(N + 1, Share(N + 1, 123))

    def test_mismatched_share_index_is_rejected(self):
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        with self.assertRaises(SettlementSealError):
            store.submit_share(2, Share(3, 123))  # trustee_id != share.x

    def test_malformed_share_type_is_rejected(self):
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        with self.assertRaises(SettlementSealError):
            store.submit_share(1, (1, 123))  # not a Share instance

    def test_scheme_rejects_bad_t_n(self):
        with self.assertRaises(SettlementSealError):
            SettlementTrusteeStore("auction-A", 0, t=0, n=5)
        with self.assertRaises(SettlementSealError):
            SettlementTrusteeStore("auction-A", 0, t=6, n=5)


class TestWrongAuctionOrSubmission(unittest.TestCase):
    def test_shares_for_a_different_submission_do_not_unseal_this_one(self):
        sealed_a, shares_a, _, _ = _seal(submission_index=0)
        sealed_b, shares_b, _, _ = _seal(submission_index=1)

        # B's shares reconstruct B's key; using B's reconstructed
        # material against A's ciphertext must fail -- the AAD
        # (bound to submission_index) will not match.
        store_b = SettlementTrusteeStore("auction-A", 1, T, N)
        for s in shares_b[:T]:
            store_b.submit_share(s.x, s)
        with self.assertRaises(SettlementSealError):
            unseal_opening(sealed_a, store_b.shares(), T, N)

    def test_shares_for_a_different_auction_do_not_unseal_this_one(self):
        sealed_a, _, _, _ = _seal(auction_id="auction-A")
        sealed_b, shares_b, _, _ = _seal(auction_id="auction-B")

        store_b = SettlementTrusteeStore("auction-B", 0, T, N)
        for s in shares_b[:T]:
            store_b.submit_share(s.x, s)
        with self.assertRaises(SettlementSealError):
            unseal_opening(sealed_a, store_b.shares(), T, N)

    def test_wrong_commitment_hex_does_not_unseal(self):
        sealed, shares, _, _ = _seal(commitment_hex="commitment-1")
        tampered_binding = dataclasses.replace(sealed, commitment_hex="commitment-2")
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        for s in shares[:T]:
            store.submit_share(s.x, s)
        with self.assertRaises(SettlementSealError):
            unseal_opening(tampered_binding, store.shares(), T, N)


class TestEncryptionIntegrity(unittest.TestCase):
    def test_tampered_ciphertext_is_rejected(self):
        sealed, shares, _, _ = _seal()
        tampered = dataclasses.replace(
            sealed,
            ciphertext=bytes([sealed.ciphertext[0] ^ 0x01]) + sealed.ciphertext[1:])
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        for s in shares[:T]:
            store.submit_share(s.x, s)
        with self.assertRaises(SettlementSealError):
            unseal_opening(tampered, store.shares(), T, N)

    def test_tampered_nonce_is_rejected(self):
        sealed, shares, _, _ = _seal()
        tampered = dataclasses.replace(
            sealed, nonce=bytes([sealed.nonce[0] ^ 0x01]) + sealed.nonce[1:])
        store = SettlementTrusteeStore("auction-A", 0, T, N)
        for s in shares[:T]:
            store.submit_share(s.x, s)
        with self.assertRaises(SettlementSealError):
            unseal_opening(tampered, store.shares(), T, N)

    def test_each_sealing_uses_a_fresh_key_and_nonce(self):
        sealed_1, _, _, _ = _seal()
        sealed_2, _, _, _ = _seal()
        self.assertNotEqual(sealed_1.nonce, sealed_2.nonce)
        self.assertNotEqual(sealed_1.ciphertext, sealed_2.ciphertext)

    def test_plaintext_never_appears_in_the_sealed_record(self):
        amount = 999999
        sealed, _, _, randomness = _seal(amount=amount)
        serialized = sealed.ciphertext + sealed.nonce
        self.assertNotIn(str(amount).encode(), serialized)


class TestNoLeakageAndNoBypass(unittest.TestCase):
    def test_sealed_opening_dataclass_has_no_plaintext_fields(self):
        sealed, _, _, _ = _seal()
        field_names = {f.name for f in dataclasses.fields(sealed)}
        self.assertEqual(
            field_names,
            {"auction_id", "submission_index", "commitment_hex", "nonce", "ciphertext"})

    def test_share_objects_do_not_carry_the_key_or_opening(self):
        _, shares, _, _ = _seal()
        for share in shares:
            field_names = {f.name for f in dataclasses.fields(share)}
            self.assertEqual(field_names, {"x", "y"})

    def test_reconstruction_requires_the_real_shares_not_a_shortcut(self):
        # There is no function in this module that returns (amount,
        # randomness) without BOTH a valid SealedOpening AND >= t real
        # shares -- confirmed structurally: unseal_opening's only two
        # parameters besides (t, n) are `sealed` and `shares`, and
        # guessing fake shares fails like any below-threshold/tampered
        # case already covered above.
        sealed, _, _, _ = _seal()
        fake_shares = [Share(1, 111), Share(2, 222), Share(3, 333)]
        with self.assertRaises(SettlementSealError):
            unseal_opening(sealed, fake_shares, T, N)


if __name__ == "__main__":
    unittest.main(verbosity=2)
