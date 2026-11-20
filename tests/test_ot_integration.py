# Tests for the OT integration adapter (OT/auction_ot_adapter.py) and a
# direct invocation of the EXISTING, UNMODIFIED self-test in
# OT/ot_layer_demo.py (pulled verbatim from origin/feature/ot-prototype).
#
# These are explicitly split into two kinds, per the integration task's
# own requirement to distinguish them:
#   - "Simulator functionality" tests: confirm the existing SimROT-based
#     1-out-of-N interface and this adapter's composition over it behave
#     as documented (selected index decrypts, others fail AEAD auth).
#     These say NOTHING about real OT security -- SimROT is a trusted
#     dealer.
#   - There are no "cryptographic security" tests here, deliberately:
#     this module has no real OT security property to test. A security
#     test suite only becomes meaningful once SimROT is replaced by a
#     real base OT (see the integration report's "remaining work").

import math
import subprocess
import sys
import unittest
from pathlib import Path

OT_DIR = Path(__file__).resolve().parents[1] / "OT"
sys.path.insert(0, str(OT_DIR))

from auction_ot_adapter import PrivateSelectionSession  # noqa: E402


class TestExistingSelfTestStillPasses(unittest.TestCase):
    """Runs ot_layer_demo.py's own, pre-existing __main__ self-test
    exactly as committed on origin/feature/ot-prototype -- not
    reimplemented, just invoked as a subprocess. This is the
    "simulator functionality" check for the underlying module itself,
    independent of this adapter."""

    def test_vendored_self_test_passes(self):
        result = subprocess.run(
            [sys.executable, str(OT_DIR / "ot_layer_demo.py")],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("all tests passed", result.stdout)


class TestAdapterSimulatorFunctionality(unittest.TestCase):
    """Simulator functionality tests for the integration adapter --
    confirms the adapter's composition over the existing Sender/
    Receiver/SimROT reproduces exactly the selection behavior
    ot_layer_demo.py's own self-test already demonstrates, now through
    the UI-facing PrivateSelectionSession interface."""

    def test_selected_index_decrypts_others_fail(self):
        payloads = [f"lot-{i}".encode() for i in range(6)]
        for choice in range(len(payloads)):
            session = PrivateSelectionSession(payloads)
            result = session.select(choice)
            self.assertEqual(result["selected_payload"], payloads[choice])
            for outcome in result["outcomes"]:
                expected = "decrypted" if outcome["index"] == choice else "auth_failed"
                self.assertEqual(outcome["status"], expected)

    def test_request_bits_length_matches_log2_n(self):
        payloads = [b"a", b"b", b"c", b"d", b"e"]  # N=5 -> l=3
        session = PrivateSelectionSession(payloads)
        result = session.select(2)
        self.assertEqual(result["l"], math.ceil(math.log2(5)))
        self.assertEqual(len(result["request_bits"]), result["l"])

    def test_two_payload_minimum(self):
        session = PrivateSelectionSession([b"x", b"y"])
        result = session.select(0)
        self.assertEqual(result["selected_payload"], b"x")

    def test_rejects_single_payload(self):
        with self.assertRaises(ValueError):
            PrivateSelectionSession([b"only one"])

    def test_rejects_out_of_range_choice(self):
        session = PrivateSelectionSession([b"a", b"b", b"c"])
        with self.assertRaises(ValueError):
            session.select(3)
        with self.assertRaises(ValueError):
            session.select(-1)

    def test_independent_sessions_use_independent_randomness(self):
        # Each PrivateSelectionSession draws fresh SimROT material via
        # os.urandom; two independent sessions over the SAME payloads
        # must draw different underlying pairs, guarding against an
        # accidentally-fixed/frozen randomness source in the adapter's
        # wiring.
        payloads = [b"same", b"payloads", b"every", b"time"]
        first_session = PrivateSelectionSession(payloads)
        second_session = PrivateSelectionSession(payloads)
        self.assertNotEqual(first_session._pairs, second_session._pairs)
        first = first_session.select(0)
        second = second_session.select(0)
        self.assertEqual(first["selected_payload"], b"same")
        self.assertEqual(second["selected_payload"], b"same")


if __name__ == "__main__":
    unittest.main(verbosity=2)
