"""
Minimal integration adapter connecting the EXISTING, UNMODIFIED OT
prototype (ot_layer_demo.py, pulled verbatim from
origin/feature/ot-prototype) to this project's auction demo.

This file introduces NO new cryptography. Every cryptographic
operation -- SimROT's trusted-dealer correlated-randomness generation,
the bit-decomposed 1-out-of-2 OT composition, HKDF-SHA256 key
derivation, and AES-256-GCM encryption/authentication -- is exactly
ot_layer_demo.py's own Sender/Receiver/SimROT classes, imported and
composed here, not reimplemented.

================================================================
SIMULATED OT -- NOT CRYPTOGRAPHICALLY SECURE.
================================================================
ot_layer_demo.py's own header is explicit about this: SimROT is a
trusted-dealer test substitute for a real 1-out-of-2 random OT. This
adapter changes nothing about that fact -- it only wires the existing
simulator into this project's auctioneer-sender / bidder-receiver
demo. Do not present a result from this module as evidence of OT's
real security property.

Deliberately kept separate from LPCom, Esgin/WCM LRS, and Shamir: this
module imports nothing from lattice_lrs, and nothing in the auction's
real cryptographic flow (SubmitBid, RevealOpening, VerifyOpening)
imports this module either.
"""

import math
import os
import sys
from pathlib import Path

# ot_layer_demo.py lives in this same directory; make it importable
# without requiring OT/ to be installed as a package.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ot_layer_demo import Sender, Receiver, SimROT  # noqa: E402  (existing, unmodified)


class PrivateSelectionSession:
    """One auctioneer-sender / bidder-receiver run of
    ot_layer_demo.py's existing 1-out-of-N interface. Pure composition:
    constructs the existing Sender once (auctioneer's payloads), then
    select() constructs the existing Receiver and drives the existing
    request()/respond()/finish() exchange exactly as
    ot_layer_demo.run() already does, returning a UI-friendly result
    instead of a bare tuple.
    """

    def __init__(self, payloads: list, session: bytes = b"auction-ot-demo"):
        if len(payloads) < 2:
            raise ValueError("at least two payloads are required for 1-out-of-N OT")
        self.payloads = payloads
        self.N = len(payloads)
        self.session = session
        self.query = os.urandom(8)
        self.l = max(1, math.ceil(math.log2(self.N)))
        # SimROT: the existing trusted-dealer simulator, unmodified.
        self._pairs, self._r, self._keys = SimROT().get(self.l)
        # Sender: the existing class, unmodified.
        self.sender = Sender(self.session, self.query, self.payloads, self._pairs)

    def select(self, choice: int) -> dict:
        """Runs one full OT exchange for a receiver choice, using only
        ot_layer_demo's existing Receiver.request()/Sender.respond()/
        Receiver.finish(). Returns a dict safe to render in a UI."""
        if not (0 <= choice < self.N):
            raise ValueError("choice out of range")

        # Receiver: the existing class, unmodified.
        receiver = Receiver(self.session, self.query, self.N, choice,
                           self._r, self._keys)
        request_bits = receiver.request()
        ciphertexts = self.sender.respond(request_bits)

        outcomes = []
        selected_payload = None
        for index in range(self.N):
            try:
                plaintext = receiver.finish(ciphertexts, index)
                outcomes.append({"index": index, "status": "decrypted"})
                if index == choice:
                    selected_payload = plaintext
            except Exception:
                # The existing Receiver.finish() raises
                # cryptography.exceptions.InvalidTag for any index the
                # receiver did not select -- caught broadly here only
                # because this adapter does not import that exception
                # type itself (ot_layer_demo.py does); any decryption
                # failure is reported identically either way.
                outcomes.append({"index": index, "status": "auth_failed"})

        return {
            "N": self.N,
            "l": self.l,
            "choice": choice,
            "request_bits": request_bits,
            "ciphertext_sizes": [len(ct) for ct in ciphertexts],
            "selected_payload": selected_payload,
            "outcomes": outcomes,
        }
