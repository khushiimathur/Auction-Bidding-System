"""
Settlement sealing: threshold-controlled encryption-key protection for an
LPCom bid opening (v, r), built ONLY by composing:

  - this project's EXISTING, UNMODIFIED Shamir implementation
    (shamir.generate_key, committee.ShamirScheme.deal_bytes/open_bytes),
    pulled verbatim from origin/feature/shamir-threshold;
  - the EXISTING `cryptography` dependency (AESGCM), already a project
    requirement because OT/ot_layer_demo.py uses it.

No new cryptographic primitive is implemented here: no AES, no HKDF, no
Shamir math. This module only decides WHAT gets encrypted, WHAT goes in
the authenticated associated data, and HOW shares are collected from
simulated trustees before `ShamirScheme.open()` is ever called.

--- What Shamir protects here, precisely ---
Shamir does NOT split the bid, the LPCom commitment, or the opening
(v, r) itself. It splits a FRESH, PER-SUBMISSION symmetric key K. (v, r)
is encrypted under K with AES-256-GCM; K is what gets Shamir-split
across trustees. Reconstructing K requires >= t trustee shares;
decrypting (v, r) then requires both K and the original AAD (binding
auction_id, submission_index, and the commitment hex) to match exactly
what the ciphertext was sealed under.

--- Known, stated limitation (not fixed here, not claimed otherwise) ---
The underlying Shamir is ORDINARY, non-verifiable sharing (see
shamir_secret_sharing/README.md's own "Current limitations" --
unmodified by this module). A corrupted trustee share is not detected
as corrupted; it simply fails to reconstruct the correct K, which then
fails AES-GCM authentication on decrypt (a cryptographic side effect of
AEAD, not a Shamir verification property). This module does not claim
Shamir itself detects tampering -- only that the AEAD layer around it
does, for the key it wraps.

--- Single-process simulation ---
Trustees here are Python objects inside one process (the Streamlit
session), exactly like shamir_secret_sharing/committee.py's own
Committee/Auctioneer simulation. There is no network, no real
distributed trust boundary. See docs/WCM_AUCTION_INTEGRATION.md.
"""

import os
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import shamir
from committee import Share, ShamirScheme
from shamir import ShamirError


class SettlementSealError(Exception):
    pass


def _length_prefixed(*parts: bytes) -> bytes:
    """Unambiguous length-prefixed encoding, identical in spirit to
    OT/ot_layer_demo.py's own `lp()` helper (not imported from there to
    keep this module's only dependency on OT at zero, per the
    constraint that OT integration must stay untouched and separate)."""
    return b"".join(struct.pack(">I", len(part)) + part for part in parts)


def build_aad(auction_id: str, submission_index: int, commitment_hex: str) -> bytes:
    """The authenticated associated data every sealed opening is bound
    to. Binding all three fields is what makes a share, ciphertext, or
    key from one auction/submission/commitment structurally unusable
    for any other: even if a reconstructed key were (incorrectly)
    reused against a different submission's ciphertext, decryption
    would fail here because the AAD would not match what that
    ciphertext was actually sealed under."""
    return _length_prefixed(
        b"pq-auction-settlement-seal-v1",
        auction_id.encode("utf-8"),
        struct.pack(">Q", submission_index),
        commitment_hex.encode("utf-8"),
    )


@dataclass(frozen=True)
class SealedOpening:
    """What gets stored publicly-visible-but-useless after sealing:
    ciphertext + nonce + the AAD context it was bound to. NEVER the
    key K, NEVER the plaintext (v, r)."""
    auction_id: str
    submission_index: int
    commitment_hex: str
    nonce: bytes
    ciphertext: bytes


def seal_opening(auction_id: str, submission_index: int, commitment_hex: str,
                 amount: int, randomness: List[int],
                 t: int, n: int) -> "tuple[SealedOpening, List[Share]]":
    """Generates a FRESH key K (shamir.generate_key() -- the existing
    CSPRNG-backed key generator, unmodified), encrypts (amount,
    randomness) under K with a fresh nonce and AEAD binding this
    submission's identity, then Shamir-splits K into n shares with
    threshold t (committee.ShamirScheme.deal_bytes(), unmodified).

    The caller MUST discard `amount`/`randomness` and K immediately
    after this call returns -- this function itself never stores
    either. Returns the sealed (public, harmless-without-the-key)
    ciphertext record and the list of shares to distribute to
    trustees.
    """
    key = shamir.generate_key()  # existing, unmodified: 32 random bytes < PRIME
    scheme = ShamirScheme(t, n)
    shares = scheme.deal_bytes(key)  # existing, unmodified Shamir split

    plaintext = (
        struct.pack(">Q", amount)
        + struct.pack(">I", len(randomness))
        + b"".join(struct.pack(">Q", value) for value in randomness)
    )
    nonce = os.urandom(12)
    aad = build_aad(auction_id, submission_index, commitment_hex)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    sealed = SealedOpening(auction_id, submission_index, commitment_hex,
                          nonce, ciphertext)
    return sealed, shares


def unseal_opening(sealed: SealedOpening, shares: List[Share],
                   t: int, n: int) -> "tuple[int, List[int]]":
    """Reconstructs K from >= t shares (committee.ShamirScheme.open(),
    unmodified -- this is what actually enforces the threshold; a call
    with fewer than t shares raises shamir.ShamirError from THAT
    existing code, not a check duplicated here), then decrypts and
    authenticates the opening. Raises SettlementSealError (wrapping the
    underlying cause) on any failure -- wrong threshold, tampered
    ciphertext, or mismatched AAD (e.g. shares/ciphertext from a
    different auction or submission) all surface here as a rejection,
    never a silently wrong result.
    """
    scheme = ShamirScheme(t, n)
    try:
        key = scheme.open_bytes(shares)
    except ShamirError as error:
        raise SettlementSealError(f"threshold reconstruction failed: {error}") from error

    aad = build_aad(sealed.auction_id, sealed.submission_index, sealed.commitment_hex)
    try:
        plaintext = AESGCM(key).decrypt(sealed.nonce, sealed.ciphertext, aad)
    except InvalidTag as error:
        raise SettlementSealError(
            "opening failed authentication: wrong key, tampered ciphertext, "
            "or mismatched auction/submission/commitment binding") from error

    offset = 0
    (amount,) = struct.unpack_from(">Q", plaintext, offset)
    offset += 8
    (randomness_count,) = struct.unpack_from(">I", plaintext, offset)
    offset += 4
    randomness = [
        struct.unpack_from(">Q", plaintext, offset + 8 * i)[0]
        for i in range(randomness_count)
    ]
    return amount, randomness


class SettlementTrusteeStore:
    """Per-(auction_id, submission_index) share collection. This is
    NEW bookkeeping code -- it duplicates none of Shamir's math -- on
    top of the existing Share/ShamirScheme types. Deliberately rejects
    what the task requires rejected; final threshold/duplicate-x
    enforcement still happens again, independently, inside the
    existing shamir.reconstruct()/ShamirScheme.open() when
    reconstruct() is called, so this store's own checks are
    defense-in-depth, not the sole enforcement point.
    """

    def __init__(self, auction_id: str, submission_index: int, t: int, n: int):
        if not (1 <= t <= n):
            raise SettlementSealError("need 1 <= t <= n")
        self.auction_id = auction_id
        self.submission_index = submission_index
        self.t = t
        self.n = n
        self._shares: Dict[int, Share] = {}

    def submit_share(self, trustee_id: int, share: Share) -> None:
        if not isinstance(trustee_id, int) or not isinstance(share, Share):
            raise SettlementSealError("malformed share submission")
        if not (1 <= trustee_id <= self.n):
            raise SettlementSealError(
                f"invalid trustee id {trustee_id}: must be in 1..{self.n}")
        if share.x != trustee_id:
            raise SettlementSealError(
                "share index does not match the submitting trustee id")
        existing = self._shares.get(trustee_id)
        if existing is not None:
            if existing.y != share.y:
                raise SettlementSealError(
                    f"trustee {trustee_id} already submitted a different share "
                    "(duplicate trustee submission with conflicting data)")
            return  # idempotent resubmission of the identical share: no-op
        self._shares[trustee_id] = share

    def collected_count(self) -> int:
        return len(self._shares)

    def threshold_met(self) -> bool:
        return len(self._shares) >= self.t

    def shares(self) -> List[Share]:
        return list(self._shares.values())
