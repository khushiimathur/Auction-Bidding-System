#pragma once

// Phase D of the Wang-Chen-Ma (WCM) linkable ring signature integration:
// the Link algorithm. Pure composition over Phase C's LRVerify -- no
// verification logic is duplicated here.
//
// --- Exact WCM algorithm implemented (cite: Wang, Chen, Ma, "Adding
// Linkability to Ring Signatures with One-Time Signatures", ISC 2019,
// Section 3.1 "Construction", the Link bullet) ---
//
//   Link(m1, m2, sigma1, sigma2, T1, T2):
//     1. Run Vrfy(m1, sigma1, T1) and Vrfy(m2, sigma2, T2).
//     2. If either call rejects, abort.
//     3. Otherwise parse sigma1 = (\hat{sigma}1, \tilde{sigma}1, ovk1) and
//        sigma2 = (\hat{sigma}2, \tilde{sigma}2, ovk2).
//     4. Compare ovk1 and ovk2: output "linked" if ovk1 = ovk2, otherwise
//        "unlinked".
//
// Section 2.3's formal Linkability game (Definition 3) requires this
// comparison to hold even for an adversarially chosen pair of (T, m, sigma)
// triples, which is exactly why step 1-2 (both must independently verify)
// happens before step 3-4 (the plain equality test) -- an attacker cannot
// manufacture a LINKED or UNLINKED verdict from a signature that would not
// itself pass LRVerify.
//
// --- What this file does NOT do, and why ---
// - It does not compare messages, rings, signer indices, or the underlying
//   Esgin signatures (\hat{sigma}). WCM's own text is explicit that
//   linkability is decided "solely" by ovk1 =? ovk2 once both signatures
//   verify; comparing anything else would not be following the paper.
// - It introduces no auction/context identifier, matching the same
//   constraint already honoured by Phase C's LRSign/LRVerify.
// - It does not persist any record of which ovk values have been seen
//   before; Link is a pure, stateless pairwise comparison, exactly as
//   specified. Any application wanting to detect reuse across more than two
//   signatures (e.g. "has this ovk appeared in any prior bid") must call
//   Link repeatedly itself and keep its own external record -- that is an
//   application-level concern, not part of the WCM algorithm, and is
//   explicitly out of scope for this phase.
//
// --- One-time linkability limitation (paper's own Section 6 "Discussion",
// reproduced here because it directly bounds what a LINKED verdict means) ---
// WCM Section 6 states: "linkability in this paper is only one-time
// linkability, which means the linkability tag is not bound to a general
// linkability context such as the ring of possible signers nor the message
// being signed, but only bound to a signer." Concretely: a LINKED verdict
// means "these two signatures were produced using the same OTS key pair
// (ovk, osk)" -- nothing more. It does NOT mean the same ring, the same
// message, or the same logical "transaction"/"auction round" were involved;
// WCM's intended usage (and this implementation's intended usage) is that
// an honest party generates a brand-new OTS key pair via LRKeygen for every
// distinct signing context it wants to be unlinkable from every other
// context, and reuses an OTS key pair only when it wants exactly that
// specific pair of signatures to be linkable (e.g. the same lattice ring
// signature public/secret key being used to sign twice within whatever
// scope the application has decided an OTS key pair should cover).
//
// --- Carried-over caveats from Phases A-C (repeated here; still apply) ---
// 1. ovk/osk are lattice_lrs::ots Dilithium5 (Round 3) keys, a documented
//    stand-in for the "very high" parameter set of the original 2018
//    CRYSTALS-Dilithium paper WCM cites -- see dilithium_ots.hpp.
// 2. Phase B's H' is a SHAKE256-XOF-with-rejection-sampling construction,
//    an implementation choice, not something the paper's text fixes.
// 3. Phase C's LRSign/LRVerify (and therefore Link, since it only calls
//    LRVerify) depend on Protocol2RSignGaussianProvider and
//    RSignBatchRejectionProvider, for which this repository has NO
//    production implementation -- only explicit, non-cryptographic test
//    doubles exist (tests/test_rsign_batch.cpp and, by the same pattern,
//    tests/test_linkable_ring_signature.cpp / tests/test_link.cpp). Any
//    LinkOutcome produced using those doubles reflects only the test
//    fixture's internal consistency, not a cryptographically sound Esgin
//    ring-signature verification.
// 4. OneTimeOtsKeyGuard enforces one-time OTS key use only within the
//    lifetime of a single guard object in one process; it is not revisited
//    or weakened by this file. Link is designed to be the mechanism that
//    *detects* a violation of that assumption after the fact (two
//    signatures sharing one ovk), not a mechanism that prevents it at
//    signing time.
//
// --- Security disclaimer ---
// Passing the Phase D unit tests establishes that Link composes correctly
// over LRVerify and returns the documented outcome on the paths exercised.
// It does not establish the paper's Linkability or Nonslanderability
// security properties (Definitions 3-4).

#include "lattice_lrs/lrs/linkable_ring_signature.hpp"

namespace lattice_lrs::lrs {

// Kept distinct from a plain bool specifically so that "both signatures
// verified but carry different ovk" (Unlinked) can never be confused with
// "at least one signature failed to verify" (Rejected) -- the paper's Link
// algorithm aborts outright in the latter case; it never reaches the ovk
// comparison at all.
enum class LinkOutcome {
    Linked,
    Unlinked,
    Rejected,
};

// Link(m1, sigma1, T1, m2, sigma2, T2) per WCM Section 3.1. public_parameters
// / proof_parameters / transcript_encoder / auxiliary_commitment are shared
// by both LRVerify calls (a single Link invocation only makes sense within
// one lattice_lrs scheme deployment; the paper does not contemplate
// comparing signatures produced under different public parameters).
//
// Returns Rejected if either LRVerify(..., ring1, message1, signature1, ...)
// or LRVerify(..., ring2, message2, signature2, ...) returns false --
// covering a modified message, a modified ring, a tampered base or OTS
// signature, or a structurally malformed signature, exactly as LRVerify
// itself already rejects those (see linkable_ring_signature.hpp). Only when
// BOTH verify does Link compare the complete ovk byte encodings
// (ots::DilithiumPublicKey::bytes, a fixed-size std::array compared
// element-wise via its built-in operator==) and return Linked or Unlinked.
LinkOutcome Link(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring1,
    const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1,
    const proofs::Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

LinkOutcome LinkForTesting(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring1,
    const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1,
    const proofs::Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

}  // namespace lattice_lrs::lrs
