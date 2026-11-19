#pragma once

// Phase C of the Wang-Chen-Ma (WCM) linkable ring signature integration:
// LRKeygen, LRSign, LRVerify. Built strictly as composition over:
//   - lattice_lrs::ring_signature::{RKeygen,RSign,RVerify}  (Esgin RS, untouched)
//   - lattice_lrs::ots::{GenerateKeyPair,Sign,Verify}        (Phase A OTS wrapper)
//   - lattice_lrs::lrs::{MaskPublicKey,UnmaskPublicKey}      (Phase B, H')
//
// --- Exact WCM algorithms implemented (cite: Wang, Chen, Ma, "Adding
// Linkability to Ring Signatures with One-Time Signatures", ISC 2019,
// Section 3.1 "Construction" and Section 4 "Instantiation") ---
//
// KeyGen(pp):
//   (p\hat{k}, \hat{sk}) <- RS.KeyGen(p\hat{p})      [Section 3.1]
//   (ovk, osk)           <- OTS.KeyGen               [Section 3.1]
//   pk = p\hat{k} + H'(ovk)                          [Section 4, fixes the
//                                                      abstract Section 3.1
//                                                      "pk = p\hat{k} (op)
//                                                      H(ovk)" to addition
//                                                      in R_q^n]
//   sk = (\hat{sk}, osk, ovk)                        [Section 3.1]
// LRKeygen below returns pk as LinkableKeyPair::linkable_public_key (the
// value the caller publishes/lists in a ring T) and sk as LinkableSecretKey.
//
// Sign(sk_s, m, T = {pk_i}_{i in [N]}):
//   p\hat{k}'_i = pk_i - H'(ovk_s)  for all i in [N]  [Section 4; Section
//                                                      3.1's abstract
//                                                      "pk_i (op)^{-1}
//                                                      H(ovk_s)"]
//   T\hat{}' = {p\hat{k}'_i}
//   \hat{sigma} <- RS.Sign(\hat{sk}_s, m, T\hat{}')   [Section 3.1; this is
//                                                      exactly RSign/
//                                                      RSignForTesting --
//                                                      not reimplemented]
//   \tilde{sigma} <- OTS.Sign(osk_s, (\hat{sigma}, T, ovk_s))
//                                                      [Section 3.1; the
//                                                      message signed by
//                                                      OTS is the TRIPLE
//                                                      (RS signature, the
//                                                      ORIGINAL untransformed
//                                                      ring T, ovk_s) -- NOT
//                                                      m directly, and NOT
//                                                      T\hat{}'. m is bound
//                                                      only transitively,
//                                                      through
//                                                      \hat{sigma}/RS.Vrfy.
//                                                      Section 4's pseudocode
//                                                      literally reuses the
//                                                      symbol \hat{sigma} for
//                                                      this OTS output too;
//                                                      that is a paper typo
//                                                      (it should read
//                                                      \tilde{sigma}), noted
//                                                      in the Phase A/B
//                                                      audit and NOT
//                                                      reproduced here.]
//   sigma = (\hat{sigma}, \tilde{sigma}, ovk_s)       [Section 3.1]
// LRSign below returns sigma as LinkableSignature.
//
// Vrfy(T, m, sigma):
//   parse sigma = (\hat{sigma}, \tilde{sigma}, ovk)
//   p\hat{k}'_i = pk_i - H'(ovk)  for all i in [N]    [same formula as Sign;
//                                                      ovk here is the one
//                                                      PARSED FROM sigma,
//                                                      not supplied
//                                                      separately]
//   accept iff RS.Vrfy(T\hat{}', m, \hat{sigma}) = 1
//          AND OTS.Vrfy(ovk, (\hat{sigma}, T, ovk), \tilde{sigma}) = 1
//                                                      [Section 3.1]
// LRVerify below implements exactly this.
//
// --- Deliberately NOT implemented here (future phase / out of scope) ---
// Link(m1,m2,sigma1,sigma2,T1,T2) is Phase D; this file exposes the
// ingredients (signature.ots_public_key is the tag) but does not compare
// them.
//
// --- Parameters WCM does not specify, and this file does not invent ---
// 1. WCM's Sign takes exactly (sk_s, m, T); there is no auction/context
//    identifier, session id, or epoch parameter anywhere in the paper. If
//    an application (e.g. the sealed-bid auction layer) needs to bind a
//    message to an auction/round, it must fold that into the byte string
//    it passes as `message` -- LRSign/LRVerify add no such field, because
//    inventing one would not be "following the exact WCM equations".
// 2. WCM's prose never names an explicit "signer index" parameter, but
//    RS.Sign cannot run without one: Protocol2Witness::index already
//    requires it in the unmodified Esgin interface, and WCM's Sign silently
//    assumes the signer knows which position in T is their own (otherwise
//    "sk_s" and "T" could not be used together at all). LRSign's
//    `signer_index` parameter is this existing Esgin requirement passed
//    through, not a new WCM-level concept.
// 3. The Protocol2RSignGaussianProvider / RSignBatchRejectionProvider
//    interfaces that RSign/RVerify require have NO production
//    implementation anywhere in this repository as of Phase C -- only
//    explicitly non-cryptographic test doubles exist, in
//    tests/test_rsign_batch.cpp, and the Protocol2RSignGaussianProvider
//    header comment states outright that "Section 6's raw Gaussian widths
//    are not fully resolved by the available specification." This is an
//    inherited gap from the Esgin (Phase 1) layer, not something Phase C
//    introduces or can resolve; LRSign/LRVerify take these providers by
//    reference exactly as RSign/RVerify do, rather than hard-coding a
//    provider that does not yet exist in a production-correct form.
//
// --- One-time OTS key enforcement (implementation choice; the paper states
// the SECURITY REQUIREMENT that osk is used once, but specifies no
// mechanism) ---
// OneTimeOtsKeyGuard wraps a LinkableSecretKey and an atomic "consumed"
// flag. LRSign takes the guard by mutable reference and atomically marks it
// consumed before performing any signing; a second LRSign call against an
// already-consumed guard throws OneTimeKeyReuseError instead of signing.
// This enforces one-time use only within the lifetime of the in-memory
// guard object in the current process; it is NOT a substitute for proper
// OTS key lifecycle management (e.g. persisting "this osk has been used"
// across process restarts, or across multiple guard objects wrapping the
// same underlying osk bytes). That broader lifecycle problem is explicitly
// out of scope for Phase C.
//
// --- Carried-over limitation from Phase A/B ---
// ovk/osk are lattice_lrs::ots Dilithium5 (Round 3) keys, a documented
// stand-in for the "very high" parameter set of the original 2018
// CRYSTALS-Dilithium paper WCM cites; see dilithium_ots.hpp for the full
// rationale. H' in Phase B is a SHAKE256-XOF construction with rejection
// sampling, an implementation choice consistent with, but not dictated by,
// the paper's "random oracle into R_q^n" requirement.
//
// --- Security disclaimer ---
// Passing these unit tests establishes functional composition
// (encode/decode/accept/reject on the paths exercised), NOT that this
// construction is anonymous, unforgeable, or linkable in the sense of WCM's
// security definitions (Definitions 1-4 of the paper). No security proof is
// claimed here.

#include "lattice_lrs/lrs/public_key_mask.hpp"
#include "lattice_lrs/ots/dilithium_ots.hpp"
#include "lattice_lrs/proofs/protocol2_proof.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <atomic>
#include <cstddef>
#include <stdexcept>
#include <vector>

namespace lattice_lrs::lrs {

// sk = (\hat{sk}, osk, ovk)  (WCM Section 3.1 KeyGen).
struct LinkableSecretKey {
    ring_signature::SecretKey base_secret_key;  // \hat{sk}
    ots::DilithiumSecretKey ots_secret_key;     // osk
    ots::DilithiumPublicKey ots_public_key;     // ovk
};

// pk = p\hat{k} + H'(ovk) plus the secret material needed to sign with it.
// pk itself (linkable_public_key) is what the caller publishes/lists in a
// ring T; it is NOT secret.
struct LinkableKeyPair {
    sampling::PolynomialVector linkable_public_key;  // pk
    LinkableSecretKey secret_key;
};

// sigma = (\hat{sigma}, \tilde{sigma}, ovk)  (WCM Section 3.1 Sign output).
struct LinkableSignature {
    ring_signature::RSignSignature base_signature;  // \hat{sigma}
    ots::DilithiumSignature ots_signature;          // \tilde{sigma}
    ots::DilithiumPublicKey ots_public_key;         // ovk (linkability tag;
                                                     // consumed by Phase D's
                                                     // Link, not here)
};

class OneTimeKeyReuseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Enforces "osk is used at most once" (see file-level comment for the exact
// scope of this enforcement -- in-process, single guard object only).
class OneTimeOtsKeyGuard {
public:
    explicit OneTimeOtsKeyGuard(LinkableSecretKey secret_key)
        : secret_key_(std::move(secret_key)) {}

    OneTimeOtsKeyGuard(const OneTimeOtsKeyGuard&) = delete;
    OneTimeOtsKeyGuard& operator=(const OneTimeOtsKeyGuard&) = delete;

    const LinkableSecretKey& secret_key() const noexcept { return secret_key_; }
    bool is_consumed() const noexcept { return consumed_.load(); }

private:
    friend LinkableSignature LRSign(
        const ring_signature::PublicParameters&,
        const proofs::Protocol2Parameters&,
        const proofs::Protocol2PublicList&,
        std::size_t,
        OneTimeOtsKeyGuard&,
        const std::vector<std::uint8_t>&,
        const ring_signature::RSignTranscriptEncoder&,
        proofs::Protocol2RSignGaussianProvider&,
        proofs::Protocol2AuxiliaryCommitmentProvider&,
        ring_signature::RSignBatchRejectionProvider&,
        sampling::RandomSource&);
    friend LinkableSignature LRSignForTesting(
        const ring_signature::PublicParameters&,
        const proofs::Protocol2Parameters&,
        const proofs::Protocol2PublicList&,
        std::size_t,
        OneTimeOtsKeyGuard&,
        const std::vector<std::uint8_t>&,
        const ring_signature::RSignTranscriptEncoder&,
        proofs::Protocol2RSignGaussianProvider&,
        proofs::Protocol2AuxiliaryCommitmentProvider&,
        ring_signature::RSignBatchRejectionProvider&,
        sampling::RandomSource&);

    // Throws OneTimeKeyReuseError if already consumed; otherwise marks
    // consumed and returns the wrapped secret key. Thread-safe via
    // compare_exchange (concurrent callers racing on the same guard will
    // have exactly one succeed).
    const LinkableSecretKey& consume_for_signing();

    LinkableSecretKey secret_key_;
    std::atomic<bool> consumed_{false};
};

// LRKeygen(pp): composes RS.KeyGen + OTS.KeyGen + MaskPublicKey exactly as
// in WCM Section 3.1 KeyGen / Section 4. Mirrors the existing
// production-vs-TestOnly split already used throughout ring_signature.hpp
// (RKeygen rejects TestOnly PublicParameters; RKeygenForTesting requires
// them).
LinkableKeyPair LRKeygen(const ring_signature::PublicParameters& public_parameters,
                         sampling::RandomSource& random);
LinkableKeyPair LRKeygenForTesting(
    const ring_signature::PublicParameters& public_parameters,
    sampling::RandomSource& random);

// LRSign(..., signer_index, signer_key_guard, message, ...): composes the
// WCM Sign algorithm (Section 3.1 / Section 4) described above.
//   - ring is T = {pk_i}, exactly the published/listed linkable public keys
//     (NOT pre-transformed by the caller).
//   - signer_index identifies the signer's own entry in `ring` (see
//     file-level comment #2: required by the underlying RS.Sign interface,
//     not a separate WCM concept).
//   - signer_key_guard must wrap the signer's own LinkableSecretKey
//     (produced by LRKeygen) and must not have been consumed by a prior
//     LRSign/LRSignForTesting call; otherwise OneTimeKeyReuseError is
//     thrown and no signing is attempted.
//   - gaussian/auxiliary_commitment/rejection/random are forwarded
//     unmodified to RSign/RSignForTesting; see file-level comment #3.
// Throws std::invalid_argument for structurally invalid inputs (empty ring,
// out-of-range signer_index, parameter/dimension mismatches between
// public_parameters and the ring), OneTimeKeyReuseError on OTS key reuse,
// and propagates whatever RSign/RSignForTesting itself throws.
LinkableSignature LRSign(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    std::size_t signer_index,
    OneTimeOtsKeyGuard& signer_key_guard,
    const std::vector<std::uint8_t>& message,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    proofs::Protocol2RSignGaussianProvider& gaussian,
    proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    ring_signature::RSignBatchRejectionProvider& rejection,
    sampling::RandomSource& random);

LinkableSignature LRSignForTesting(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    std::size_t signer_index,
    OneTimeOtsKeyGuard& signer_key_guard,
    const std::vector<std::uint8_t>& message,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    proofs::Protocol2RSignGaussianProvider& gaussian,
    proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    ring_signature::RSignBatchRejectionProvider& rejection,
    sampling::RandomSource& random);

// LRVerify(..., ring, message, signature, ...): composes the WCM Vrfy
// algorithm (Section 3.1 / Section 4) described above. Returns false for
// any malformed, tampered, or inconsistent signature (wrong message, wrong
// ring, tampered base_signature, tampered ots_signature, tampered
// ots_public_key, or a ring/parameter shape mismatch encountered while
// reconstructing T\hat{}'). Throws only if public_parameters or
// proof_parameters themselves fail their own validate() -- i.e. only for
// caller-supplied setup that is invalid independent of the signature being
// checked, matching the existing RVerify convention.
bool LRVerify(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    const std::vector<std::uint8_t>& message,
    const LinkableSignature& signature,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

bool LRVerifyForTesting(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    const std::vector<std::uint8_t>& message,
    const LinkableSignature& signature,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

}  // namespace lattice_lrs::lrs
