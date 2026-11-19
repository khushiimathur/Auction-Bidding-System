#pragma once

// Production WCM linkable-ring-signature integration layer.
//
// Connects the concrete production implementations of every LRSign/
// LRVerify/Link dependency into one object that can run a real Esgin et
// al. (2018/773) ring signature UNDER the Wang-Chen-Ma (ISC 2019)
// linkability wrapper -- no test doubles, no mocks. This mirrors
// ring_signature::ProductionRSignContext exactly, swapping RKeygen/RSign/
// RVerify for lrs::LRKeygen/LRSign/LRVerify (which are themselves pure
// composition over RKeygen/RSign/RVerify plus the Dilithium5 OTS wrapper
// and the H' public-key mask -- see linkable_ring_signature.hpp for the
// exact WCM equations implemented). This file reuses every piece
// unchanged:
//   - lrs::LRKeygen / LRSign / LRVerify / Link                  (unmodified)
//   - ring_signature::RSetup / ParameterProfile                 (unmodified)
//   - ring_signature::CanonicalRSignTranscriptEncoder            (unmodified)
//   - ring_signature::Shake256CToChallenges                      (unmodified)
//   - proofs::Shake256AuxiliaryCommitmentProvider                (unmodified)
//   - proofs::SigmaSection6GaussianProviderBundle         (the Phase E fix)
//   - ring_signature::Section6BatchRejectionProvider  (the corrected
//     Algorithm-1 global rejection)
//   - proofs::ExactBernoulliExponentialProvider                  (unmodified)
//   - ots::GenerateKeyPair / Sign / Verify (Dilithium5, Round 3)  (unmodified)
//   - lrs::MaskPublicKey / UnmaskPublicKey (H', SHAKE256-XOF)      (unmodified)
//
// No new cryptographic algorithm is introduced here; this is composition
// and lifetime management only.
//
// --- Status as of this file's introduction ---
// Both real blockers found while building ring_signature::
// ProductionRSignContext (ParameterProfile::T1_squared()'s squaring bug,
// and ExactDiscreteGaussianProvider's O(rate_denominator) geometric
// sampler) are fixed, and a real N64-scale RSign/RVerify round trip
// (including tampered-message/ring/signature rejection) has been
// confirmed to pass end-to-end
// (tests/test_production_rsign_integration.cpp). A third, independent
// blocker (protocol2_proof.cpp's verify_norms missing Section 6's
// r-repetition scaling, plus an unrelated (beta-1) exponent bug) was
// found the same way and is also fixed
// (tests/test_protocol2_proof.cpp's r-scaling regression tests). This
// file is the first attempt to run LRSign/LRVerify/Link on top of that
// now-working RSign/RVerify at real (non-TestOnly) parameters; see
// tests/test_production_lrsign_integration.cpp for the real end-to-end
// result, including whether it succeeded or hit a new blocker.
//
// --- Lifetime contract ---
// ProductionLRSignContext OWNS every provider LRSign/LRVerify/Link need
// by reference (transcript encoder, auxiliary commitment provider, the
// Gaussian provider bundle, the rejection provider and its exponential
// dependency) -- identical ownership pattern to
// ring_signature::ProductionRSignContext. As long as a
// ProductionLRSignContext is alive, every reference it hands out remains
// valid. Do not call Sign()/Verify()/Link() after the context has been
// destroyed.
//
// --- OTS one-time-key guard lifetime (WCM-specific; no analogue in
// ProductionRSignContext) ---
// Unlike the base ring signature, every linkable signing operation
// consumes a fresh, caller-owned lrs::OneTimeOtsKeyGuard (see
// linkable_ring_signature.hpp: it is move/copy-disabled and enforces
// "this osk signs at most once" via an atomic flag). This context does
// NOT own guards -- LinkableKeyPair (from GenerateKeyPair) contains the
// LinkableSecretKey the caller must wrap in their own
// lrs::OneTimeOtsKeyGuard before calling Sign(). This mirrors exactly how
// lrs::LRSign itself takes the guard by mutable reference; it is not an
// extra layer invented here.
//
// --- What "production" means here, precisely ---
// Create() only ever calls ring_signature::RSetup (never
// RSetupForTesting) and LRKeygen (never LRKeygenForTesting)/LRSign
// (never LRSignForTesting)/LRVerify (never LRVerifyForTesting), so every
// operation runs the non-test-only code path by construction. As with
// ProductionRSignContext, "production" describes the code path exercised
// (the real algorithms, a real named parameter profile, real OS
// randomness when the caller supplies sampling::SystemRandomSource) --
// it is NOT a claim that the resulting signatures are cryptographically
// secure. See linkable_ring_signature.hpp and link.hpp's own extensive
// "what this does NOT establish" sections, which apply unchanged here.

#include "lattice_lrs/lrs/link.hpp"
#include "lattice_lrs/lrs/linkable_ring_signature.hpp"
#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/production_gaussian_provider.hpp"
#include "lattice_lrs/proofs/shake256_auxiliary_commitment.hpp"
#include "lattice_lrs/ring_signature/canonical_rsign_transcript.hpp"
#include "lattice_lrs/ring_signature/parameter_profile.hpp"
#include "lattice_lrs/ring_signature/production_rejection_provider.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"

namespace lattice_lrs::lrs {

class ProductionLRSignContext final {
public:
    // Builds a context for `profile` via ring_signature::RSetup (never
    // RSetupForTesting). Throws std::invalid_argument if `profile` fails
    // its own validate(), or (defensively, mirroring
    // ProductionRSignContext) if the resulting PublicParameters are
    // somehow test-only.
    static ProductionLRSignContext Create(
        const ring_signature::ParameterProfile& profile,
        sampling::RandomSource& random);

    ProductionLRSignContext(const ProductionLRSignContext&) = delete;
    ProductionLRSignContext& operator=(const ProductionLRSignContext&) = delete;
    ProductionLRSignContext(ProductionLRSignContext&&) = delete;
    ProductionLRSignContext& operator=(ProductionLRSignContext&&) = delete;

    const ring_signature::PublicParameters& public_parameters() const noexcept {
        return public_parameters_;
    }
    const proofs::Protocol2Parameters& proof_parameters() const noexcept {
        return proof_parameters_;
    }
    std::size_t expected_ring_size() const;

    // lrs::LRKeygen(public_parameters(), random): generates a fresh base
    // Esgin key pair AND a fresh Dilithium5 OTS key pair, and returns
    // pk = p\hat{k} + H'(ovk) (WCM Section 4) as LinkableKeyPair. The
    // caller publishes/lists linkable_public_key in the ring, and must
    // wrap secret_key in a fresh lrs::OneTimeOtsKeyGuard before calling
    // Sign() (see the file-level comment on OTS guard lifetime above).
    LinkableKeyPair GenerateKeyPair(sampling::RandomSource& random) const;

    // lrs::LRSign with every production provider this context owns.
    // `signer_key_guard` must wrap the signer's own LinkableSecretKey and
    // must not have been consumed by a prior Sign() call (on this
    // context or any other); otherwise OneTimeKeyReuseError is thrown.
    LinkableSignature Sign(const proofs::Protocol2PublicList& ring,
                          std::size_t signer_index,
                          OneTimeOtsKeyGuard& signer_key_guard,
                          const std::vector<std::uint8_t>& message,
                          sampling::RandomSource& random);

    // lrs::LRVerify with this context's production providers. Returns
    // false (never throws, beyond public_parameters/proof_parameters'
    // own validate()) for any malformed/tampered/inconsistent signature.
    bool Verify(const proofs::Protocol2PublicList& ring,
               const std::vector<std::uint8_t>& message,
               const LinkableSignature& signature) const;

    // lrs::Link with this context's production providers (shared by both
    // LRVerify calls Link performs internally). Per WCM Section 3.1: runs
    // LRVerify on both (ring1, message1, signature1) and (ring2, message2,
    // signature2); if either rejects, returns LinkOutcome::Rejected
    // without comparing anything else. Only if BOTH verify does it
    // compare the two signatures' OTS public keys (ovk) and return
    // Linked or Unlinked. See link.hpp's extensive documentation of
    // exactly what a Linked/Unlinked verdict does and does not mean
    // (WCM's "one-time linkability": bound to a signer's OTS key pair
    // only, not to any ring, message, or application-level context such
    // as an auction).
    LinkOutcome Link(const proofs::Protocol2PublicList& ring1,
                     const std::vector<std::uint8_t>& message1,
                     const LinkableSignature& signature1,
                     const proofs::Protocol2PublicList& ring2,
                     const std::vector<std::uint8_t>& message2,
                     const LinkableSignature& signature2) const;

private:
    ProductionLRSignContext(ring_signature::ParameterProfile profile,
                           ring_signature::PublicParameters public_parameters);

    ring_signature::ParameterProfile profile_;
    ring_signature::PublicParameters public_parameters_;
    proofs::Protocol2Parameters proof_parameters_;
    ring_signature::CanonicalRSignTranscriptEncoder transcript_encoder_;
    proofs::Shake256AuxiliaryCommitmentProvider auxiliary_commitment_;
    proofs::ExactBernoulliExponentialProvider rejection_exponential_;
    ring_signature::Section6BatchRejectionProvider rejection_;
    proofs::SigmaSection6GaussianProviderBundle gaussian_bundle_;
};

}  // namespace lattice_lrs::lrs

// --- Unresolved cryptographic assumptions that remain even on a
// successful Sign()/Verify()/Link() round trip (restated here
// deliberately, matching production_rsign.hpp's own practice) ---
// 1. Everything inherited from ProductionRSignContext still applies:
//    Shake256AuxiliaryCommitmentProvider is explicitly documented as
//    experimental ("hiding/binding [as] conditional assumptions, not a
//    paper security proof"); a successful round trip establishes
//    internal self-consistency of this specific pipeline, not a security
//    proof of anonymity, unforgeability, or post-quantum security.
// 2. WCM-specific additions: ovk/osk are lattice_lrs::ots Dilithium5
//    (Round 3) keys, a documented stand-in for the "very high" parameter
//    set of the original 2018 CRYSTALS-Dilithium paper WCM cites (see
//    dilithium_ots.hpp). H' is a SHAKE256-XOF-with-rejection-sampling
//    construction, an implementation choice the paper's "random oracle
//    into R_q^n" requirement does not itself dictate.
// 3. lrs::OneTimeOtsKeyGuard enforces "osk signs at most once" only
//    within the lifetime of a single guard object in one process; it is
//    not a substitute for cross-process/cross-restart OTS key lifecycle
//    management. This context does not change or strengthen that.
// 4. lrs::Link provides only WCM's "one-time linkability" (its own
//    Section 6 Discussion, reproduced in link.hpp): a Linked verdict
//    means "same OTS key pair", nothing about shared ring, message, or
//    any higher-level application context. Any application (e.g. an
//    auction) that wants to detect reuse across more than a single pair
//    of signatures must call Link repeatedly itself and keep its own
//    external record -- this context does not do so, by design (see
//    link.hpp).