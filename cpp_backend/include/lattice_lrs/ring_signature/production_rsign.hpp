#pragma once

// Production RSign integration layer.
//
// Connects, for the first time in this repository, the concrete production
// implementations of every RSign dependency into one object that can run a
// real Esgin et al. (2018/773) ring signature signing/verification
// operation -- no test doubles, no mocks. This file reuses every piece
// unchanged:
//   - ring_signature::RSetup / RKeygen / RSign / RVerify       (unmodified)
//   - ring_signature::ParameterProfile                          (unmodified)
//   - ring_signature::CanonicalRSignTranscriptEncoder            (unmodified)
//   - ring_signature::Shake256CToChallenges                      (unmodified)
//   - proofs::Shake256AuxiliaryCommitmentProvider                (unmodified)
//   - proofs::SigmaSection6GaussianProviderBundle          (this phase's fix)
//   - ring_signature::Section6BatchRejectionProvider   (the reviewed/corrected
//     Algorithm-1 global rejection)
//   - proofs::ExactBernoulliExponentialProvider                  (unmodified)
//
// No new cryptographic algorithm is introduced here; this is composition
// and lifetime management only.
//
// --- Lifetime contract ---
// ProductionRSignContext OWNS every provider RSign/RVerify need by
// reference (transcript encoder, auxiliary commitment provider, the
// Gaussian provider bundle, the rejection provider and its exponential
// dependency). As long as a ProductionRSignContext object is alive, every
// reference RSign/RVerify take from it remains valid. Do not call Sign()/
// Verify() after the context has been destroyed, and do not take raw
// references out of it that outlive it.
//
// --- What "production" means here, precisely ---
// Create() only ever calls ring_signature::RSetup (never RSetupForTesting),
// so the resulting PublicParameters are guaranteed non-test-only by
// construction; this is checked defensively anyway. "Production" describes
// the code path exercised (the real algorithms, real parameter profile,
// real OS randomness when the caller supplies sampling::SystemRandomSource)
// -- it is NOT a claim that the resulting signatures are
// cryptographically secure. See the end of this file for the specific
// unresolved assumptions that remain even when this integration runs
// successfully.

#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/production_gaussian_provider.hpp"
#include "lattice_lrs/proofs/shake256_auxiliary_commitment.hpp"
#include "lattice_lrs/ring_signature/canonical_rsign_transcript.hpp"
#include "lattice_lrs/ring_signature/parameter_profile.hpp"
#include "lattice_lrs/ring_signature/production_rejection_provider.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include <memory>

namespace lattice_lrs::ring_signature {

class ProductionRSignContext final {
public:
    // Builds a context for `profile` via ring_signature::RSetup (never
    // RSetupForTesting). Throws std::invalid_argument if `profile` fails
    // its own validate(), or (defensively -- this should be unreachable,
    // since RSetup only ever produces non-test-only PublicParameters) if
    // the resulting PublicParameters are somehow test-only.
    static ProductionRSignContext Create(const ParameterProfile& profile,
                                         sampling::RandomSource& random);

    ProductionRSignContext(const ProductionRSignContext&) = delete;
    ProductionRSignContext& operator=(const ProductionRSignContext&) = delete;
    ProductionRSignContext(ProductionRSignContext&&) = delete;
    ProductionRSignContext& operator=(ProductionRSignContext&&) = delete;

    const PublicParameters& public_parameters() const noexcept {
        return public_parameters_;
    }
    const proofs::Protocol2Parameters& proof_parameters() const noexcept {
        return proof_parameters_;
    }
    // The expected ring size (beta^k) for this profile; Sign/Verify below
    // rely on RSign/RVerify's own internal check of this against the
    // supplied ring, rather than duplicating that validation here.
    std::size_t expected_ring_size() const;

    // ring_signature::RKeygen(public_parameters(), random). Thin
    // passthrough, kept here only so callers that already hold a context
    // do not need a second reference to public_parameters().
    KeyPair GenerateKeyPair(sampling::RandomSource& random) const;

    // ring_signature::RSign with every production provider this context
    // owns. Throws std::invalid_argument if `ring` does not have exactly
    // expected_ring_size() entries or `witness.index` is out of range
    // (RSign's own check; not duplicated here), and propagates whatever
    // the Gaussian/rejection providers or `random` throw.
    RSignSignature Sign(const proofs::Protocol2PublicList& ring,
                       const proofs::Protocol2Witness& witness,
                       const std::vector<std::uint8_t>& message,
                       sampling::RandomSource& random);

    // ring_signature::RVerify with this context's production providers.
    // Returns false (never throws) for any malformed/tampered signature,
    // ring, or message, matching RVerify's own contract.
    bool Verify(const proofs::Protocol2PublicList& ring,
               const std::vector<std::uint8_t>& message,
               const RSignSignature& signature) const;

private:
    ProductionRSignContext(ParameterProfile profile,
                          PublicParameters public_parameters);

    ParameterProfile profile_;
    PublicParameters public_parameters_;
    proofs::Protocol2Parameters proof_parameters_;
    CanonicalRSignTranscriptEncoder transcript_encoder_;
    proofs::Shake256AuxiliaryCommitmentProvider auxiliary_commitment_;
    proofs::ExactBernoulliExponentialProvider rejection_exponential_;
    Section6BatchRejectionProvider rejection_;
    proofs::SigmaSection6GaussianProviderBundle gaussian_bundle_;
};

}  // namespace lattice_lrs::ring_signature

// --- Status (updated after real end-to-end validation) ---
// A real N64-scale RSign -> RVerify round trip, including rejection of a
// tampered message, a tampered ring, and a tampered signature, has been
// confirmed to pass (tests/test_production_rsign_integration.cpp). Three
// real, independently-confirmed blockers were found and fixed to get
// here, each only reachable once the previous one was resolved:
//   1. ParameterProfile::T1_squared() carried the paper's Theorem 1/
//      Section 6 (2d+2) scale factor unsquared. Fixed; see
//      parameter_profile.cpp's T1_squared() derivation comment and
//      tests/test_parameter_profile.cpp's regression test.
//   2. ExactDiscreteGaussianProvider's geometric proposal sampler
//      (discrete_gaussian.cpp) used an O(rate_denominator) unary-
//      counting algorithm, making real N64-scale signing take hours.
//      Replaced with an exact, O(1)-amortized J*t+I decomposition; see
//      discrete_gaussian.cpp's sample_geometric derivation comment and
//      tests/test_discrete_gaussian.cpp's regression/benchmark coverage.
//   3. protocol2_proof.cpp's verify_norms checked each repetition
//      against Theorem 2's original (non-repeated) Protocol 2 bounds,
//      not Section 6's r-scaled per-run bounds -- plus an independent,
//      unrelated (beta-1) exponent bug. Fixed; see verify_norms'
//      derivation comment and tests/test_protocol2_proof.cpp's r-scaling
//      regression tests.
// Remaining, NOT resolved by any of the above:
// 1. Shake256AuxiliaryCommitmentProvider is explicitly documented (in its
//    own header) as an experimental aCom construction with
//    "hiding/binding [as] conditional assumptions, not a paper security
//    proof" -- unchanged by this integration.
// 2. A successful Sign()/Verify() round trip establishes that this
//    specific pipeline is internally self-consistent (the prover's
//    output satisfies the verifier's checks); it does not establish
//    anonymity, unforgeability, or post-quantum security in the sense of
//    the paper's own theorems.
