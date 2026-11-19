#pragma once

// Shared demo-scale TestOnly commitment/Protocol2 parameters, used by
// BOTH lattice_lrs::auction::SealedBidAuction and the cryptographic
// playground (demo/playground_session.hpp) so the two demo surfaces
// never drift to different, inconsistently-reasoned-about dimensions.
//
// These are explicitly NOT validated against Esgin's Section 6.1
// security analysis (no Assumption 1 / Theorem 3 derivation was done
// for them, unlike the named ParameterProfile instances). They exist
// only so real signing/verification completes in well under a second
// for an interactive demo, instead of the multiple minutes a real
// ParameterProfile::N64() round trip takes (confirmed in
// tests/test_production_lrsign_integration.cpp). Every algorithm and
// provider run against these dimensions is the identical real
// implementation used at N64 -- only the dimensions are smaller.
//
// degree=64 keeps 2*degree a power of two (required by
// Shake256CToChallenges); k=3, beta=2 gives ring_size = beta^k = 8
// (kDemoRingSize); m*degree = 128 >= 86 satisfies Protocol 1's own
// minimum; q is a 41-bit prime comfortably satisfying
// BinaryProofParameters::validate's q-lower-bound check at these
// phi1/d/k values (empirically verified, not re-derived from
// Assumption 1's closed form).

#include "lattice_lrs/commitment/commitment.hpp"
#include "lattice_lrs/proofs/protocol2_proof.hpp"

#include <cstddef>

namespace lattice_lrs::demo {

// Ring size implied by DemoProtocol2Parameters()'s (k=3, beta=2):
// beta^k = 8. Restated as a named constant (not redefined -- the single
// canonical kDemoRingSize lives in lattice_lrs::auction, since
// SealedBidAuction::ring_size() already exposes it publicly) only in
// comments here; callers needing the ring size use
// lattice_lrs::auction::kDemoRingSize directly.

commitment::Parameters DemoCommitmentParameters();
proofs::Protocol2Parameters DemoProtocol2Parameters();

}  // namespace lattice_lrs::demo
