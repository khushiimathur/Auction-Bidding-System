#pragma once

#include "lattice_lrs/proofs/binary_proof.hpp"

namespace lattice_lrs::proofs {

// Exact Bernoulli(exp(r)) implementation for strictly negative rational r.
// The caller retains Algorithm 1's deterministic accept branch for r >= 0.
// Randomness is supplied by the existing RandomSource abstraction.
class ExactBernoulliExponentialProvider final
    : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ& log_numerator,
                    const NTL::ZZ& log_denominator,
                    sampling::RandomSource& random) override;
};

}  // namespace lattice_lrs::proofs
