#pragma once

#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

namespace lattice_lrs::proofs {

// Samples a Bernoulli variable with probability exp(-pi*t), for rational t>=0.
class BernoulliPiExponentialProvider {
public:
    virtual ~BernoulliPiExponentialProvider() = default;
    virtual bool sample_exp_neg_pi_rational(
        const NTL::ZZ& t_numerator,
        const NTL::ZZ& t_denominator,
        sampling::RandomSource& random) = 0;
};

// Exact interval-refinement implementation, conditional on independent
// unbiased bits from RandomSource. Runtime is variable and unbounded.
class ExactBernoulliPiExponentialProvider final
    : public BernoulliPiExponentialProvider {
public:
    bool sample_exp_neg_pi_rational(
        const NTL::ZZ& t_numerator,
        const NTL::ZZ& t_denominator,
        sampling::RandomSource& random) override;
};

}  // namespace lattice_lrs::proofs
