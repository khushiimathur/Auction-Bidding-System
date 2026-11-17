#pragma once

#include "lattice_lrs/proofs/bernoulli_pi_exponential.hpp"

namespace lattice_lrs::proofs {

// Samples one integer coefficient from Esgin's D_s law, where the exact
// positive rational s_squared is s^2 and mass is proportional to
// exp(-pi*x^2/s_squared).
class DiscreteGaussianSProvider {
public:
    virtual ~DiscreteGaussianSProvider() = default;
    virtual NTL::ZZ sample_coefficient_from_scale_squared(
        const NTL::ZZ& s_squared_numerator,
        const NTL::ZZ& s_squared_denominator,
        sampling::RandomSource& random) = 0;
};

// Exact rejection sampler under the BernoulliPiExponentialProvider contract.
// The positive rational proposal center affects efficiency, not the target.
class ExactDiscreteGaussianSProvider final : public DiscreteGaussianSProvider {
public:
    ExactDiscreteGaussianSProvider(
        BernoulliPiExponentialProvider& exponential,
        const NTL::ZZ& proposal_center_numerator,
        const NTL::ZZ& proposal_center_denominator);

    NTL::ZZ sample_coefficient_from_scale_squared(
        const NTL::ZZ& s_squared_numerator,
        const NTL::ZZ& s_squared_denominator,
        sampling::RandomSource& random) override;

private:
    BernoulliPiExponentialProvider& exponential_;
    NTL::ZZ proposal_center_numerator_;
    NTL::ZZ proposal_center_denominator_;
};

}  // namespace lattice_lrs::proofs
