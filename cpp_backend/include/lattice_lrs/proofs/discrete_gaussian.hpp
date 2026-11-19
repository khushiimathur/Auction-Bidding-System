#pragma once

#include "lattice_lrs/proofs/binary_proof.hpp"

namespace lattice_lrs::proofs {

// Exact D_sigma sampler using the existing Bernoulli-exponential provider.
// The referenced provider must outlive this object.
class ExactDiscreteGaussianProvider final : public DiscreteGaussianProvider {
public:
    explicit ExactDiscreteGaussianProvider(
        BernoulliExponentialProvider& exponential) noexcept;

    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                               const NTL::ZZ& sigma_squared_denominator,
                               sampling::RandomSource& random) override;

private:
    BernoulliExponentialProvider& exponential_;
};

}  // namespace lattice_lrs::proofs
