#include "lattice_lrs/proofs/discrete_gaussian.hpp"

#include <NTL/ZZ.h>

#include <stdexcept>

namespace lattice_lrs::proofs {
namespace {

NTL::ZZ proposal_rate_denominator(const NTL::ZZ& sigma_squared_numerator,
                                  const NTL::ZZ& sigma_squared_denominator) {
    if (sigma_squared_numerator <= sigma_squared_denominator) {
        return NTL::ZZ(1);
    }

    NTL::ZZ integer_part = sigma_squared_numerator / sigma_squared_denominator;
    NTL::ZZ rate_denominator;
    NTL::SqrRoot(rate_denominator, integer_part);
    if (rate_denominator * rate_denominator * sigma_squared_denominator <
        sigma_squared_numerator) {
        ++rate_denominator;
    }
    return rate_denominator;
}

NTL::ZZ sample_geometric(const NTL::ZZ& rate_denominator,
                         sampling::RandomSource& random,
                         BernoulliExponentialProvider& exponential) {
    const NTL::ZZ minus_one(-1);
    NTL::ZZ successes(0);
    while (exponential.sample_exp(minus_one, rate_denominator, random)) {
        ++successes;
    }
    return successes;
}

}  // namespace

ExactDiscreteGaussianProvider::ExactDiscreteGaussianProvider(
    BernoulliExponentialProvider& exponential) noexcept
    : exponential_(exponential) {}

NTL::ZZ ExactDiscreteGaussianProvider::sample_coefficient(
    const NTL::ZZ& sigma_squared_numerator,
    const NTL::ZZ& sigma_squared_denominator,
    sampling::RandomSource& random) {
    if (sigma_squared_numerator <= 0 || sigma_squared_denominator <= 0) {
        throw std::invalid_argument(
            "D_sigma parameter sigma_squared must be a positive rational");
    }

    const NTL::ZZ rate_denominator = proposal_rate_denominator(
        sigma_squared_numerator, sigma_squared_denominator);
    const NTL::ZZ acceptance_log_denominator =
        2 * sigma_squared_numerator * sigma_squared_denominator *
        rate_denominator * rate_denominator;

    for (;;) {
        const NTL::ZZ first = sample_geometric(rate_denominator, random, exponential_);
        const NTL::ZZ second = sample_geometric(rate_denominator, random, exponential_);
        const NTL::ZZ sample = first - second;
        const NTL::ZZ absolute_sample = sample < 0 ? -sample : sample;
        const NTL::ZZ scaled_difference =
            sigma_squared_denominator * rate_denominator * absolute_sample -
            sigma_squared_numerator;
        const NTL::ZZ acceptance_log_numerator =
            -(scaled_difference * scaled_difference);

        if (acceptance_log_numerator == 0) {
            return sample;
        }
        const NTL::ZZ common_divisor =
            NTL::GCD(-acceptance_log_numerator, acceptance_log_denominator);
        const NTL::ZZ reduced_log_numerator =
            acceptance_log_numerator / common_divisor;
        const NTL::ZZ reduced_log_denominator =
            acceptance_log_denominator / common_divisor;
        if (exponential_.sample_exp(reduced_log_numerator,
                                    reduced_log_denominator, random)) {
            return sample;
        }
    }
}

}  // namespace lattice_lrs::proofs
