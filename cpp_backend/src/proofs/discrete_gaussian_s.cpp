#include "lattice_lrs/proofs/discrete_gaussian_s.hpp"

#include <stdexcept>

namespace lattice_lrs::proofs {
namespace {

NTL::ZZ sample_geometric(const NTL::ZZ& rate_numerator,
                         const NTL::ZZ& rate_denominator,
                         sampling::RandomSource& random,
                         BernoulliPiExponentialProvider& exponential) {
    NTL::ZZ successes(0);
    while (exponential.sample_exp_neg_pi_rational(
        rate_numerator, rate_denominator, random)) {
        ++successes;
    }
    return successes;
}

NTL::ZZ absolute_value(const NTL::ZZ& value) {
    return value < 0 ? -value : value;
}

}  // namespace

ExactDiscreteGaussianSProvider::ExactDiscreteGaussianSProvider(
    BernoulliPiExponentialProvider& exponential,
    const NTL::ZZ& proposal_center_numerator,
    const NTL::ZZ& proposal_center_denominator)
    : exponential_(exponential),
      proposal_center_numerator_(proposal_center_numerator),
      proposal_center_denominator_(proposal_center_denominator) {
    if (proposal_center_numerator_ <= 0 ||
        proposal_center_denominator_ <= 0) {
        throw std::invalid_argument(
            "D_s proposal center must be a positive rational");
    }
}

NTL::ZZ ExactDiscreteGaussianSProvider::sample_coefficient_from_scale_squared(
    const NTL::ZZ& s_squared_numerator,
    const NTL::ZZ& s_squared_denominator,
    sampling::RandomSource& random) {
    if (s_squared_numerator <= 0 || s_squared_denominator <= 0) {
        throw std::invalid_argument(
            "D_s scale squared must be a positive rational");
    }

    // lambda = exp(-pi * 2*a/S), represented as a nonnegative rational
    // coefficient of pi.
    const NTL::ZZ proposal_rate_numerator =
        2 * proposal_center_numerator_ * s_squared_denominator;
    const NTL::ZZ proposal_rate_denominator =
        proposal_center_denominator_ * s_squared_numerator;

    for (;;) {
        const NTL::ZZ first = sample_geometric(
            proposal_rate_numerator, proposal_rate_denominator,
            random, exponential_);
        const NTL::ZZ second = sample_geometric(
            proposal_rate_numerator, proposal_rate_denominator,
            random, exponential_);
        const NTL::ZZ sample = first - second;

        const NTL::ZZ centered =
            absolute_value(sample) * proposal_center_denominator_ -
            proposal_center_numerator_;
        const NTL::ZZ acceptance_numerator =
            centered * centered * s_squared_denominator;
        if (acceptance_numerator == 0) return sample;

        const NTL::ZZ acceptance_denominator =
            proposal_center_denominator_ * proposal_center_denominator_ *
            s_squared_numerator;
        if (exponential_.sample_exp_neg_pi_rational(
                acceptance_numerator, acceptance_denominator, random)) {
            return sample;
        }
    }
}

}  // namespace lattice_lrs::proofs
