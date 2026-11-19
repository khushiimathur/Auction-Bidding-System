#include "lattice_lrs/proofs/discrete_gaussian.hpp"

#include "lattice_lrs/sampling/sampler.hpp"

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

// Samples K with P(K >= n) = exp(-n / rate_denominator) exactly for every
// integer n >= 0 -- i.e. a Geometric(1 - exp(-1/rate_denominator)) variate,
// written t = rate_denominator below.
//
// The ORIGINAL implementation flipped Bernoulli(exp(-1/t)) once per unit
// and counted successes until the first failure: an O(t) unary encoding
// of K, since K's own mean is O(t). That unary cost is the actual driver
// behind production-scale RSign hangs (t reaches several thousand at N64
// scale, and this function runs twice per sampled coefficient, for
// thousands of coefficients per repetition).
//
// An earlier attempt at this fix tried an exponential-search-then-
// binary-search scheme built on the geometric distribution's memoryless
// property. That scheme is WRONG: after a doubling probe of width w
// fails, the correct posterior for K is truncated to [established,
// established+w) and is no longer the plain memoryless conditional
// exp(-x/t) used by a further unconditional probe -- doing so ignores
// the truncation and introduces a measurable upward bias (confirmed
// empirically: ~59.6 vs a theoretical mean of ~49.5 at t=50, nowhere
// near explainable by sampling noise). It was discarded rather than
// shipped; see test_geometric_regression_against_prior_implementation in
// tests/test_discrete_gaussian.cpp, which pins the correct distribution
// down numerically so this mistake cannot silently return.
//
// The implementation below instead uses an EXACT decomposition that
// factors K as K = J*t + I, where:
//   - J ~ Geometric(1 - exp(-1)) -- note the FIXED rate exp(-1),
//     independent of t. This is provably exact: writing K's pmf
//     (1-e^{-1/t}) e^{-K/t} with K = J*t + I, 0<=I<t, and summing over I
//     shows P(J=j) = (1-e^{-1}) e^{-j} exactly (a geometric series
//     telescopes the t-dependence away). Because the rate is fixed, J
//     costs O(1) expected exact Bernoulli(exp(-1)) trials regardless of
//     t -- this reuses the ORIGINAL unary method, which is only
//     expensive when its rate depends on t; here it does not.
//   - I in {0,...,t-1}, independent of J, with pmf proportional to
//     e^{-I/t} (the same sum above gives P(I=i | J=j) = (1-e^{-1/t})/
//     (1-e^{-1}) * e^{-i/t}, independent of j). This is sampled by
//     textbook rejection sampling: propose I uniformly over {0,...,t-1}
//     (reuses sampling::sample_uniform_coefficient, itself exact
//     rejection sampling on random bits), and accept with probability
//     exp(-I/t) via one exact Bernoulli trial of magnitude < 1 (so the
//     existing ExactBernoulliExponentialProvider's series-convergence
//     cost for this trial is O(1), not O(t)). The expected number of
//     rejection rounds tends to 1/(1-e^{-1}) =~ 1.58 as t grows, i.e.
//     O(1), not O(t) and not O(log t).
// Multiplying the two pmfs above exactly reconstructs the target pmf of
// K, so this is exact, not an approximation, and uses only the two exact
// primitives already in this codebase (BernoulliExponentialProvider and
// sampling::sample_uniform_coefficient).
NTL::ZZ sample_geometric(const NTL::ZZ& rate_denominator,
                         sampling::RandomSource& random,
                         BernoulliExponentialProvider& exponential) {
    const NTL::ZZ minus_one(-1);
    const NTL::ZZ one(1);
    NTL::ZZ j(0);
    while (exponential.sample_exp(minus_one, one, random)) {
        ++j;
    }
    if (rate_denominator == 1) {
        return j;
    }
    for (;;) {
        const NTL::ZZ candidate =
            sampling::sample_uniform_coefficient(rate_denominator, random);
        if (candidate == 0 ||
            exponential.sample_exp(-candidate, rate_denominator, random)) {
            return j * rate_denominator + candidate;
        }
    }
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
