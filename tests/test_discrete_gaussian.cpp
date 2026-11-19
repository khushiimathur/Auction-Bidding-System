#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/discrete_gaussian.hpp"
#include "lattice_lrs/sampling/random_source.hpp"
#include "lattice_lrs/sampling/sampler.hpp"

#include <NTL/ZZ.h>

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::proofs::BernoulliExponentialProvider;
using lattice_lrs::proofs::ExactBernoulliExponentialProvider;
using lattice_lrs::proofs::ExactDiscreteGaussianProvider;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ zz(long value) { return NTL::to_ZZ(value); }

struct BernoulliCall {
    NTL::ZZ numerator;
    NTL::ZZ denominator;
};

class ScriptedExponential final : public BernoulliExponentialProvider {
public:
    explicit ScriptedExponential(std::vector<bool> outcomes)
        : outcomes_(std::move(outcomes)) {}

    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        require(numerator < 0 && denominator > 0,
                "Gaussian sampler must pass a negative rational log");
        calls_.push_back({numerator, denominator});
        if (next_ == outcomes_.size()) {
            throw std::runtime_error("scripted exponential outcomes exhausted");
        }
        return outcomes_[next_++];
    }

    const std::vector<BernoulliCall>& calls() const noexcept { return calls_; }

private:
    std::vector<bool> outcomes_;
    std::size_t next_ = 0;
    std::vector<BernoulliCall> calls_;
};

// Returns fixed, scripted byte strings on successive fill_bytes calls, so
// a test can pin down exactly which uniform candidate
// sampling::sample_uniform_coefficient will draw.
class ScriptedRandomSource final : public RandomSource {
public:
    explicit ScriptedRandomSource(std::vector<std::vector<std::uint8_t>> byte_strings)
        : byte_strings_(std::move(byte_strings)) {}

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        if (next_ == byte_strings_.size()) {
            throw std::runtime_error("scripted random-source byte strings exhausted");
        }
        const std::vector<std::uint8_t>& bytes = byte_strings_[next_++];
        require(bytes.size() == length,
                "scripted byte string length does not match requested length");
        for (std::size_t i = 0; i < length; ++i) output[i] = bytes[i];
    }

private:
    std::vector<std::vector<std::uint8_t>> byte_strings_;
    std::size_t next_ = 0;
};

// Counts calls made through it while forwarding to a real provider, so
// tests can assert on how many exact Bernoulli-exponential trials a
// sample actually consumed -- the direct observable for the O(1)
// (amortized, independent of t) performance claim.
class CountingExponential final : public BernoulliExponentialProvider {
public:
    explicit CountingExponential(BernoulliExponentialProvider& inner)
        : inner_(inner) {}

    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource& random) override {
        ++call_count;
        return inner_.sample_exp(numerator, denominator, random);
    }

    std::size_t call_count = 0;

private:
    BernoulliExponentialProvider& inner_;
};

class ZeroRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override { ++calls; }
    std::size_t calls = 0;
};

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        ++calls;
        throw std::runtime_error("injected random source failure");
    }
    std::size_t calls = 0;
};

void require_call(const ScriptedExponential& exponential, std::size_t index,
                  long numerator, long denominator) {
    require(index < exponential.calls().size(), "missing exponential-provider call");
    require(exponential.calls()[index].numerator == zz(numerator) &&
                exponential.calls()[index].denominator == zz(denominator),
            "exponential-provider call had an unexpected rational log");
}

template <typename Operation>
void require_invalid_argument(Operation&& operation, const std::string& message) {
    bool threw = false;
    try {
        operation();
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, message);
}

// Test-local copy of the geometric proposal sampler currently shipped in
// discrete_gaussian.cpp: K = J*t + I, where J ~ Geometric(1-exp(-1)) (a
// FIXED rate, independent of t) and I in {0,...,t-1} is drawn by
// rejection sampling (uniform proposal, acceptance probability
// exp(-I/t)). See discrete_gaussian.cpp's sample_geometric for the exact
// derivation showing this reconstructs the target pmf
// (1-exp(-1/t))*exp(-K/t). Kept here, independent of the production
// source, so the tests below can drive the exact same algorithm
// directly without reaching into discrete_gaussian.cpp's anonymous
// namespace.
NTL::ZZ fast_sample_geometric(const NTL::ZZ& rate_denominator,
                              RandomSource& random,
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
            lattice_lrs::sampling::sample_uniform_coefficient(rate_denominator, random);
        if (candidate == 0 ||
            exponential.sample_exp(-candidate, rate_denominator, random)) {
            return j * rate_denominator + candidate;
        }
    }
}

// Test-local copy of the PRIOR production implementation (one Bernoulli
// trial per unit, O(rate_denominator) expected trials), kept only as a
// fixed reference point for the regression test below -- it is not used
// anywhere in production code.
NTL::ZZ reference_unary_sample_geometric(const NTL::ZZ& rate_denominator,
                                         RandomSource& random,
                                         BernoulliExponentialProvider& exponential) {
    const NTL::ZZ minus_one(-1);
    NTL::ZZ successes(0);
    while (exponential.sample_exp(minus_one, rate_denominator, random)) {
        ++successes;
    }
    return successes;
}

void test_parameter_validation() {
    ScriptedExponential exponential({});
    ExactDiscreteGaussianProvider sampler(exponential);
    ZeroRandomSource random;

    require_invalid_argument([&] { (void)sampler.sample_coefficient(zz(0), zz(1), random); },
                             "zero sigma_squared numerator must be rejected");
    require_invalid_argument([&] { (void)sampler.sample_coefficient(zz(-1), zz(1), random); },
                             "negative sigma_squared numerator must be rejected");
    require_invalid_argument([&] { (void)sampler.sample_coefficient(zz(1), zz(0), random); },
                             "zero sigma_squared denominator must be rejected");
    require_invalid_argument([&] { (void)sampler.sample_coefficient(zz(1), zz(-1), random); },
                             "negative sigma_squared denominator must be rejected");
    require(exponential.calls().empty() && random.calls == 0,
            "invalid parameters must fail before consuming randomness");
}

// At sigma_squared = (1,1), proposal_rate_denominator returns t=1, which
// collapses the geometric proposal to its fixed-rate J-only case (no
// uniform-coefficient draw needed) -- identical, call for call, to the
// prior production algorithm. These scripted sequences therefore pin
// down the same deterministic behavior the original implementation had.
void test_deterministic_acceptance_and_signs() {
    ZeroRandomSource random;
    {
        ScriptedExponential exponential({true, false, false});
        ExactDiscreteGaussianProvider sampler(exponential);
        require(sampler.sample_coefficient(zz(1), zz(1), random) == zz(1),
                "zero acceptance log must accept deterministically");
        require(exponential.calls().size() == 3,
                "zero acceptance log must not call the exponential provider again");
        for (std::size_t i = 0; i < 3; ++i) {
            require_call(exponential, i, -1, 1);
        }
    }
    {
        ScriptedExponential exponential({false, true, false});
        ExactDiscreteGaussianProvider sampler(exponential);
        require(sampler.sample_coefficient(zz(1), zz(1), random) == zz(-1),
                "difference of geometric draws must preserve negative outputs");
        require(exponential.calls().size() == 3,
                "unit acceptance probability must be deterministic");
    }
}

void test_rejection_retry_and_exact_rational_logs() {
    ZeroRandomSource random;
    ScriptedExponential exponential({false, false, false, true, false, false});
    ExactDiscreteGaussianProvider sampler(exponential);
    require(sampler.sample_coefficient(zz(1), zz(1), random) == zz(1),
            "rejected proposal must restart and return the next accepted value");
    require(exponential.calls().size() == 6,
            "rejection must consume one acceptance coin before restarting");
    require_call(exponential, 0, -1, 1);
    require_call(exponential, 1, -1, 1);
    require_call(exponential, 2, -1, 2);
    require_call(exponential, 3, -1, 1);
    require_call(exponential, 4, -1, 1);
    require_call(exponential, 5, -1, 1);

    // sigma_squared=(3,1) gives rate_denominator=2 (not 1), so this
    // exercises the full J*t+I decomposition rather than the pure J-only
    // shortcut: both geometric draws land on I=0 via ZeroRandomSource's
    // always-zero uniform candidate, so only the J-loop portion of each
    // draw consumes scripted outcomes. Hand-traced: attempt 1 draws
    // first=0 (call0=false), second=0 (call1=false), then the
    // acceptance coin (call2) rejects; attempt 2 draws first=2
    // (call3=true,call4=false => J=1, value=J*2+0=2), second=0
    // (call5=false), and the acceptance coin (call6) accepts, yielding
    // first-second = 2.
    ScriptedExponential reduced_log_retry({false, false, false, true, false,
                                           false, true});
    ExactDiscreteGaussianProvider reduced_log_sampler(reduced_log_retry);
    require(reduced_log_sampler.sample_coefficient(zz(3), zz(1), random) == zz(2),
            "rejection after reducing an acceptance log must preserve later logs");
    require(reduced_log_retry.calls().size() == 7,
            "reduced-log retry must consume both proposals and decisions");
    require_call(reduced_log_retry, 2, -3, 8);
    require_call(reduced_log_retry, 6, -1, 24);

    ScriptedExponential fractional_exponential({false, false, true});
    ExactDiscreteGaussianProvider fractional_sampler(fractional_exponential);
    require(fractional_sampler.sample_coefficient(zz(1), zz(4), random) == zz(0),
            "small positive rational sigma_squared must be supported");
    require_call(fractional_exponential, 0, -1, 1);
    require_call(fractional_exponential, 1, -1, 1);
    require_call(fractional_exponential, 2, -1, 8);
}

// Direct, hand-traced unit test of the J*t+I geometric proposal itself
// (not routed through sample_coefficient), at t=5, covering: a candidate
// that lands on I=0 (short-circuits the acceptance coin entirely), one
// rejected uniform candidate before an accepted one, and a nonzero J.
void test_geometric_proposal_correctness_scripted() {
    {
        // J-loop: single failure => J=0. Uniform candidate byte 0x00 =>
        // I=0, which short-circuits straight to acceptance (no
        // exponential call for the I-stage).
        ScriptedExponential exponential({false});
        ScriptedRandomSource random({{0x00}});
        require(fast_sample_geometric(zz(5), random, exponential) == zz(0),
                "I=0 must be returned without consuming an acceptance coin");
        require(exponential.calls().size() == 1,
                "I=0 case must cost exactly one exact Bernoulli trial (the J-loop)");
    }
    {
        // J-loop: single failure => J=0. First uniform candidate byte
        // 0x07 = 7 >= 5 is rejected by sample_uniform_coefficient itself
        // (consuming a second fill_bytes call) before a valid candidate
        // 0x03 = 3 is drawn and accepted.
        ScriptedExponential exponential({false, true});
        ScriptedRandomSource random({{0x07}, {0x03}});
        require(fast_sample_geometric(zz(5), random, exponential) == zz(3),
                "a rejected uniform candidate must not affect the final value");
        require(exponential.calls().size() == 2,
                "J-loop (1 call) plus one acceptance decision on the valid "
                "candidate (1 call) must total two trials");
        require_call(exponential, 0, -1, 1);
        require_call(exponential, 1, -3, 5);
    }
    {
        // J-loop succeeds twice then fails => J=2. Candidate byte 0x01 =
        // 1, accepted. Result = J*t + I = 2*5 + 1 = 11.
        ScriptedExponential exponential({true, true, false, true});
        ScriptedRandomSource random({{0x01}});
        require(fast_sample_geometric(zz(5), random, exponential) == zz(11),
                "nonzero J must scale correctly into K = J*t + I");
        require(exponential.calls().size() == 4,
                "J=2 (3 calls: true,true,false) plus one acceptance decision "
                "must total four trials");
    }
}

void test_large_variance_no_overflow_and_terminates() {
    ExactBernoulliExponentialProvider exponential;
    ExactDiscreteGaussianProvider sampler(exponential);
    lattice_lrs::sampling::SystemRandomSource random;

    NTL::ZZ huge_variance;
    NTL::power(huge_variance, zz(10), 80);
    const NTL::ZZ result = sampler.sample_coefficient(huge_variance, zz(1), random);
    // No specific value is asserted (this now goes through real
    // randomness and the J*t+I decomposition rather than a scripted
    // provider) -- the point of this test is simply that an
    // astronomically large exact sigma_squared does not overflow, throw,
    // or hang, which it would have under the old O(rate_denominator)
    // unary algorithm's unary loop at rate_denominator ~ 10^40.
    require(result > -huge_variance && result < huge_variance,
            "large exact sigma_squared must produce a value within a sane range");
}

void test_random_source_failure_propagates() {
    ExactBernoulliExponentialProvider exponential;
    ExactDiscreteGaussianProvider sampler(exponential);
    FailingRandomSource random;
    bool propagated = false;
    try {
        (void)sampler.sample_coefficient(zz(1), zz(1), random);
    } catch (const std::runtime_error&) {
        propagated = true;
    }
    require(propagated && random.calls == 1,
            "random-source failure must propagate without a fallback sample");
}

// Direct randomness-consumption / termination test: at a rate_denominator
// of 10,000, the old unary algorithm needed ~10,000 expected exact
// Bernoulli trials per geometric draw (two draws per sample_coefficient
// call). The J*t+I decomposition's expected trial count is O(1),
// independent of rate_denominator -- this is the concrete, executable
// form of that claim, using real randomness rather than a scripted
// provider.
void test_termination_cost_is_independent_of_rate() {
    ExactBernoulliExponentialProvider real_exponential;
    CountingExponential counting(real_exponential);
    ExactDiscreteGaussianProvider sampler(counting);
    lattice_lrs::sampling::SystemRandomSource random;

    const NTL::ZZ sigma_squared = zz(100000000);  // rate_denominator = 10000
    constexpr std::size_t sample_count = 50;
    for (std::size_t i = 0; i < sample_count; ++i) {
        (void)sampler.sample_coefficient(sigma_squared, zz(1), random);
    }
    const double average_calls_per_sample =
        static_cast<double>(counting.call_count) / sample_count;
    require(average_calls_per_sample < 50.0,
            "average exact Bernoulli trials per sample must stay a small "
            "constant independent of rate_denominator (expected O(1), "
            "nowhere near the ~10000 the old unary algorithm would need)");
}

void test_statistical_distribution_diagnostic() {
    ExactBernoulliExponentialProvider exponential;
    ExactDiscreteGaussianProvider sampler(exponential);
    lattice_lrs::sampling::SystemRandomSource random;
    constexpr std::size_t sample_count = 2048;
    long double observed_sum = 0;
    long double observed_square_sum = 0;
    std::size_t observed_tail = 0;

    for (std::size_t i = 0; i < sample_count; ++i) {
        const long value = NTL::to_long(sampler.sample_coefficient(zz(1), zz(1), random));
        observed_sum += value;
        observed_square_sum += static_cast<long double>(value) * value;
        observed_tail += std::abs(value) >= 2 ? 1U : 0U;
    }

    long double normalizer = 0;
    long double expected_square_sum = 0;
    long double expected_tail_weight = 0;
    for (long value = -12; value <= 12; ++value) {
        const long double weight = std::exp(-static_cast<long double>(value * value) / 2);
        normalizer += weight;
        expected_square_sum += static_cast<long double>(value * value) * weight;
        if (std::abs(value) >= 2) expected_tail_weight += weight;
    }

    const long double observed_mean = observed_sum / sample_count;
    const long double observed_second_moment = observed_square_sum / sample_count;
    const long double observed_tail_probability =
        static_cast<long double>(observed_tail) / sample_count;
    const long double expected_second_moment = expected_square_sum / normalizer;
    const long double expected_tail_probability = expected_tail_weight / normalizer;

    require(std::abs(observed_mean) < 0.14L,
            "diagnostic sample mean is outside its broad symmetry band");
    require(std::abs(observed_second_moment - expected_second_moment) < 0.18L,
            "diagnostic second moment is outside its broad reference band");
    require(std::abs(observed_tail_probability - expected_tail_probability) < 0.04L,
            "diagnostic tail frequency is outside its broad reference band");
}

// Same diagnostic shape as above, but at production-relevant scale
// (sigma^2 = 77,316,096, matching N64's response_mask stage). This both
// confirms the target distribution is unchanged at large sigma and
// serves as a wall-clock regression guard: with the old O(sigma)
// geometric sampler this sample count would take on the order of tens of
// minutes to hours (as observed directly against the real RSign
// integration); with the corrected O(1)-amortized sampler it completes
// in well under a second.
void test_statistical_distribution_production_scale() {
    ExactBernoulliExponentialProvider exponential;
    ExactDiscreteGaussianProvider sampler(exponential);
    lattice_lrs::sampling::SystemRandomSource random;

    const NTL::ZZ sigma_squared = zz(77316096);
    const long double sigma = std::sqrt(static_cast<long double>(77316096));
    constexpr std::size_t sample_count = 500;

    const auto start = std::chrono::steady_clock::now();
    long double observed_square_sum = 0;
    for (std::size_t i = 0; i < sample_count; ++i) {
        const NTL::ZZ value = sampler.sample_coefficient(sigma_squared, zz(1), random);
        const long double value_ld = static_cast<long double>(NTL::to_long(value));
        observed_square_sum += value_ld * value_ld;
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const long double observed_rms =
        std::sqrt(observed_square_sum / sample_count);

    require(elapsed < std::chrono::seconds(10),
            "production-scale sampling must complete in well under a "
            "second per sample, not the tens of minutes to hours observed "
            "with the old O(sigma) geometric sampler");
    require(observed_rms > 0.5L * sigma && observed_rms < 1.5L * sigma,
            "production-scale sample RMS must stay within a broad band "
            "around sigma, confirming the target distribution's width is "
            "unchanged at large sigma");
}

// Regression check: cross-validates the current (fast, J*t+I) geometric
// sampler's statistical behaviour against both closed-form theory and a
// fixed test-local copy of the prior (unary, O(rate_denominator))
// production implementation, at a rate_denominator small enough for the
// old algorithm to remain tractable in a unit test.
void test_geometric_regression_against_prior_implementation() {
    ExactBernoulliExponentialProvider exponential;
    lattice_lrs::sampling::SystemRandomSource random;

    const NTL::ZZ rate_denominator = zz(50);
    constexpr std::size_t sample_count = 4000;

    long double fast_sum = 0;
    long double reference_sum = 0;
    for (std::size_t i = 0; i < sample_count; ++i) {
        fast_sum += static_cast<long double>(
            NTL::to_long(fast_sample_geometric(rate_denominator, random, exponential)));
        reference_sum += static_cast<long double>(NTL::to_long(
            reference_unary_sample_geometric(rate_denominator, random, exponential)));
    }
    const long double fast_mean = fast_sum / sample_count;
    const long double reference_mean = reference_sum / sample_count;

    // Closed-form mean of K ~ Geometric(1 - exp(-1/t)): E[K] = 1/(e^{1/t}-1).
    const long double t = 50.0L;
    const long double theoretical_mean = 1.0L / (std::expl(1.0L / t) - 1.0L);

    require(std::abs(fast_mean - theoretical_mean) < 2.5L,
            "fast geometric sampler's empirical mean must track the exact "
            "theoretical geometric mean");
    require(std::abs(reference_mean - theoretical_mean) < 2.5L,
            "reference unary geometric sampler's empirical mean must also "
            "track the same theoretical mean (sanity check on the "
            "reference implementation itself)");
    require(std::abs(fast_mean - reference_mean) < 3.5L,
            "the fast and prior geometric samplers must agree with each "
            "other's empirical distribution within statistical noise, "
            "confirming the optimization did not change the sampled "
            "distribution");
}

}  // namespace

int main() {
    try {
        test_parameter_validation();
        test_deterministic_acceptance_and_signs();
        test_rejection_retry_and_exact_rational_logs();
        test_geometric_proposal_correctness_scripted();
        test_large_variance_no_overflow_and_terminates();
        test_random_source_failure_propagates();
        test_termination_cost_is_independent_of_rate();
        test_statistical_distribution_diagnostic();
        test_statistical_distribution_production_scale();
        test_geometric_regression_against_prior_implementation();
    } catch (const std::exception& error) {
        std::cerr << "Discrete-Gaussian test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
