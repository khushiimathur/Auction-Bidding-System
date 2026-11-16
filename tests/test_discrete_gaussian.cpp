#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/discrete_gaussian.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

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

void test_deterministic_acceptance_and_signs() {
    ZeroRandomSource random;
    {
        ScriptedExponential exponential({true, false, false});
        ExactDiscreteGaussianProvider sampler(exponential);
        require(sampler.sample_coefficient(zz(1), zz(1), random) == zz(1),
                "zero acceptance log must accept deterministically");
        require(exponential.calls().size() == 3,
                "zero acceptance log must not call the exponential provider");
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

    ScriptedExponential reduced_log_retry({false, false, false, true, false,
                                           false, true});
    ExactDiscreteGaussianProvider reduced_log_sampler(reduced_log_retry);
    require(reduced_log_sampler.sample_coefficient(zz(3), zz(1), random) == zz(1),
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

    NTL::ZZ huge_variance;
    NTL::power(huge_variance, zz(10), 80);
    NTL::ZZ huge_rate_denominator;
    NTL::power(huge_rate_denominator, zz(10), 40);
    ScriptedExponential large_exponential({false, false, true});
    ExactDiscreteGaussianProvider large_sampler(large_exponential);
    require(large_sampler.sample_coefficient(huge_variance, zz(1), random) == zz(0),
            "large exact sigma_squared must not overflow");
    require(large_exponential.calls().size() == 3,
            "large-parameter case must use two proposal coins and one acceptance coin");
    require(large_exponential.calls()[0].numerator == zz(-1) &&
                large_exponential.calls()[0].denominator == huge_rate_denominator &&
                large_exponential.calls()[1].numerator == zz(-1) &&
                large_exponential.calls()[1].denominator == huge_rate_denominator,
            "large-parameter proposal rate must remain exact");
    require(large_exponential.calls()[2].numerator == zz(-1) &&
                large_exponential.calls()[2].denominator == zz(2),
            "large-parameter acceptance log must remain exact");
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

}  // namespace

int main() {
    try {
        test_parameter_validation();
        test_deterministic_acceptance_and_signs();
        test_rejection_retry_and_exact_rational_logs();
        test_random_source_failure_propagates();
        test_statistical_distribution_diagnostic();
    } catch (const std::exception& error) {
        std::cerr << "Discrete-Gaussian test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
