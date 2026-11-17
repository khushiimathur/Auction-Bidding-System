#include "lattice_lrs/proofs/bernoulli_pi_exponential.hpp"
#include "lattice_lrs/proofs/discrete_gaussian_s.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::proofs::BernoulliPiExponentialProvider;
using lattice_lrs::proofs::ExactBernoulliPiExponentialProvider;
using lattice_lrs::proofs::ExactDiscreteGaussianSProvider;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ zz(long value) { return NTL::to_ZZ(value); }

struct RationalInput {
    NTL::ZZ numerator;
    NTL::ZZ denominator;
};

class ScriptedPiExponential final : public BernoulliPiExponentialProvider {
public:
    explicit ScriptedPiExponential(std::vector<bool> outcomes)
        : outcomes_(std::move(outcomes)) {}

    bool sample_exp_neg_pi_rational(const NTL::ZZ& numerator,
                                    const NTL::ZZ& denominator,
                                    RandomSource&) override {
        require(numerator >= 0 && denominator > 0,
                "sampler must pass a nonnegative rational pi-exponential input");
        calls_.push_back({numerator, denominator});
        if (next_ == outcomes_.size()) {
            throw std::runtime_error("scripted pi-exponential outcomes exhausted");
        }
        return outcomes_[next_++];
    }

    const std::vector<RationalInput>& calls() const noexcept { return calls_; }

private:
    std::vector<bool> outcomes_;
    std::size_t next_ = 0;
    std::vector<RationalInput> calls_;
};

class FixedByteSource final : public RandomSource {
public:
    explicit FixedByteSource(std::uint8_t byte) : byte_(byte) {}

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        ++calls;
        for (std::size_t i = 0; i < length; ++i) output[i] = byte_;
    }

    std::size_t calls = 0;

private:
    std::uint8_t byte_;
};

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        ++calls;
        throw std::runtime_error("injected random source failure");
    }
    std::size_t calls = 0;
};

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
    ScriptedPiExponential exponential({});
    FixedByteSource random(0);
    require_invalid_argument(
        [&] { ExactDiscreteGaussianSProvider invalid(exponential, zz(0), zz(1)); },
        "zero proposal center numerator must be rejected");
    require_invalid_argument(
        [&] { ExactDiscreteGaussianSProvider invalid(exponential, zz(1), zz(0)); },
        "zero proposal center denominator must be rejected");

    ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
    require_invalid_argument(
        [&] { (void)sampler.sample_coefficient_from_scale_squared(zz(0), zz(1), random); },
        "zero s_squared numerator must be rejected");
    require_invalid_argument(
        [&] { (void)sampler.sample_coefficient_from_scale_squared(zz(-1), zz(1), random); },
        "negative s_squared numerator must be rejected");
    require_invalid_argument(
        [&] { (void)sampler.sample_coefficient_from_scale_squared(zz(1), zz(0), random); },
        "zero s_squared denominator must be rejected");
    require_invalid_argument(
        [&] { (void)sampler.sample_coefficient_from_scale_squared(zz(1), zz(-1), random); },
        "negative s_squared denominator must be rejected");
    require(exponential.calls().empty() && random.calls == 0,
            "invalid parameters must fail before consuming randomness");

    ExactBernoulliPiExponentialProvider pi_exponential;
    require_invalid_argument(
        [&] { (void)pi_exponential.sample_exp_neg_pi_rational(zz(-1), zz(1), random); },
        "negative pi-exponential input must be rejected");
    require_invalid_argument(
        [&] { (void)pi_exponential.sample_exp_neg_pi_rational(zz(1), zz(0), random); },
        "zero pi-exponential denominator must be rejected");
}

void test_exact_pi_exponential_edges() {
    ExactBernoulliPiExponentialProvider exponential;
    FixedByteSource zero_bits(0);
    FixedByteSource one_bits(0xff);

    require(exponential.sample_exp_neg_pi_rational(zz(0), zz(7), zero_bits),
            "t=0 must be accepted deterministically");
    require(zero_bits.calls == 0, "t=0 must not consume random bits");
    require(exponential.sample_exp_neg_pi_rational(zz(1), zz(2), zero_bits),
            "all-zero bits must eventually lie below a positive probability");
    require(zero_bits.calls > 0, "positive input must consume random bits");
    require(!exponential.sample_exp_neg_pi_rational(zz(1), zz(1), one_bits),
            "all-one bits must eventually lie above exp(-pi)");
    require(one_bits.calls > 0, "positive input must refine the random interval");

    FixedByteSource large_input_bits(0xff);
    require(!exponential.sample_exp_neg_pi_rational(zz(1000), zz(1),
                                                     large_input_bits),
            "large positive input should have a rapidly rejected coin path");
}

void test_scripted_sampler_paths() {
    FixedByteSource random_bytes(0);
    {
        ScriptedPiExponential exponential({true, false, false});
        ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
        require(sampler.sample_coefficient_from_scale_squared(zz(1), zz(1),
                                                               random_bytes) == zz(1),
                "positive output should be produced by the geometric difference");
        require(exponential.calls().size() == 3,
                "zero acceptance exponent must not request an additional coin");
        require(exponential.calls()[0].numerator == zz(2) &&
                    exponential.calls()[0].denominator == zz(1),
                "geometric proposal must use the exact parameter 2a/S");
    }
    {
        ScriptedPiExponential exponential({false, true, false});
        ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
        require(sampler.sample_coefficient_from_scale_squared(zz(1), zz(1),
                                                               random_bytes) == zz(-1),
                "negative output should be preserved");
    }
    {
        ScriptedPiExponential exponential({false, false, true});
        ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
        require(sampler.sample_coefficient_from_scale_squared(zz(1), zz(1),
                                                               random_bytes) == zz(0),
                "zero output should pass through the acceptance coin");
        require(exponential.calls().size() == 3,
                "zero output's nonzero acceptance exponent must be tested");
        require(exponential.calls()[2].numerator == zz(1) &&
                    exponential.calls()[2].denominator == zz(1),
                "acceptance exponent must be (|y|-a)^2/S");
    }
    {
        ScriptedPiExponential exponential(
            {true, true, true, true, true, false, false, true});
        ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
        require(sampler.sample_coefficient_from_scale_squared(zz(1), zz(1),
                                                               random_bytes) == zz(5),
                "large geometric proposal should be returned when accepted");
        require(exponential.calls().back().numerator == zz(16) &&
                    exponential.calls().back().denominator == zz(1),
                "large proposal must use its exact rational acceptance exponent");
    }
    {
        ScriptedPiExponential exponential({true, true, false, false, true});
        ExactDiscreteGaussianSProvider sampler(exponential, zz(3), zz(2));
        require(sampler.sample_coefficient_from_scale_squared(zz(5), zz(2),
                                                               random_bytes) == zz(2),
                "rational proposal center and scale must remain supported");
        require(exponential.calls()[0].numerator * zz(5) ==
                    exponential.calls()[0].denominator * zz(6),
                "rational scale must produce the exact geometric rate");
        require(exponential.calls().back().numerator * zz(10) ==
                    exponential.calls().back().denominator,
                "rational parameters must produce the exact acceptance exponent");
    }
    {
        ScriptedPiExponential exponential({false, false, false, true, false, false});
        ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
        require(sampler.sample_coefficient_from_scale_squared(zz(1), zz(1),
                                                               random_bytes) == zz(1),
                "outer rejection must draw another geometric proposal");
        require(exponential.calls().size() == 6,
                "rejected proposal must consume an acceptance decision before retry");
    }
}

void test_random_source_failure_propagates() {
    ExactBernoulliPiExponentialProvider exponential;
    ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
    FailingRandomSource random;
    bool propagated = false;
    try {
        (void)sampler.sample_coefficient_from_scale_squared(zz(1), zz(1), random);
    } catch (const std::runtime_error&) {
        propagated = true;
    }
    require(propagated && random.calls == 1,
            "random-source failure must propagate without a fallback sample");
}

void test_statistical_distribution_diagnostic() {
    ExactBernoulliPiExponentialProvider exponential;
    ExactDiscreteGaussianSProvider sampler(exponential, zz(1), zz(1));
    lattice_lrs::sampling::SystemRandomSource random;
    constexpr std::size_t sample_count = 256;
    long double sum = 0;
    long double sum_squares = 0;
    bool observed_positive = false;
    bool observed_negative = false;
    bool observed_zero = false;
    bool observed_large_magnitude = false;

    for (std::size_t i = 0; i < sample_count; ++i) {
        const long value = NTL::to_long(
            sampler.sample_coefficient_from_scale_squared(zz(4), zz(1), random));
        sum += value;
        sum_squares += static_cast<long double>(value) * value;
        observed_positive = observed_positive || value > 0;
        observed_negative = observed_negative || value < 0;
        observed_zero = observed_zero || value == 0;
        observed_large_magnitude = observed_large_magnitude || std::abs(value) >= 2;
    }

    const long double mean = sum / sample_count;
    const long double second_moment = sum_squares / sample_count;
    require(observed_positive && observed_negative && observed_zero &&
                observed_large_magnitude,
            "statistical diagnostic should observe both signs, zero, and a tail value");
    require(std::abs(mean) < 0.35L,
            "diagnostic sample mean is outside its broad symmetry band");
    require(second_moment > 0.2L && second_moment < 1.5L,
            "diagnostic second moment is outside its broad reference band");
}

}  // namespace

int main() {
    try {
        test_parameter_validation();
        test_exact_pi_exponential_edges();
        test_scripted_sampler_paths();
        test_random_source_failure_propagates();
        test_statistical_distribution_diagnostic();
    } catch (const std::exception& error) {
        std::cerr << "D_s discrete-Gaussian test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
