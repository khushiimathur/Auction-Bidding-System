#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

using lattice_lrs::proofs::BernoulliExponentialProvider;
using lattice_lrs::proofs::ExactBernoulliExponentialProvider;
using lattice_lrs::sampling::RandomSource;

static_assert(std::is_base_of_v<BernoulliExponentialProvider,
                                ExactBernoulliExponentialProvider>,
              "production sampler must implement the existing provider API");

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ zz(long value) { return NTL::to_ZZ(value); }

class ConstantByteSource final : public RandomSource {
public:
    explicit ConstantByteSource(std::uint8_t byte) : byte_(byte) {}

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        ++calls;
        for (std::size_t i = 0; i < length; ++i) output[i] = byte_;
    }

    std::size_t calls = 0;

private:
    std::uint8_t byte_;
};

class FailingByteSource final : public RandomSource {
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

void test_exact_boundary_decisions() {
    ExactBernoulliExponentialProvider provider;

    // These deterministic bit tapes force U near zero and near one. They test
    // interval-comparison branches, not the probability distribution.
    ConstantByteSource low_bits(0x00);
    require(provider.sample_exp(zz(-1), zz(1), low_bits),
            "low uniform bit stream must fall below exp(-1)");
    require(low_bits.calls > 0, "negative log must consume random bytes");

    ConstantByteSource high_bits(0xFF);
    require(!provider.sample_exp(zz(-1), zz(1), high_bits),
            "high uniform bit stream must exceed exp(-1)");

    ConstantByteSource just_below_one_low(0x00);
    require(provider.sample_exp(zz(-255), zz(256), just_below_one_low),
            "low uniform bit stream must accept just below x=1");
    ConstantByteSource just_below_one_high(0xFF);
    require(!provider.sample_exp(zz(-255), zz(256), just_below_one_high),
            "high uniform bit stream must reject just below x=1");

    ConstantByteSource just_above_one_low(0x00);
    require(provider.sample_exp(zz(-257), zz(256), just_above_one_low),
            "low uniform bit stream must accept just above x=1");
    ConstantByteSource just_above_one_high(0xFF);
    require(!provider.sample_exp(zz(-257), zz(256), just_above_one_high),
            "high uniform bit stream must reject just above x=1");

    ConstantByteSource zero_fraction(0x00);
    require(provider.sample_exp(zz(-1), zz(2), zero_fraction),
            "negative fractional log with low bits must accept");
    ConstantByteSource high_fraction(0xFF);
    require(!provider.sample_exp(zz(-1), zz(2), high_fraction),
            "negative fractional log with high bits must reject");

    ConstantByteSource multi_unit_low(0x00);
    require(provider.sample_exp(zz(-2), zz(1), multi_unit_low),
            "product of unit exponential coins must accept on all-low tape");
    ConstantByteSource multi_unit_high(0xFF);
    require(!provider.sample_exp(zz(-2), zz(1), multi_unit_high),
            "product of unit exponential coins must stop on first failure");
}

void test_invalid_inputs_and_failure_propagation() {
    ExactBernoulliExponentialProvider provider;
    ConstantByteSource unused(0x00);

    require_invalid_argument([&] { (void)provider.sample_exp(zz(0), zz(1), unused); },
        "zero log must be handled by the caller's deterministic branch");
    require_invalid_argument([&] { (void)provider.sample_exp(zz(1), zz(1), unused); },
        "positive log must be rejected by the negative-domain provider");
    require_invalid_argument([&] { (void)provider.sample_exp(zz(-1), zz(0), unused); },
        "zero denominator must be rejected");
    require_invalid_argument([&] { (void)provider.sample_exp(zz(-1), zz(-1), unused); },
        "negative denominator must be rejected");
    require(unused.calls == 0, "invalid inputs must fail before consuming randomness");

    FailingByteSource failing;
    bool propagated = false;
    try {
        (void)provider.sample_exp(zz(-1), zz(2), failing);
    } catch (const std::runtime_error&) {
        propagated = true;
    }
    require(propagated && failing.calls == 1,
            "randomness failure must propagate without a fallback decision");
}

void test_extreme_rational_inputs_terminate_without_fixed_precision() {
    ExactBernoulliExponentialProvider provider;
    NTL::ZZ huge_numerator;
    NTL::power(huge_numerator, zz(10), 80);
    ConstantByteSource high_bits(0xFF);
    require(!provider.sample_exp(-huge_numerator, zz(1), high_bits),
            "very negative log should short-circuit on a rejecting unit coin");

    NTL::ZZ huge_denominator;
    NTL::power(huge_denominator, zz(2), 256);
    ConstantByteSource low_bits(0x00);
    require(provider.sample_exp(zz(-1), huge_denominator, low_bits),
            "very small negative log should accept on a low uniform tape");
}

void test_empirical_probability_diagnostic() {
    ExactBernoulliExponentialProvider provider;
    lattice_lrs::sampling::SystemRandomSource random;
    constexpr std::size_t trials = 2048;
    std::size_t accepted = 0;
    for (std::size_t i = 0; i < trials; ++i) {
        accepted += provider.sample_exp(zz(-1), zz(1), random) ? 1U : 0U;
    }

    const double observed = static_cast<double>(accepted) / trials;
    const double expected = std::exp(-1.0);  // Diagnostic only, not production.
    require(std::abs(observed - expected) < 0.06,
            "empirical Bernoulli frequency is outside the broad diagnostic band");
}

}  // namespace

int main() {
    try {
        test_exact_boundary_decisions();
        test_invalid_inputs_and_failure_propagation();
        test_extreme_rational_inputs_terminate_without_fixed_precision();
        test_empirical_probability_diagnostic();
    } catch (const std::exception& error) {
        std::cerr << "Bernoulli-exponential test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
