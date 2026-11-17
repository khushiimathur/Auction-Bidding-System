#include "lattice_lrs/proofs/protocol2_rejection.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::CommitmentKey;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::proofs::AcceptProtocol2JointResponse;
using lattice_lrs::proofs::BernoulliExponentialProvider;
using lattice_lrs::proofs::PositiveRational;
using lattice_lrs::proofs::Protocol2JointRejectionInput;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("random source failure");
    }
};

class RecordingExponential final : public BernoulliExponentialProvider {
public:
    explicit RecordingExponential(bool result) : result_(result) {}

    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        ++calls;
        last_numerator = numerator;
        last_denominator = denominator;
        return result_;
    }

    std::size_t calls = 0;
    NTL::ZZ last_numerator{0};
    NTL::ZZ last_denominator{0};

private:
    bool result_;
};

class ThrowingExponential final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ&, const NTL::ZZ&, RandomSource&) override {
        throw std::runtime_error("exponential provider failure");
    }
};

class RandomUsingExponential final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ&, const NTL::ZZ&,
                    RandomSource& random) override {
        std::uint8_t byte = 0;
        random.fill_bytes(&byte, 1);
        return byte != 0;
    }
};

CommitmentKey make_key() {
    Parameters parameters{1, 1, 1, 1, z(17), z(1),
                          SquaredNormBound(z(10), z(1))};
    Matrix G_r(1, 1, 1, z(17));
    Matrix G_m(1, 1, 1, z(17));
    G_r.at(0, 0) = Polynomial(1, z(17), {z(1)});
    return CommitmentKey(parameters, std::move(G_r), std::move(G_m));
}

Protocol2JointRejectionInput make_input(long response_coefficient) {
    return {{z(response_coefficient)}, {z(response_coefficient)},
            {z(response_coefficient)}, {z(1)}, {z(1)}, {z(1)}};
}

template <typename Exception, typename Function>
void require_throws(Function&& function, const std::string& message) {
    bool threw = false;
    try {
        function();
    } catch (const Exception&) {
        threw = true;
    }
    require(threw, message);
}

void test_positive_and_zero_exponents_accept_deterministically() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    FailingRandomSource random;
    RecordingExponential exponential(false);

    require(AcceptProtocol2JointResponse(
                key, phi2, make_input(-13), random, exponential),
            "positive exponent must accept deterministically");
    require(AcceptProtocol2JointResponse(
                key, phi2, make_input(-12), random, exponential),
            "zero exponent must accept deterministically");
    require(exponential.calls == 0,
            "nonnegative exponents must not invoke the exponential provider");
}

void test_negative_exponent_uses_exact_rational_provider() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    FailingRandomSource random;
    RecordingExponential exponential(false);

    require(!AcceptProtocol2JointResponse(
                key, phi2, make_input(0), random, exponential),
            "negative exponent result must come from the provider");
    require(exponential.calls == 1, "negative exponent must invoke the provider once");
    // K^2=3, ||C||^2=3, and <Z,C>=0:
    // E=(-75+3)/6=-12. The previous -1/phi constant yielded -6/6.
    require(exponential.last_numerator == z(-72) &&
                exponential.last_denominator == z(6),
            "provider must receive the corrected exact rational exponent");
}

void test_inner_product_sign_is_preserved() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    FailingRandomSource random;
    RecordingExponential exponential(false);

    (void)AcceptProtocol2JointResponse(
        key, phi2, make_input(1), random, exponential);
    // <Z,C>=3 and ||C||^2=3, so E=(-75-6+3)/6=-13.
    require(exponential.calls == 1 &&
                exponential.last_numerator == z(-78) &&
                exponential.last_denominator == z(6),
            "the response-center inner-product sign must remain negative");
}

void test_integer_lifts_are_used_without_modular_reduction() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    FailingRandomSource random;
    RecordingExponential exponential(true);
    Protocol2JointRejectionInput input = make_input(0);
    input.z_lift[0] = z(15);  // Keep this lift; q=17 would center it to -2.

    require(AcceptProtocol2JointResponse(
                key, phi2, input, random, exponential),
            "provider's decision must be returned");
    require(exponential.last_numerator == z(-102) &&
                exponential.last_denominator == z(6),
            "rejection exponent must use the supplied integer lift, not a residue lift");
}

void test_invalid_dimensions_and_center_bound() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    FailingRandomSource random;
    RecordingExponential exponential(false);

    Protocol2JointRejectionInput invalid = make_input(0);
    invalid.z_b_lift.clear();
    require_throws<std::invalid_argument>(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, invalid, random, exponential);
        },
        "a response block with the wrong dimension must be rejected");

    invalid = make_input(0);
    invalid.center_z_lift.clear();
    require_throws<std::invalid_argument>(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, invalid, random, exponential);
        },
        "a center block with the wrong dimension must be rejected");

    invalid = make_input(0);
    invalid.center_z_lift[0] = z(2);
    require_throws<std::invalid_argument>(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, invalid, random, exponential);
        },
        "a concatenated rejection center exceeding K must be rejected");
}

void test_provider_and_random_source_failures_propagate() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    Protocol2JointRejectionInput input = make_input(0);
    FailingRandomSource random;
    ThrowingExponential throwing_provider;
    RandomUsingExponential random_using_provider;

    require_throws<std::runtime_error>(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, input, random, throwing_provider);
        },
        "exponential-provider failures must propagate");
    require_throws<std::runtime_error>(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, input, random, random_using_provider);
        },
        "RandomSource failures must propagate through the provider");
}

}  // namespace

int main() {
    try {
        test_positive_and_zero_exponents_accept_deterministically();
        test_negative_exponent_uses_exact_rational_provider();
        test_inner_product_sign_is_preserved();
        test_integer_lifts_are_used_without_modular_reduction();
        test_invalid_dimensions_and_center_bound();
        test_provider_and_random_source_failures_propagate();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 rejection test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
