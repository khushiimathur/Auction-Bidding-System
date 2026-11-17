#include "lattice_lrs/proofs/protocol2_rejection.hpp"
#include "lattice_lrs/proofs/protocol2_response_lift.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::CommitmentKey;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::proofs::AcceptProtocol2JointResponse;
using lattice_lrs::proofs::BernoulliExponentialProvider;
using lattice_lrs::proofs::ComputeProtocol2IntegerLiftResponses;
using lattice_lrs::proofs::PositiveRational;
using lattice_lrs::proofs::Protocol2IntegerLiftResponses;
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
    Parameters parameters{1, 1, 1, 2, z(17), z(4),
                          SquaredNormBound(z(100), z(1))};
    Matrix G_r(1, 1, 2, z(17));
    Matrix G_m(1, 1, 2, z(17));
    G_r.at(0, 0) = Polynomial(2, z(17), {z(1)});
    return CommitmentKey(parameters, std::move(G_r), std::move(G_m));
}

Protocol2JointRejectionInput with_centers(
    const Protocol2IntegerLiftResponses& responses,
    std::vector<NTL::ZZ> center_z,
    std::vector<NTL::ZZ> center_z_b,
    std::vector<NTL::ZZ> center_z_c) {
    return {responses.z_lift, responses.z_b_lift, responses.z_c_lift,
            std::move(center_z), std::move(center_z_b), std::move(center_z_c)};
}

void test_nonnegative_exponents_accept_without_provider() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    const Polynomial x(2, z(17), {z(0), z(1)});
    FailingRandomSource random;
    RecordingExponential exponential(false);

    const Protocol2IntegerLiftResponses positive =
        ComputeProtocol2IntegerLiftResponses(
            x, 2, {z(4), z(-4)}, {{z(-56), z(56)}, {z(0), z(0)}},
            {z(4), z(-4)}, {z(-56), z(-56)},
            {z(4), z(-4)}, {z(-56), z(-56)});
    const Protocol2JointRejectionInput positive_input = with_centers(
        positive, {z(-4), z(4)}, {z(4), z(4)}, {z(4), z(4)});
    require(positive.z_lift == std::vector<NTL::ZZ>{z(52), z(-52)} &&
                positive.z_b_lift == std::vector<NTL::ZZ>{z(-52), z(-52)} &&
                positive.z_c_lift == std::vector<NTL::ZZ>{z(-52), z(-52)},
            "positive-exponent responses must match the hand calculation");
    require(AcceptProtocol2JointResponse(
                key, phi2, positive_input, random, exponential),
            "positive exponent must accept deterministically");

    const Protocol2IntegerLiftResponses zero =
        ComputeProtocol2IntegerLiftResponses(
            x, 2, {z(4), z(-4)}, {{z(-52), z(52)}, {z(0), z(0)}},
            {z(4), z(-4)}, {z(-52), z(-52)},
            {z(4), z(-4)}, {z(-52), z(-52)});
    const Protocol2JointRejectionInput zero_input = with_centers(
        zero, {z(-4), z(4)}, {z(4), z(4)}, {z(4), z(4)});
    require(zero.z_lift == std::vector<NTL::ZZ>{z(48), z(-48)} &&
                zero.z_b_lift == std::vector<NTL::ZZ>{z(-48), z(-48)} &&
                zero.z_c_lift == std::vector<NTL::ZZ>{z(-48), z(-48)},
            "zero-exponent responses must match the hand calculation");
    require(AcceptProtocol2JointResponse(
                key, phi2, zero_input, random, exponential),
            "zero exponent must accept deterministically");
    require(exponential.calls == 0,
            "nonnegative exponents must not invoke the Bernoulli provider");
}

void test_negative_exponent_and_unreduced_lifts() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    const Polynomial x(2, z(17), {z(0), z(1)});
    FailingRandomSource random;
    RecordingExponential exponential(false);

    const Protocol2IntegerLiftResponses responses =
        ComputeProtocol2IntegerLiftResponses(
            x, 2, {z(2), z(-3)},
            {{z(1), z(4)}, {z(-2), z(5)}},
            {z(3), z(4)}, {z(-30), z(0)},
            {z(-2), z(1)}, {z(0), z(0)});
    require(responses.z_lift == std::vector<NTL::ZZ>{z(2), z(1)} &&
                responses.z_b_lift == std::vector<NTL::ZZ>{z(-34), z(3)} &&
                responses.z_c_lift == std::vector<NTL::ZZ>{z(-1), z(-2)},
            "negative-exponent responses must match the hand calculation");

    const Protocol2JointRejectionInput input = with_centers(
        responses, {z(-2), z(3)}, {z(-4), z(3)}, {z(-1), z(-2)});
    require(!AcceptProtocol2JointResponse(
                key, phi2, input, random, exponential),
            "negative exponent must use the provider's rejection result");

    // Hand calculation: K^2=96, ||C||^2=43, <Z,C>=149, hence
    // numerator=-25*96 + (-2*149+43)=-2655 and denominator=2*96=192.
    require(exponential.calls == 1 &&
                exponential.last_numerator == z(-2655) &&
                exponential.last_denominator == z(192),
            "joint rejection exponent must match the independent calculation");
    require(input.z_b_lift[0] == z(-34),
            "the coefficient beyond q must reach rejection without reduction");
}

void test_provider_and_random_source_failures_propagate() {
    const CommitmentKey key = make_key();
    const PositiveRational phi2(z(1), z(1));
    const Polynomial x(2, z(17), {z(0), z(1)});
    const Protocol2IntegerLiftResponses responses =
        ComputeProtocol2IntegerLiftResponses(
            x, 2, {z(2), z(-3)},
            {{z(1), z(4)}, {z(-2), z(5)}},
            {z(3), z(4)}, {z(-30), z(0)},
            {z(-2), z(1)}, {z(0), z(0)});
    const Protocol2JointRejectionInput input = with_centers(
        responses, {z(-2), z(3)}, {z(-4), z(3)}, {z(-1), z(-2)});
    FailingRandomSource random;
    ThrowingExponential throwing_provider;
    RandomUsingExponential random_using_provider;

    auto require_runtime_error = [&](auto&& action, const std::string& message) {
        bool threw = false;
        try {
            action();
        } catch (const std::runtime_error&) {
            threw = true;
        }
        require(threw, message);
    };
    require_runtime_error(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, input, random, throwing_provider);
        },
        "exponential-provider failures must propagate");
    require_runtime_error(
        [&] {
            (void)AcceptProtocol2JointResponse(
                key, phi2, input, random, random_using_provider);
        },
        "RandomSource failures must propagate through the provider");
}

}  // namespace

int main() {
    try {
        test_nonnegative_exponents_accept_without_provider();
        test_negative_exponent_and_unreduced_lifts();
        test_provider_and_random_source_failures_propagate();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 response/rejection integration test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
