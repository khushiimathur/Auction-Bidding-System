#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include <NTL/ZZ.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::ring_signature::ChallengeSet;
using lattice_lrs::ring_signature::ChallengeVector;
using lattice_lrs::ring_signature::HashToChallenges;
using lattice_lrs::ring_signature::RKeygen;
using lattice_lrs::ring_signature::RKeygenForTesting;
using lattice_lrs::ring_signature::RSetupForTesting;
using lattice_lrs::ring_signature::TestOnlySetupParameters;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

class ZeroByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        std::fill(output, output + length, std::uint8_t(0));
    }
};

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("simulated random-source failure");
    }
};

class FirstChallenges final : public HashToChallenges {
public:
    ChallengeVector hash(const std::vector<std::uint8_t>&,
                         const ChallengeSet& challenge_set,
                         std::size_t output_count) const override {
        if (output_count > challenge_set.size()) {
            throw std::invalid_argument("test requested too many challenges");
        }
        return ChallengeVector(challenge_set.begin(),
                              challenge_set.begin() + output_count);
    }
};

class InvalidHash final : public HashToChallenges {
public:
    ChallengeVector hash(const std::vector<std::uint8_t>&,
                         const ChallengeSet&,
                         std::size_t output_count) const override {
        return ChallengeVector(output_count, Polynomial(1, z(3)));
    }
};

TestOnlySetupParameters test_parameters() {
    return TestOnlySetupParameters{
        Parameters{1, 2, 1, 3, z(101), z(3),
                   SquaredNormBound(z(100000), z(1))},
        2};
}

bool throws_invalid_argument(const std::function<void()>& operation) {
    try {
        operation();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

bool throws_runtime_error(const std::function<void()>& operation) {
    try {
        operation();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

void test_setup_challenge_set_and_hash_interface() {
    ZeroByteSource random;
    const auto hash = std::make_shared<FirstChallenges>();
    const auto public_parameters =
        RSetupForTesting(test_parameters(), hash, random);

    const ChallengeSet& challenges = public_parameters.challenge_set();
    require(challenges.size() == 6, "challenge set must contain 2d elements");
    for (std::size_t exponent = 0; exponent < challenges.size(); ++exponent) {
        std::vector<NTL::ZZ> expected(3, z(0));
        expected[exponent % 3] = exponent < 3 ? z(1) : z(100);
        require(challenges[exponent] == Polynomial(3, z(101), expected),
                "challenge set must represent X^omega in R_q with X^d = -1");
    }

    const ChallengeVector mapped =
        public_parameters.hash_to_challenges({0x01, 0x02, 0x03});
    require(mapped.size() == 2 && mapped[0] == challenges[0] &&
                mapped[1] == challenges[1],
            "injected hash interface must produce the configured number of C-valued challenges");

    const auto invalid_parameters = RSetupForTesting(
        test_parameters(), std::make_shared<InvalidHash>(), random);
    require(throws_runtime_error([&] {
                (void)invalid_parameters.hash_to_challenges({0x01});
            }),
            "invalid hash output must be reported as a provider runtime error");
}

void test_keygen_commitment_consistency_and_distribution() {
    ZeroByteSource setup_random;
    const auto public_parameters = RSetupForTesting(
        test_parameters(), std::make_shared<FirstChallenges>(), setup_random);

    ZeroByteSource key_random;
    const auto key_pair = RKeygenForTesting(public_parameters, key_random);
    const auto& parameters = public_parameters.commitment_key().parameters();
    require(key_pair.secret_key.randomness.size() == parameters.m,
            "secret key must contain m ring elements");
    for (const Polynomial& polynomial : key_pair.secret_key.randomness) {
        require(polynomial.degree() == parameters.degree &&
                    polynomial.modulus() == parameters.q,
                "secret-key polynomial ring mismatch");
        for (std::size_t i = 0; i < parameters.degree; ++i) {
            const NTL::ZZ coefficient = polynomial.centered_coefficient(i);
            require(coefficient >= -parameters.B && coefficient <= parameters.B,
                    "secret key must be sampled from S_B^m");
        }
    }

    const Polynomial zero(parameters.degree, parameters.q);
    const std::vector<Polynomial> zero_message(parameters.v, zero);
    const auto expected = lattice_lrs::commitment::Com(
        public_parameters.commitment_key(), zero_message,
        key_pair.secret_key.randomness);
    require(key_pair.public_key.commitment == expected,
            "public key must equal Com_ck(0; secret randomness)");
}

void test_invalid_parameters_and_random_failures() {
    ZeroByteSource random;
    const auto hash = std::make_shared<FirstChallenges>();

    TestOnlySetupParameters no_hash_outputs = test_parameters();
    no_hash_outputs.hash_output_count = 0;
    require(throws_invalid_argument([&] {
                (void)RSetupForTesting(no_hash_outputs, hash, random);
            }),
            "setup must reject an empty hash output vector");

    TestOnlySetupParameters noninjective_bound = test_parameters();
    noninjective_bound.commitment.q = z(5);
    noninjective_bound.commitment.B = z(3);
    require(throws_invalid_argument([&] {
                (void)RSetupForTesting(noninjective_bound, hash, random);
            }),
            "setup must reject S_B coefficients that are ambiguous modulo q");

    TestOnlySetupParameters invalid_modulus = test_parameters();
    invalid_modulus.commitment.q = z(100);
    require(throws_invalid_argument([&] {
                (void)RSetupForTesting(invalid_modulus, hash, random);
            }),
            "setup must reject an even commitment modulus");

    TestOnlySetupParameters invalid_dimensions = test_parameters();
    invalid_dimensions.commitment.m = 0;
    require(throws_invalid_argument([&] {
                (void)RSetupForTesting(invalid_dimensions, hash, random);
            }),
            "setup must reject invalid commitment dimensions");

    require(throws_invalid_argument([&] {
                (void)RSetupForTesting(test_parameters(), nullptr, random);
            }),
            "setup must reject a missing hash-to-challenges provider");

    FailingRandomSource failing;
    bool setup_failure_propagated = false;
    try {
        (void)RSetupForTesting(test_parameters(), hash, failing);
    } catch (const std::runtime_error&) {
        setup_failure_propagated = true;
    }
    require(setup_failure_propagated,
            "RSetup must propagate commitment-key randomness failures");

    const auto public_parameters =
        RSetupForTesting(test_parameters(), hash, random);
    bool keygen_failure_propagated = false;
    try {
        (void)RKeygenForTesting(public_parameters, failing);
    } catch (const std::runtime_error&) {
        keygen_failure_propagated = true;
    }
    require(keygen_failure_propagated,
            "RKeygen must propagate secret-key sampling failures");
    require(throws_invalid_argument([&] {
                (void)RKeygen(public_parameters, random);
            }),
            "production RKeygen must reject TestOnly setup parameters");
}

}  // namespace

int main() {
    try {
        test_setup_challenge_set_and_hash_interface();
        test_keygen_commitment_consistency_and_distribution();
        test_invalid_parameters_and_random_failures();
    } catch (const std::exception& error) {
        std::cerr << "ring-signature setup/keygen test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
