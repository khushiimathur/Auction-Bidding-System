#include "lattice_lrs/proofs/shake256_auxiliary_commitment.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::proofs::AuxiliaryCommitmentOpening;
using lattice_lrs::proofs::AuxiliaryCommitmentValue;
using lattice_lrs::proofs::Shake256AuxiliaryCommitmentProvider;
using lattice_lrs::sampling::PolynomialVector;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

Polynomial polynomial(long constant) {
    return Polynomial(3, z(101), {z(constant), z(2), z(3)});
}

class InsecureIncrementingRandomSourceForTesting final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        for (std::size_t i = 0; i < length; ++i) {
            output[i] = next_++;
        }
    }

private:
    std::uint8_t next_ = 0;
};

class InsecureFixedRandomSourceForTesting final : public RandomSource {
public:
    explicit InsecureFixedRandomSourceForTesting(std::uint8_t value)
        : value_(value) {}

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        std::fill(output, output + length, value_);
    }

private:
    std::uint8_t value_;
};

class InsecureFailingRandomSourceForTesting final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("simulated entropy failure");
    }
};

std::string to_hex(const std::vector<std::uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (std::uint8_t byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

void test_protocol1_commitment_and_opening() {
    Shake256AuxiliaryCommitmentProvider provider;
    InsecureIncrementingRandomSourceForTesting random;
    const PolynomialVector A{polynomial(1)};
    const PolynomialVector C{polynomial(4)};
    const PolynomialVector D{polynomial(7)};

    const AuxiliaryCommitmentOpening first = provider.commit(A, C, D, random);
    require(first.opening.size() == provider.kOpeningSize &&
                first.commitment.bytes.size() == provider.kDigestSize,
            "Protocol 1 commitment must use the configured opening and digest sizes");
    require(provider.verify(A, C, D, first.commitment, first.opening),
            "Protocol 1 commitment must verify with its opening");

    std::vector<std::uint8_t> wrong_opening = first.opening;
    wrong_opening[0] ^= 1;
    require(!provider.verify(A, C, D, first.commitment, wrong_opening),
            "Protocol 1 must reject an incorrect opening");

    PolynomialVector changed_A = A;
    changed_A[0] = polynomial(2);
    require(!provider.verify(changed_A, C, D, first.commitment, first.opening),
            "Protocol 1 must reject modified input");

    AuxiliaryCommitmentValue changed_commitment = first.commitment;
    changed_commitment.bytes[0] ^= 1;
    require(!provider.verify(A, C, D, changed_commitment, first.opening),
            "Protocol 1 must reject a modified commitment");

    const AuxiliaryCommitmentOpening second = provider.commit(A, C, D, random);
    require(first.opening != second.opening &&
                first.commitment.bytes != second.commitment.bytes,
            "fresh openings for the same input must yield different commitments");
}

void test_protocol2_commitment_and_all_fields() {
    Shake256AuxiliaryCommitmentProvider provider;
    InsecureIncrementingRandomSourceForTesting random;
    const PolynomialVector A{polynomial(1)};
    const PolynomialVector B{polynomial(2)};
    const PolynomialVector C{polynomial(3)};
    const PolynomialVector D{polynomial(4)};
    const std::vector<PolynomialVector> E{{polynomial(5)}, {polynomial(6)}};

    const AuxiliaryCommitmentOpening result =
        provider.commit(A, B, C, D, E, random);
    require(provider.verify(A, B, C, D, E, result.commitment, result.opening),
            "Protocol 2 commitment must verify with its opening");

    PolynomialVector changed_A{polynomial(8)};
    PolynomialVector changed_C{polynomial(8)};
    PolynomialVector changed_D{polynomial(8)};
    PolynomialVector changed_B{polynomial(8)};
    require(!provider.verify(changed_A, B, C, D, E,
                             result.commitment, result.opening) &&
                !provider.verify(A, changed_B, C, D, E,
                             result.commitment, result.opening) &&
                !provider.verify(A, B, changed_C, D, E,
                             result.commitment, result.opening) &&
                !provider.verify(A, B, C, changed_D, E,
                             result.commitment, result.opening),
            "Protocol 2 must bind A, B, C and D fields");
    std::vector<PolynomialVector> changed_E = E;
    changed_E[1][0] = polynomial(8);
    require(!provider.verify(A, B, C, D, changed_E,
                             result.commitment, result.opening),
            "Protocol 2 must bind every E_j field");
}

void test_domain_separation_and_field_boundaries() {
    Shake256AuxiliaryCommitmentProvider provider;
    InsecureFixedRandomSourceForTesting random(0x42);
    const Polynomial x = polynomial(1);
    const Polynomial y = polynomial(2);

    const AuxiliaryCommitmentOpening protocol1 =
        provider.commit({x}, {y}, {}, random);
    const AuxiliaryCommitmentOpening protocol2 =
        provider.commit({x}, {}, {y}, {}, {}, random);
    require(protocol1.opening == protocol2.opening &&
                protocol1.commitment.bytes != protocol2.commitment.bytes,
            "Protocol 1 and Protocol 2 must use separate commitment domains");
    require(!provider.verify({x}, {y}, {}, protocol2.commitment,
                             protocol2.opening),
            "Protocol 1 verifier must reject a Protocol 2 commitment");

    const AuxiliaryCommitmentOpening split_fields =
        provider.commit({x}, {y}, {}, random);
    const AuxiliaryCommitmentOpening merged_field =
        provider.commit({x, y}, {}, {}, random);
    require(split_fields.opening == merged_field.opening &&
                split_fields.commitment.bytes != merged_field.commitment.bytes,
            "length prefixes must distinguish different vector field boundaries");

    const AuxiliaryCommitmentOpening separate_E =
        provider.commit({x}, {}, {}, {}, {{x}, {y}}, random);
    const AuxiliaryCommitmentOpening joined_E =
        provider.commit({x}, {}, {}, {}, {{x, y}}, random);
    require(separate_E.commitment.bytes != joined_E.commitment.bytes,
            "nested length prefixes must distinguish E-vector boundaries");
}

void test_empty_input_known_hash_and_verification_lengths() {
    Shake256AuxiliaryCommitmentProvider provider;
    InsecureFixedRandomSourceForTesting random(0x42);
    const AuxiliaryCommitmentOpening empty =
        provider.commit({}, {}, {}, random);
    require(to_hex(empty.commitment.bytes) ==
                "af68ac72f627b619873973d9f5216dc50a8eac9376498f62a3c4dbb7000b5655",
            "empty Protocol 1 input must match the canonical SHAKE256 vector");
    require(provider.verify({}, {}, {}, empty.commitment, empty.opening),
            "empty input with correct opening must verify");

    const AuxiliaryCommitmentOpening empty_protocol2 =
        provider.commit({}, {}, {}, {}, {}, random);
    require(to_hex(empty_protocol2.commitment.bytes) ==
                "bb53b8e85b1641b46e9d29b8afce0e8d3bcc9092f766cc61b3abe8fe3a0f64e8",
            "empty Protocol 2 input must use its separate canonical domain");
    require(provider.verify({}, {}, {}, {}, {}, empty_protocol2.commitment,
                            empty_protocol2.opening),
            "empty Protocol 2 input with correct opening must verify");

    AuxiliaryCommitmentValue short_digest{{0x01}};
    require(!provider.verify({}, {}, {}, short_digest, empty.opening),
            "verification must reject a digest with the wrong length");
    std::vector<std::uint8_t> short_opening(31, 0x42);
    require(!provider.verify({}, {}, {}, empty.commitment, short_opening),
            "verification must reject an opening with the wrong length");
}

void test_randomness_failure_propagates() {
    Shake256AuxiliaryCommitmentProvider provider;
    InsecureFailingRandomSourceForTesting random;
    bool propagated = false;
    try {
        (void)provider.commit({}, {}, {}, random);
    } catch (const std::runtime_error&) {
        propagated = true;
    }
    require(propagated, "aCom must propagate RandomSource failures");
}

}  // namespace

int main() {
    try {
        test_protocol1_commitment_and_opening();
        test_protocol2_commitment_and_all_fields();
        test_domain_separation_and_field_boundaries();
        test_empty_input_known_hash_and_verification_lengths();
        test_randomness_failure_propagates();
    } catch (const std::exception& error) {
        std::cerr << "SHAKE256 auxiliary commitment test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
