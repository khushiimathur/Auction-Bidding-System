#include "lattice_lrs/ring_signature/canonical_rsign_transcript.hpp"

extern "C" {
#include "fips202.h"
}

#include "lattice_lrs/proofs/binary_proof.hpp"

#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace lattice_lrs::ring_signature {
namespace {

using sampling::PolynomialVector;

constexpr std::string_view kTranscriptDomain =
    "PQ-LRS/RSign/Fiat-Shamir/Transcript/v1";
constexpr std::string_view kChallengeDomain =
    "PQ-LRS/RSign/Fiat-Shamir/Challenges/v1";

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::length_error("RSIGN transcript length exceeds uint64");
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_integer(std::vector<std::uint8_t>& output, const NTL::ZZ& value) {
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << value;
    if (!stream) throw std::runtime_error("failed to encode transcript integer");
    const std::string text = stream.str();
    append_size(output, text.size());
    output.insert(output.end(), text.begin(), text.end());
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& bytes) {
    append_size(output, bytes.size());
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_text(std::vector<std::uint8_t>& output, std::string_view text) {
    append_size(output, text.size());
    output.insert(output.end(), text.begin(), text.end());
}

void append_polynomial(std::vector<std::uint8_t>& output,
                       const arithmetic::Polynomial& polynomial,
                       const NTL::ZZ& expected_modulus,
                       std::size_t expected_degree) {
    if (polynomial.degree() != expected_degree ||
        polynomial.modulus() != expected_modulus) {
        throw std::invalid_argument(
            "RSIGN transcript polynomial has incompatible ring parameters");
    }
    append_u64(output, 1);
    append_size(output, polynomial.degree());
    append_integer(output, polynomial.modulus());
    append_size(output, polynomial.coefficients().size());
    for (const NTL::ZZ& coefficient : polynomial.coefficients()) {
        if (coefficient < 0 || coefficient >= polynomial.modulus()) {
            throw std::invalid_argument(
                "RSIGN transcript polynomial is not canonically encoded");
        }
        append_integer(output, coefficient);
    }
}

void append_polynomial_vector(
    std::vector<std::uint8_t>& output, const PolynomialVector& values,
    const commitment::Parameters& parameters, std::size_t expected_length) {
    if (values.size() != expected_length) {
        throw std::invalid_argument(
            "RSIGN transcript polynomial vector has an incompatible length");
    }
    append_size(output, values.size());
    for (const arithmetic::Polynomial& polynomial : values) {
        append_polynomial(output, polynomial, parameters.q, parameters.degree);
    }
}

void append_matrix(std::vector<std::uint8_t>& output,
                   const arithmetic::Matrix& matrix,
                   const commitment::Parameters& parameters,
                   std::size_t rows, std::size_t columns) {
    if (matrix.rows() != rows || matrix.columns() != columns ||
        matrix.degree() != parameters.degree ||
        matrix.modulus() != parameters.q) {
        throw std::invalid_argument(
            "RSIGN transcript commitment matrix has incompatible dimensions");
    }
    append_u64(output, 1);
    append_size(output, matrix.rows());
    append_size(output, matrix.columns());
    append_size(output, matrix.degree());
    append_integer(output, matrix.modulus());
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t column = 0; column < columns; ++column) {
            append_polynomial(output, matrix.at(row, column),
                              parameters.q, parameters.degree);
        }
    }
}

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::uint64_t challenge_words(std::uint64_t word, std::size_t exponent_count) {
    const std::uint64_t mask = static_cast<std::uint64_t>(
        static_cast<std::uint64_t>(exponent_count) - 1);
    return word & mask;
}

}  // namespace

std::vector<std::uint8_t> CanonicalRSignTranscriptEncoder::encode(
    const commitment::CommitmentKey& key,
    const std::vector<std::uint8_t>& message,
    const proofs::Protocol2PublicList& ring,
    const std::vector<proofs::Protocol2FirstMessage>& first_messages)
    const {
    const commitment::Parameters& p = key.parameters();
    p.validate();
    std::vector<std::uint8_t> output;
    append_text(output, kTranscriptDomain);
    append_u64(output, 1);

    append_u64(output, 1);
    append_size(output, p.n);
    append_size(output, p.m);
    append_size(output, p.v);
    append_size(output, p.degree);
    append_integer(output, p.q);
    append_integer(output, p.B);
    append_integer(output, p.T_com_squared.numerator);
    append_integer(output, p.T_com_squared.denominator);
    append_matrix(output, key.G_r(), p, p.n, p.m);
    append_matrix(output, key.G_m(), p, p.n, p.v);
    append_matrix(output, key.G(), p, p.n, p.m + p.v);

    append_u64(output, 2);
    append_bytes(output, message);

    append_u64(output, 3);
    append_size(output, ring.size());
    if (ring.empty()) {
        throw std::invalid_argument(
            "RSIGN transcript ring must not be empty");
    }
    for (const PolynomialVector& entry : ring) {
        append_polynomial_vector(output, entry, p, p.n);
    }

    append_u64(output, 4);
    append_size(output, first_messages.size());
    if (first_messages.empty()) {
        throw std::invalid_argument(
            "RSIGN transcript must contain at least one first message");
    }
    for (const proofs::Protocol2FirstMessage& first : first_messages) {
        append_u64(output, 5);
        append_polynomial_vector(output, first.A, p, p.n);
        append_polynomial_vector(output, first.B, p, p.n);
        append_polynomial_vector(output, first.C, p, p.n);
        append_polynomial_vector(output, first.D, p, p.n);
        append_u64(output, 6);
        append_size(output, first.E.size());
        if (first.E.empty()) {
            throw std::invalid_argument(
                "RSIGN transcript first message must contain E_j values");
        }
        for (const PolynomialVector& value : first.E) {
            append_polynomial_vector(output, value, p, p.n);
        }
        append_u64(output, 7);
        if (first.auxiliary_commitment.bytes.empty()) {
            throw std::invalid_argument(
                "RSIGN transcript auxiliary commitment c_a must not be empty");
        }
        append_bytes(output, first.auxiliary_commitment.bytes);
    }
    return output;
}

ChallengeVector Shake256CToChallenges::hash(
    const std::vector<std::uint8_t>& input,
    const ChallengeSet& challenge_set,
    std::size_t output_count) const {
    if (input.empty()) {
        throw std::invalid_argument(
            "SHAKE256 challenge hash input must not be empty");
    }
    if (challenge_set.size() < 2 || !is_power_of_two(challenge_set.size())) {
        throw std::invalid_argument(
            "C must have power-of-two size 2d");
    }
    if (output_count == 0) {
        throw std::invalid_argument(
            "challenge hash output count must be positive");
    }
    if (output_count > std::numeric_limits<std::size_t>::max() / 8) {
        throw std::length_error("challenge hash expansion is too large");
    }

    const std::size_t degree = challenge_set.front().degree();
    if (degree == 0 || challenge_set.size() != 2 * degree) {
        throw std::invalid_argument(
            "challenge set size must equal 2d");
    }
    for (const arithmetic::Polynomial& challenge : challenge_set) {
        if (challenge.degree() != degree ||
            challenge.modulus() != challenge_set.front().modulus()) {
            throw std::invalid_argument(
                "challenge set has incompatible ring parameters");
        }
    }
    const NTL::ZZ modulus = challenge_set.front().modulus();
    for (std::size_t exponent = 0; exponent < challenge_set.size(); ++exponent) {
        const std::size_t signed_index =
            exponent < degree ? exponent : exponent - degree;
        const NTL::ZZ signed_value =
            exponent < degree ? NTL::ZZ(1) : NTL::ZZ(-1);
        for (std::size_t coefficient = 0;
             coefficient < degree; ++coefficient) {
            const NTL::ZZ expected =
                coefficient == signed_index
                    ? (signed_value == 1 ? NTL::ZZ(1) : modulus - 1)
                    : NTL::ZZ(0);
            if (challenge_set[exponent].coefficient(coefficient) != expected) {
                throw std::invalid_argument(
                    "challenge set does not contain exactly X^omega");
            }
        }
    }

    std::vector<std::uint8_t> encoded;
    append_text(encoded, kChallengeDomain);
    append_u64(encoded, 1);
    append_size(encoded, challenge_set.size());
    append_size(encoded, output_count);
    append_size(encoded, input.size());
    encoded.insert(encoded.end(), input.begin(), input.end());

    std::vector<std::uint8_t> words(output_count * 8);
    shake256(words.data(), words.size(), encoded.data(), encoded.size());

    ChallengeVector result;
    result.reserve(output_count);
    for (std::size_t i = 0; i < output_count; ++i) {
        std::uint64_t word = 0;
        for (int shift = 0; shift < 8; ++shift) {
            word |= static_cast<std::uint64_t>(words[8 * i + shift])
                    << (8 * shift);
        }
        const std::size_t exponent = static_cast<std::size_t>(
            challenge_words(word, challenge_set.size()));
        result.push_back(challenge_set[exponent]);
    }
    return result;
}

}  // namespace lattice_lrs::ring_signature
