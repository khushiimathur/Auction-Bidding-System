#include "lattice_lrs/proofs/shake256_auxiliary_commitment.hpp"

extern "C" {
#include "fips202.h"
}

#include <array>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace lattice_lrs::proofs {
namespace {

using sampling::PolynomialVector;

constexpr std::string_view kProtocol1Domain =
    "PQ-LRS/aCom/Protocol1/v1";
constexpr std::string_view kProtocol2Domain =
    "PQ-LRS/aCom/Protocol2/v1";

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::length_error("aCom encoding length exceeds uint64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::uint8_t* bytes, std::size_t length) {
    append_size(output, length);
    if (length != 0) output.insert(output.end(), bytes, bytes + length);
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& bytes) {
    append_bytes(output, bytes.data(), bytes.size());
}

void append_text(std::vector<std::uint8_t>& output, std::string_view text) {
    append_bytes(output,
                 reinterpret_cast<const std::uint8_t*>(text.data()),
                 text.size());
}

void append_integer(std::vector<std::uint8_t>& output, const NTL::ZZ& value) {
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << value;
    if (!stream) throw std::runtime_error("failed to encode aCom integer");
    const std::string decimal = stream.str();
    append_text(output, decimal);
}

void append_polynomial(std::vector<std::uint8_t>& output,
                       const arithmetic::Polynomial& polynomial) {
    append_size(output, polynomial.degree());
    append_integer(output, polynomial.modulus());
    append_size(output, polynomial.coefficients().size());
    for (const NTL::ZZ& coefficient : polynomial.coefficients()) {
        append_integer(output, coefficient);
    }
}

void append_polynomial_vector(std::vector<std::uint8_t>& output,
                              const PolynomialVector& values) {
    append_size(output, values.size());
    for (const arithmetic::Polynomial& polynomial : values) {
        append_polynomial(output, polynomial);
    }
}

void append_field(std::vector<std::uint8_t>& output, std::uint8_t tag,
                  const PolynomialVector& values) {
    output.push_back(tag);
    append_polynomial_vector(output, values);
}

std::vector<std::uint8_t> encode_protocol1(
    const PolynomialVector& A, const PolynomialVector& C,
    const PolynomialVector& D, const std::vector<std::uint8_t>& opening) {
    std::vector<std::uint8_t> output;
    append_text(output, kProtocol1Domain);
    append_u64(output, 1);
    append_field(output, 1, A);
    append_field(output, 2, C);
    append_field(output, 3, D);
    output.push_back(0xf0);
    append_bytes(output, opening);
    return output;
}

std::vector<std::uint8_t> encode_protocol2(
    const PolynomialVector& A, const PolynomialVector& B,
    const PolynomialVector& C, const PolynomialVector& D,
    const std::vector<PolynomialVector>& E,
    const std::vector<std::uint8_t>& opening) {
    std::vector<std::uint8_t> output;
    append_text(output, kProtocol2Domain);
    append_u64(output, 1);
    append_field(output, 1, A);
    append_field(output, 2, B);
    append_field(output, 3, C);
    append_field(output, 4, D);
    output.push_back(5);
    append_size(output, E.size());
    for (const PolynomialVector& vector : E) {
        append_polynomial_vector(output, vector);
    }
    output.push_back(0xf0);
    append_bytes(output, opening);
    return output;
}

std::vector<std::uint8_t> hash_encoded(
    const std::vector<std::uint8_t>& encoded) {
    std::vector<std::uint8_t> digest(
        Shake256AuxiliaryCommitmentProvider::kDigestSize);
    shake256(digest.data(), digest.size(), encoded.data(), encoded.size());
    return digest;
}

std::vector<std::uint8_t> sample_opening(sampling::RandomSource& random) {
    std::vector<std::uint8_t> opening(
        Shake256AuxiliaryCommitmentProvider::kOpeningSize);
    random.fill_bytes(opening.data(), opening.size());
    return opening;
}

bool constant_time_equal(const std::vector<std::uint8_t>& left,
                         const std::vector<std::uint8_t>& right) {
    if (left.size() != right.size()) return false;
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i) {
        difference = static_cast<std::uint8_t>(difference | (left[i] ^ right[i]));
    }
    return difference == 0;
}

bool valid_lengths(const AuxiliaryCommitmentValue& commitment,
                   const std::vector<std::uint8_t>& opening) {
    return commitment.bytes.size() ==
               Shake256AuxiliaryCommitmentProvider::kDigestSize &&
           opening.size() ==
               Shake256AuxiliaryCommitmentProvider::kOpeningSize;
}

}  // namespace

AuxiliaryCommitmentOpening Shake256AuxiliaryCommitmentProvider::commit(
    const PolynomialVector& A, const PolynomialVector& C,
    const PolynomialVector& D, sampling::RandomSource& random) {
    std::vector<std::uint8_t> opening = sample_opening(random);
    const std::vector<std::uint8_t> encoded =
        encode_protocol1(A, C, D, opening);
    return {AuxiliaryCommitmentValue{hash_encoded(encoded)},
            std::move(opening)};
}

bool Shake256AuxiliaryCommitmentProvider::verify(
    const PolynomialVector& A, const PolynomialVector& C,
    const PolynomialVector& D, const AuxiliaryCommitmentValue& commitment,
    const std::vector<std::uint8_t>& opening) const {
    if (!valid_lengths(commitment, opening)) return false;
    const std::vector<std::uint8_t> encoded =
        encode_protocol1(A, C, D, opening);
    return constant_time_equal(commitment.bytes, hash_encoded(encoded));
}

AuxiliaryCommitmentOpening Shake256AuxiliaryCommitmentProvider::commit(
    const PolynomialVector& A, const PolynomialVector& B,
    const PolynomialVector& C, const PolynomialVector& D,
    const std::vector<PolynomialVector>& E, sampling::RandomSource& random) {
    std::vector<std::uint8_t> opening = sample_opening(random);
    const std::vector<std::uint8_t> encoded =
        encode_protocol2(A, B, C, D, E, opening);
    return {AuxiliaryCommitmentValue{hash_encoded(encoded)},
            std::move(opening)};
}

bool Shake256AuxiliaryCommitmentProvider::verify(
    const PolynomialVector& A, const PolynomialVector& B,
    const PolynomialVector& C, const PolynomialVector& D,
    const std::vector<PolynomialVector>& E,
    const AuxiliaryCommitmentValue& commitment,
    const std::vector<std::uint8_t>& opening) const {
    if (!valid_lengths(commitment, opening)) return false;
    const std::vector<std::uint8_t> encoded =
        encode_protocol2(A, B, C, D, E, opening);
    return constant_time_equal(commitment.bytes, hash_encoded(encoded));
}

}  // namespace lattice_lrs::proofs
