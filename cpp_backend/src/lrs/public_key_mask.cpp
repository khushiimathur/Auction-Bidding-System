#include "lattice_lrs/lrs/public_key_mask.hpp"

extern "C" {
#include "fips202.h"
}

#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace lattice_lrs::lrs {
namespace {

using sampling::PolynomialVector;

// Domain-separated from the Fiat-Shamir challenge hash
// (ring_signature::Shake256CToChallenges, domain implied by
// CanonicalRSignTranscriptEncoder) and from the aCom hashes
// (proofs::Shake256AuxiliaryCommitmentProvider, "PQ-LRS/aCom/..."). This is
// H' from WCM Section 4, not H.
constexpr std::string_view kHPrimeDomain = "PQ-LRS/WCM/Hprime/PkMask/v1";

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::length_error("H' encoding length exceeds uint64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_bytes(std::vector<std::uint8_t>& output, const std::uint8_t* bytes,
                  std::size_t length) {
    append_size(output, length);
    if (length != 0) output.insert(output.end(), bytes, bytes + length);
}

void append_text(std::vector<std::uint8_t>& output, std::string_view text) {
    append_bytes(output, reinterpret_cast<const std::uint8_t*>(text.data()),
                text.size());
}

void append_integer(std::vector<std::uint8_t>& output, const NTL::ZZ& value) {
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << value;
    if (!stream) throw std::runtime_error("failed to encode H' integer");
    append_text(output, stream.str());
}

// Unambiguous, length-prefixed encoding of (domain, format version,
// commitment parameters, ovk bytes). Length-prefixing every variable-length
// field (including the trailing ovk byte string) prevents the classic
// concatenation ambiguity (e.g. distinguishing "ab"+"c" from "a"+"bc").
std::vector<std::uint8_t> encode_hash_input(
    const commitment::Parameters& parameters,
    const ots::DilithiumPublicKey& ovk) {
    std::vector<std::uint8_t> output;
    append_text(output, kHPrimeDomain);
    append_u64(output, 1);  // format version
    append_size(output, parameters.n);
    append_size(output, parameters.degree);
    append_integer(output, parameters.q);
    append_bytes(output, ovk.bytes.data(), ovk.bytes.size());
    return output;
}

// Deterministic byte source backed by a single SHAKE256 XOF stream: absorb
// once, then squeeze on demand. Squeeze calls are cumulative (each call
// continues the same stream), which is exactly what the existing
// rejection-sampling coefficient/vector samplers in sampler.cpp need to
// stay unbiased while consuming a variable number of bytes per coefficient.
class Shake256XofRandomSource final : public sampling::RandomSource {
public:
    explicit Shake256XofRandomSource(const std::vector<std::uint8_t>& input) {
        shake256_absorb_once(&state_, input.data(), input.size());
    }

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        if (length == 0) return;
        shake256_squeeze(output, length, &state_);
    }

private:
    keccak_state state_{};
};

void require_vector_shape(const commitment::Parameters& parameters,
                          const PolynomialVector& vector,
                          const char* label) {
    if (vector.size() != parameters.n) {
        throw std::invalid_argument(
            std::string(label) +
            " length does not match the commitment parameters' n");
    }
    for (const arithmetic::Polynomial& polynomial : vector) {
        if (polynomial.degree() != parameters.degree) {
            throw std::invalid_argument(
                std::string(label) +
                " polynomial degree does not match the commitment "
                "parameters' degree");
        }
        if (polynomial.modulus() != parameters.q) {
            throw std::invalid_argument(
                std::string(label) +
                " polynomial modulus does not match the commitment "
                "parameters' q");
        }
    }
}

PolynomialVector add_vectors(const PolynomialVector& left,
                             const PolynomialVector& right) {
    // Polynomial::operator+ itself rejects mismatched degree/modulus, but
    // the length check must happen first or we read out of bounds.
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "cannot combine public-key vectors of different lengths");
    }
    PolynomialVector result;
    result.reserve(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        result.push_back(left[i] + right[i]);
    }
    return result;
}

PolynomialVector subtract_vectors(const PolynomialVector& left,
                                  const PolynomialVector& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument(
            "cannot combine public-key vectors of different lengths");
    }
    PolynomialVector result;
    result.reserve(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        result.push_back(left[i] - right[i]);
    }
    return result;
}

}  // namespace

PolynomialVector HashOvkToPublicKeySpace(
    const commitment::Parameters& parameters,
    const ots::DilithiumPublicKey& ovk) {
    parameters.validate();
    const std::vector<std::uint8_t> encoded = encode_hash_input(parameters, ovk);
    Shake256XofRandomSource xof(encoded);
    // Unbiased: sample_uniform_vector -> sample_uniform_polynomial ->
    // sample_uniform_coefficient performs rejection sampling against q
    // (sampler.cpp), not a modulo reduction, so it introduces no bias even
    // when q is not a power of two.
    return sampling::sample_uniform_vector(parameters.n, parameters.degree,
                                           parameters.q, xof);
}

PolynomialVector MaskPublicKey(const commitment::Parameters& parameters,
                               const PolynomialVector& base_public_key,
                               const ots::DilithiumPublicKey& ovk) {
    parameters.validate();
    require_vector_shape(parameters, base_public_key, "base public key");
    const PolynomialVector mask = HashOvkToPublicKeySpace(parameters, ovk);
    return add_vectors(base_public_key, mask);
}

PolynomialVector UnmaskPublicKey(const commitment::Parameters& parameters,
                                 const PolynomialVector& masked_public_key,
                                 const ots::DilithiumPublicKey& ovk) {
    parameters.validate();
    require_vector_shape(parameters, masked_public_key, "masked public key");
    const PolynomialVector mask = HashOvkToPublicKeySpace(parameters, ovk);
    return subtract_vectors(masked_public_key, mask);
}

}  // namespace lattice_lrs::lrs
