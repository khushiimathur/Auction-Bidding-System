#include "lattice_lrs/demo/playground_session.hpp"

#include "lattice_lrs/demo/demo_parameters.hpp"

extern "C" {
#include "fips202.h"
}

#include <sstream>
#include <stdexcept>

namespace lattice_lrs::demo {
namespace {

using lattice_lrs::ring_signature::PublicParameters;
using lattice_lrs::ring_signature::RSetupForTesting;
using lattice_lrs::ring_signature::Shake256CToChallenges;
using lattice_lrs::ring_signature::TestOnlySetupParameters;

std::string to_hex(const std::uint8_t* bytes, std::size_t length) {
    static const char* kDigits = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(kDigits[bytes[i] >> 4]);
        result.push_back(kDigits[bytes[i] & 0x0F]);
    }
    return result;
}

std::string shake256_hex(const std::vector<std::uint8_t>& input,
                         std::size_t output_bytes) {
    std::vector<std::uint8_t> digest(output_bytes);
    shake256(digest.data(), digest.size(), input.data(), input.size());
    return to_hex(digest.data(), digest.size());
}

std::string ovk_fingerprint(const ots::DilithiumPublicKey& ovk) {
    const std::vector<std::uint8_t> bytes(ovk.bytes.begin(), ovk.bytes.end());
    return shake256_hex(bytes, 8);
}

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(
            static_cast<std::uint64_t>(value) >> shift));
    }
}

// Mirrors auction::(anonymous namespace)::append_polynomial_vector_for_fingerprint
// exactly -- deterministic, display-only encoding of a public key's
// polynomial vector, not part of any protocol transcript.
std::string pk_fingerprint(const sampling::PolynomialVector& key) {
    std::vector<std::uint8_t> encoded;
    append_size(encoded, key.size());
    for (const arithmetic::Polynomial& polynomial : key) {
        append_size(encoded, polynomial.degree());
        for (const NTL::ZZ& coefficient : polynomial.coefficients()) {
            std::ostringstream text;
            text << coefficient;
            const std::string digits = text.str();
            append_size(encoded, digits.size());
            encoded.insert(encoded.end(), digits.begin(), digits.end());
        }
    }
    return shake256_hex(encoded, 8);
}

std::vector<std::uint8_t> flipped(std::vector<std::uint8_t> bytes) {
    if (bytes.empty()) {
        bytes.push_back(0x01);
    } else {
        bytes[0] ^= 0x01;
    }
    return bytes;
}

lrs::LinkableSignature with_tampered_signature(
    const lrs::LinkableSignature& original) {
    lrs::LinkableSignature tampered = original;
    std::vector<NTL::ZZ> coefficients =
        tampered.base_signature.challenges[0].coefficients();
    coefficients[0] += 1;
    tampered.base_signature.challenges[0] = arithmetic::Polynomial(
        tampered.base_signature.challenges[0].degree(),
        tampered.base_signature.challenges[0].modulus(), coefficients);
    return tampered;
}

proofs::Protocol2PublicList with_tampered_ring(
    proofs::Protocol2PublicList ring) {
    if (ring.size() >= 2) {
        std::swap(ring[0], ring[1]);
    }
    return ring;
}

}  // namespace

PlaygroundSession::PlaygroundSession(
    PublicParameters public_parameters, proofs::Protocol2Parameters proof_parameters,
    std::vector<lrs::LinkableKeyPair> keys)
    : public_parameters_(std::move(public_parameters)),
      proof_parameters_(proof_parameters),
      keys_(std::move(keys)),
      transcript_encoder_(),
      auxiliary_commitment_(),
      rejection_exponential_(),
      rejection_(rejection_exponential_),
      gaussian_bundle_() {
    ring_.reserve(keys_.size());
    for (const lrs::LinkableKeyPair& key_pair : keys_) {
        ring_.push_back(key_pair.linkable_public_key);
    }
}

PlaygroundSession PlaygroundSession::Create(sampling::RandomSource& random) {
    TestOnlySetupParameters setup{DemoCommitmentParameters(), 3};
    auto hash_to_challenges = std::make_shared<const Shake256CToChallenges>();
    PublicParameters public_parameters =
        RSetupForTesting(setup, hash_to_challenges, random);

    std::vector<lrs::LinkableKeyPair> keys;
    const std::size_t ring_size = 8;  // DemoProtocol2Parameters(): beta^k = 2^3 = 8
    keys.reserve(ring_size);
    for (std::size_t i = 0; i < ring_size; ++i) {
        keys.push_back(lrs::LRKeygenForTesting(public_parameters, random));
    }

    return PlaygroundSession(std::move(public_parameters), DemoProtocol2Parameters(),
                             std::move(keys));
}

std::vector<std::string> PlaygroundSession::RingFingerprints() const {
    std::vector<std::string> fingerprints;
    fingerprints.reserve(keys_.size());
    for (const lrs::LinkableKeyPair& key_pair : keys_) {
        fingerprints.push_back(pk_fingerprint(key_pair.linkable_public_key));
    }
    return fingerprints;
}

PlaygroundSession::SignOutcome PlaygroundSession::Sign(
    std::size_t signer_index, const std::vector<std::uint8_t>& message,
    sampling::RandomSource& random) {
    if (signer_index >= keys_.size()) {
        throw std::invalid_argument(
            "PlaygroundSession::Sign: signer_index is not a ring member");
    }
    lrs::OneTimeOtsKeyGuard guard(keys_[signer_index].secret_key);
    lrs::LinkableSignature signature = lrs::LRSignForTesting(
        public_parameters_, proof_parameters_, ring_, signer_index, guard, message,
        transcript_encoder_, gaussian_bundle_.provider(), auxiliary_commitment_,
        rejection_, random);

    const std::size_t id = next_signature_id_++;
    const std::string ovk_fp = ovk_fingerprint(signature.ots_public_key);
    const std::string pk_fp =
        pk_fingerprint(keys_[signer_index].linkable_public_key);
    signatures_.emplace(id,
                        SignedRecord{signer_index, message, std::move(signature),
                                    ovk_fp});
    return SignOutcome{id, pk_fp, ovk_fp};
}

const SignedRecord& PlaygroundSession::Get(std::size_t signature_id) const {
    auto iterator = signatures_.find(signature_id);
    if (iterator == signatures_.end()) {
        throw std::invalid_argument(
            "PlaygroundSession: unknown signature id");
    }
    return iterator->second;
}

VerifyResult PlaygroundSession::Verify(std::size_t signature_id,
                                       TamperMode mode) const {
    const SignedRecord& record = Get(signature_id);

    std::vector<std::uint8_t> message = record.message;
    proofs::Protocol2PublicList ring = ring_;
    lrs::LinkableSignature signature = record.signature;
    std::string mode_name = "none";

    switch (mode) {
        case TamperMode::None:
            break;
        case TamperMode::Message:
            message = flipped(message);
            mode_name = "message";
            break;
        case TamperMode::Signature:
            signature = with_tampered_signature(signature);
            mode_name = "signature";
            break;
        case TamperMode::Ring:
            ring = with_tampered_ring(ring);
            mode_name = "ring";
            break;
    }

    const bool accepted = lrs::LRVerifyForTesting(
        public_parameters_, proof_parameters_, ring, message, signature,
        transcript_encoder_, auxiliary_commitment_);
    return VerifyResult{accepted, mode_name};
}

lrs::LinkOutcome PlaygroundSession::Link(std::size_t signature_id_a,
                                        std::size_t signature_id_b) const {
    const SignedRecord& a = Get(signature_id_a);
    const SignedRecord& b = Get(signature_id_b);
    return lrs::LinkForTesting(public_parameters_, proof_parameters_, ring_,
                              a.message, a.signature, ring_, b.message,
                              b.signature, transcript_encoder_,
                              auxiliary_commitment_);
}

}  // namespace lattice_lrs::demo
