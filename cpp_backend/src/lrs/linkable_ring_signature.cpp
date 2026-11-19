#include "lattice_lrs/lrs/linkable_ring_signature.hpp"

#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace lattice_lrs::lrs {
namespace {

using ring_signature::ChallengeVector;
using ring_signature::PublicParameters;
using ring_signature::RSignBatchRejectionProvider;
using ring_signature::RSignSignature;
using ring_signature::RSignTranscriptEncoder;
using proofs::Protocol2AuxiliaryCommitmentProvider;
using proofs::Protocol2FirstMessage;
using proofs::Protocol2Parameters;
using proofs::Protocol2PublicList;
using proofs::Protocol2Response;
using proofs::Protocol2RSignGaussianProvider;
using sampling::PolynomialVector;

// Domain-separated from H' (lrs::HashOvkToPublicKeySpace, "PQ-LRS/WCM/
// Hprime/..."), from the Fiat-Shamir challenge hash
// (ring_signature::Shake256CToChallenges), and from the aCom hashes
// (proofs::Shake256AuxiliaryCommitmentProvider). This encodes exactly the
// WCM Section 3.1 OTS message (\hat{sigma}, T, ovk_s); the resulting bytes
// are handed to Dilithium's own signing/verification, which performs its
// own hashing internally -- this is not itself a hash, just an unambiguous
// serialization.
constexpr std::string_view kOtsPayloadDomain = "PQ-LRS/WCM/OTSPayload/v1";

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max()) {
            throw std::length_error("OTS payload encoding length exceeds uint64");
        }
    }
    append_u64(output, static_cast<std::uint64_t>(value));
}

void append_bytes(std::vector<std::uint8_t>& output, const std::uint8_t* bytes,
                  std::size_t length) {
    append_size(output, length);
    if (length != 0) output.insert(output.end(), bytes, bytes + length);
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& bytes) {
    append_bytes(output, bytes.data(), bytes.size());
}

void append_text(std::vector<std::uint8_t>& output, std::string_view text) {
    append_bytes(output, reinterpret_cast<const std::uint8_t*>(text.data()),
                text.size());
}

void append_integer(std::vector<std::uint8_t>& output, const NTL::ZZ& value) {
    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << value;
    if (!stream) throw std::runtime_error("failed to encode OTS payload integer");
    append_text(output, stream.str());
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
    for (const arithmetic::Polynomial& value : values) {
        append_polynomial(output, value);
    }
}

void append_ovk(std::vector<std::uint8_t>& output,
                const ots::DilithiumPublicKey& ovk) {
    append_bytes(output, ovk.bytes.data(), ovk.bytes.size());
}

void append_first_message(std::vector<std::uint8_t>& output,
                          const Protocol2FirstMessage& first_message) {
    append_polynomial_vector(output, first_message.A);
    append_polynomial_vector(output, first_message.B);
    append_polynomial_vector(output, first_message.C);
    append_polynomial_vector(output, first_message.D);
    append_size(output, first_message.E.size());
    for (const PolynomialVector& value : first_message.E) {
        append_polynomial_vector(output, value);
    }
    append_bytes(output, first_message.auxiliary_commitment.bytes);
}

void append_response(std::vector<std::uint8_t>& output,
                     const Protocol2Response& response) {
    append_polynomial_vector(output, response.f_nonzero);
    append_bytes(output, response.auxiliary_opening);
    append_polynomial_vector(output, response.z);
    append_polynomial_vector(output, response.z_b);
    append_polynomial_vector(output, response.z_c);
}

void append_base_signature(std::vector<std::uint8_t>& output,
                           const RSignSignature& base_signature) {
    append_size(output, base_signature.first_messages.size());
    for (const Protocol2FirstMessage& first_message :
        base_signature.first_messages) {
        append_first_message(output, first_message);
    }
    append_size(output, base_signature.challenges.size());
    for (const arithmetic::Polynomial& challenge : base_signature.challenges) {
        append_polynomial(output, challenge);
    }
    append_size(output, base_signature.responses.size());
    for (const Protocol2Response& response : base_signature.responses) {
        append_response(output, response);
    }
}

void append_ring(std::vector<std::uint8_t>& output,
                 const Protocol2PublicList& ring) {
    append_size(output, ring.size());
    for (const PolynomialVector& entry : ring) {
        append_polynomial_vector(output, entry);
    }
}

// Encodes exactly (\hat{sigma}, T, ovk) -- WCM Section 3.1's OTS message --
// as an unambiguous, length-prefixed byte string. `ring` here MUST be the
// original published/listed T (the masked pk_i's), never the transformed
// T\hat{}'; both LRSign and LRVerify below are careful to pass the
// untransformed ring to this function.
std::vector<std::uint8_t> encode_ots_payload(
    const RSignSignature& base_signature, const Protocol2PublicList& ring,
    const ots::DilithiumPublicKey& ovk) {
    std::vector<std::uint8_t> output;
    append_text(output, kOtsPayloadDomain);
    append_u64(output, 1);  // format version
    append_base_signature(output, base_signature);
    append_ring(output, ring);
    append_ovk(output, ovk);
    return output;
}

// p\hat{k}'_i = pk_i - H'(ovk)  for every i -- WCM Section 4, applied
// uniformly to every ring entry (Sign and Vrfy use the identical formula;
// only the source of `ovk` differs -- the signer's own ovk_s during Sign,
// the ovk parsed from the signature during Vrfy).
Protocol2PublicList transform_ring(const commitment::Parameters& parameters,
                                   const Protocol2PublicList& ring,
                                   const ots::DilithiumPublicKey& ovk) {
    Protocol2PublicList transformed;
    transformed.reserve(ring.size());
    for (const PolynomialVector& pk_i : ring) {
        transformed.push_back(UnmaskPublicKey(parameters, pk_i, ovk));
    }
    return transformed;
}

LinkableKeyPair keygen_impl(ring_signature::KeyPair base,
                            const commitment::Parameters& parameters) {
    ots::DilithiumKeyPair ots_keys = ots::GenerateKeyPair();
    PolynomialVector linkable_public_key = MaskPublicKey(
        parameters, base.public_key.commitment, ots_keys.public_key);
    LinkableSecretKey secret_key{std::move(base.secret_key),
                                 std::move(ots_keys.secret_key),
                                 ots_keys.public_key};
    return LinkableKeyPair{std::move(linkable_public_key),
                           std::move(secret_key)};
}

// Validates structural inputs BEFORE the caller consumes the one-time key,
// so a rejected call (empty ring, out-of-range index) never marks the OTS
// key as used.
void validate_sign_inputs(const Protocol2PublicList& ring,
                          std::size_t signer_index) {
    if (ring.empty()) {
        throw std::invalid_argument("LRSign ring T must not be empty");
    }
    if (signer_index >= ring.size()) {
        throw std::invalid_argument(
            "LRSign signer_index does not refer to an entry in ring T");
    }
}

LinkableSignature lr_sign_impl(
    const PublicParameters& public_parameters,
    const Protocol2Parameters& proof_parameters,
    const Protocol2PublicList& ring, std::size_t signer_index,
    const LinkableSecretKey& secret_key,
    const std::vector<std::uint8_t>& message,
    const RSignTranscriptEncoder& transcript_encoder,
    Protocol2RSignGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    RSignBatchRejectionProvider& rejection, sampling::RandomSource& random,
    bool allow_test_only) {
    const commitment::Parameters& parameters =
        public_parameters.commitment_key().parameters();
    const Protocol2PublicList transformed_ring =
        transform_ring(parameters, ring, secret_key.ots_public_key);

    proofs::Protocol2Witness witness{signer_index,
                                     secret_key.base_secret_key.randomness};

    RSignSignature base_signature =
        allow_test_only
            ? ring_signature::RSignForTesting(
                  public_parameters, proof_parameters, transformed_ring,
                  witness, message, transcript_encoder, gaussian,
                  auxiliary_commitment, rejection, random)
            : ring_signature::RSign(public_parameters, proof_parameters,
                                    transformed_ring, witness, message,
                                    transcript_encoder, gaussian,
                                    auxiliary_commitment, rejection, random);

    const std::vector<std::uint8_t> ots_payload = encode_ots_payload(
        base_signature, ring, secret_key.ots_public_key);
    ots::DilithiumSignature ots_signature =
        ots::Sign(secret_key.ots_secret_key, ots_payload);

    return LinkableSignature{std::move(base_signature),
                             std::move(ots_signature),
                             secret_key.ots_public_key};
}

bool lr_verify_impl(const PublicParameters& public_parameters,
                    const Protocol2Parameters& proof_parameters,
                    const Protocol2PublicList& ring,
                    const std::vector<std::uint8_t>& message,
                    const LinkableSignature& signature,
                    const RSignTranscriptEncoder& transcript_encoder,
                    const Protocol2AuxiliaryCommitmentProvider&
                        auxiliary_commitment,
                    bool allow_test_only) {
    // Mirrors ring_signature::r_verify_impl's own contract exactly: a
    // TestOnly/production PublicParameters mismatch is a verification
    // outcome (false), not an exception.
    if (public_parameters.is_test_only() != allow_test_only) return false;
    public_parameters.validate();
    const commitment::CommitmentKey& key = public_parameters.commitment_key();
    proof_parameters.validate(key);

    if (ring.empty()) return false;

    try {
        const commitment::Parameters& parameters = key.parameters();
        const Protocol2PublicList transformed_ring =
            transform_ring(parameters, ring, signature.ots_public_key);

        const bool base_signature_valid =
            allow_test_only
                ? ring_signature::RVerifyForTesting(
                      public_parameters, proof_parameters, transformed_ring,
                      message, signature.base_signature, transcript_encoder,
                      auxiliary_commitment)
                : ring_signature::RVerify(
                      public_parameters, proof_parameters, transformed_ring,
                      message, signature.base_signature, transcript_encoder,
                      auxiliary_commitment);
        if (!base_signature_valid) return false;

        const std::vector<std::uint8_t> ots_payload = encode_ots_payload(
            signature.base_signature, ring, signature.ots_public_key);
        return ots::Verify(signature.ots_public_key, ots_payload,
                           signature.ots_signature);
    } catch (const std::exception&) {
        // Any malformed/incompatible shape encountered while reconstructing
        // T\hat{}' or re-encoding the OTS payload is a rejection, not a
        // thrown error -- consistent with "reject malformed, tampered, or
        // inconsistent signatures" rather than crashing the verifier.
        return false;
    }
}

}  // namespace

const LinkableSecretKey& OneTimeOtsKeyGuard::consume_for_signing() {
    bool expected = false;
    if (!consumed_.compare_exchange_strong(expected, true)) {
        throw OneTimeKeyReuseError(
            "OneTimeOtsKeyGuard: this OTS secret key has already been used "
            "to sign once; WCM requires osk to be used at most once, so "
            "reuse is rejected rather than silently signing again");
    }
    return secret_key_;
}

LinkableKeyPair LRKeygen(const PublicParameters& public_parameters,
                         sampling::RandomSource& random) {
    ring_signature::KeyPair base =
        ring_signature::RKeygen(public_parameters, random);
    return keygen_impl(std::move(base),
                       public_parameters.commitment_key().parameters());
}

LinkableKeyPair LRKeygenForTesting(const PublicParameters& public_parameters,
                                   sampling::RandomSource& random) {
    ring_signature::KeyPair base =
        ring_signature::RKeygenForTesting(public_parameters, random);
    return keygen_impl(std::move(base),
                       public_parameters.commitment_key().parameters());
}

LinkableSignature LRSign(
    const PublicParameters& public_parameters,
    const Protocol2Parameters& proof_parameters,
    const Protocol2PublicList& ring, std::size_t signer_index,
    OneTimeOtsKeyGuard& signer_key_guard,
    const std::vector<std::uint8_t>& message,
    const RSignTranscriptEncoder& transcript_encoder,
    Protocol2RSignGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    RSignBatchRejectionProvider& rejection, sampling::RandomSource& random) {
    validate_sign_inputs(ring, signer_index);
    // Consume the one-time key BEFORE doing any further work, so a reuse
    // attempt (including a racing concurrent call) fails fast and never
    // reaches RS.Sign or OTS.Sign with the same osk twice.
    const LinkableSecretKey& secret_key =
        signer_key_guard.consume_for_signing();
    return lr_sign_impl(public_parameters, proof_parameters, ring,
                        signer_index, secret_key, message,
                        transcript_encoder, gaussian, auxiliary_commitment,
                        rejection, random, false);
}

LinkableSignature LRSignForTesting(
    const PublicParameters& public_parameters,
    const Protocol2Parameters& proof_parameters,
    const Protocol2PublicList& ring, std::size_t signer_index,
    OneTimeOtsKeyGuard& signer_key_guard,
    const std::vector<std::uint8_t>& message,
    const RSignTranscriptEncoder& transcript_encoder,
    Protocol2RSignGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    RSignBatchRejectionProvider& rejection, sampling::RandomSource& random) {
    validate_sign_inputs(ring, signer_index);
    const LinkableSecretKey& secret_key =
        signer_key_guard.consume_for_signing();
    return lr_sign_impl(public_parameters, proof_parameters, ring,
                        signer_index, secret_key, message,
                        transcript_encoder, gaussian, auxiliary_commitment,
                        rejection, random, true);
}

bool LRVerify(const PublicParameters& public_parameters,
             const Protocol2Parameters& proof_parameters,
             const Protocol2PublicList& ring,
             const std::vector<std::uint8_t>& message,
             const LinkableSignature& signature,
             const RSignTranscriptEncoder& transcript_encoder,
             const Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    return lr_verify_impl(public_parameters, proof_parameters, ring, message,
                          signature, transcript_encoder, auxiliary_commitment,
                          false);
}

bool LRVerifyForTesting(
    const PublicParameters& public_parameters,
    const Protocol2Parameters& proof_parameters,
    const Protocol2PublicList& ring, const std::vector<std::uint8_t>& message,
    const LinkableSignature& signature,
    const RSignTranscriptEncoder& transcript_encoder,
    const Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    return lr_verify_impl(public_parameters, proof_parameters, ring, message,
                          signature, transcript_encoder, auxiliary_commitment,
                          true);
}

}  // namespace lattice_lrs::lrs
