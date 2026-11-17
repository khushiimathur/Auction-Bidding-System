#pragma once

#include "lattice_lrs/commitment/commitment.hpp"
#include "lattice_lrs/proofs/protocol2_proof.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace lattice_lrs::ring_signature {

using ChallengeSet = std::vector<arithmetic::Polynomial>;
using ChallengeVector = std::vector<arithmetic::Polynomial>;

class HashToChallenges {
public:
    virtual ~HashToChallenges() = default;

    virtual ChallengeVector hash(
        const std::vector<std::uint8_t>& input,
        const ChallengeSet& challenge_set,
        std::size_t output_count) const = 0;
};

struct SetupParameters {
    commitment::Parameters commitment;
    std::size_t hash_output_count;

    void validate() const;
};

class PublicParameters;

PublicParameters RSetup(
    const SetupParameters& parameters,
    std::shared_ptr<const HashToChallenges> hash_to_challenges,
    sampling::RandomSource& random);

class PublicParameters {
public:
    const commitment::CommitmentKey& commitment_key() const noexcept {
        return commitment_key_;
    }
    const ChallengeSet& challenge_set() const noexcept { return challenge_set_; }
    std::size_t hash_output_count() const noexcept { return hash_output_count_; }

    ChallengeVector hash_to_challenges(
        const std::vector<std::uint8_t>& input) const;

    void validate() const;

private:
    PublicParameters(
        commitment::CommitmentKey commitment_key,
        std::size_t hash_output_count,
        std::shared_ptr<const HashToChallenges> hash_to_challenges);

    commitment::CommitmentKey commitment_key_;
    ChallengeSet challenge_set_;
    std::size_t hash_output_count_;
    std::shared_ptr<const HashToChallenges> hash_to_challenges_;

    friend PublicParameters RSetup(
        const SetupParameters&,
        std::shared_ptr<const HashToChallenges>,
        sampling::RandomSource&);
};

struct PublicKey {
    sampling::PolynomialVector commitment;
};

struct SecretKey {
    sampling::PolynomialVector randomness;
};

struct KeyPair {
    PublicKey public_key;
    SecretKey secret_key;
};

KeyPair RKeygen(const PublicParameters& public_parameters,
                sampling::RandomSource& random);

class RSignTranscriptEncoder {
public:
    virtual ~RSignTranscriptEncoder() = default;
    virtual std::vector<std::uint8_t> encode(
        const commitment::CommitmentKey& key,
        const std::vector<std::uint8_t>& message,
        const proofs::Protocol2PublicList& ring,
        const std::vector<proofs::Protocol2FirstMessage>& first_messages) const = 0;
};

enum class RSignRejectionStage {
    f_vector,
    response_vector,
};

struct RSignBatchRejectionParameters {
    RSignRejectionStage stage;
    std::size_t repetitions;
    std::size_t k;
    std::size_t beta;
    std::size_t m;
    std::size_t d;
    NTL::ZZ B;
    NTL::ZZ K_squared;
    NTL::ZZ target_s_squared_numerator;
    NTL::ZZ target_s_squared_denominator;
};

class RSignBatchRejectionProvider {
public:
    virtual ~RSignBatchRejectionProvider() = default;
    virtual bool supports_section6_rejection() const noexcept = 0;
    virtual bool accept(
        const std::vector<NTL::ZZ>& values,
        const std::vector<NTL::ZZ>& center,
        const RSignBatchRejectionParameters& parameters,
        sampling::RandomSource& random) = 0;
};

class UnsupportedRSignConfiguration : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct RSignSignature {
    std::vector<proofs::Protocol2FirstMessage> first_messages;
    ChallengeVector challenges;
    std::vector<proofs::Protocol2Response> responses;
};

// Returns the least r such that (2*d/max(2,k))^r >= 2^lambda.
std::size_t ComputeRSignRepetitionCount(
    std::size_t security_parameter_lambda,
    std::size_t degree,
    std::size_t k);

// Orchestrates the complete Section 6 retry loop. Gaussian and rejection
// providers must explicitly affirm support for the Section 6 distributions.
// The encoding and provider contracts remain caller-supplied; this function
// does not claim their cryptographic properties.
RSignSignature RSign(
    const PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    const proofs::Protocol2Witness& witness,
    const std::vector<std::uint8_t>& message,
    const RSignTranscriptEncoder& transcript_encoder,
    proofs::Protocol2RSignGaussianProvider& gaussian,
    proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    RSignBatchRejectionProvider& rejection,
    sampling::RandomSource& random);

bool RVerify(
    const PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    const std::vector<std::uint8_t>& message,
    const RSignSignature& signature,
    const RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

}  // namespace lattice_lrs::ring_signature
