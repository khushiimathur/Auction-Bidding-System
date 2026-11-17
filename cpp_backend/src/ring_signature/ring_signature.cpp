#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include "lattice_lrs/proofs/binary_proof.hpp"
#include "lattice_lrs/sampling/sampler.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace lattice_lrs::ring_signature {
namespace {

std::size_t challenge_set_size(std::size_t degree) {
    if (degree > std::numeric_limits<std::size_t>::max() / 2) {
        throw std::length_error("challenge set size overflows size_t");
    }
    return 2 * degree;
}

std::size_t checked_product(std::size_t left, std::size_t right) {
    if (right != 0 && left > std::numeric_limits<std::size_t>::max() / right) {
        throw std::length_error("RSign vector dimension overflows size_t");
    }
    return left * right;
}

NTL::ZZ zz(std::size_t value) {
    if (value > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        throw std::length_error("RSign dimension exceeds NTL's index range");
    }
    return NTL::to_ZZ(static_cast<long>(value));
}

std::size_t checked_ring_size(std::size_t k, std::size_t beta) {
    std::size_t result = 1;
    for (std::size_t i = 0; i < k; ++i) {
        result = checked_product(result, beta);
    }
    return result;
}

NTL::ZZ norm_squared(const std::vector<NTL::ZZ>& values) {
    NTL::ZZ result(0);
    for (const NTL::ZZ& value : values) result += value * value;
    return result;
}

void append(std::vector<NTL::ZZ>& destination,
            const std::vector<NTL::ZZ>& source) {
    if (destination.size() >
        std::numeric_limits<std::size_t>::max() - source.size()) {
        throw std::length_error("RSign concatenated vector overflows size_t");
    }
    destination.insert(destination.end(), source.begin(), source.end());
}

void validate_ring_signature_parameters(
    const commitment::Parameters& commitment_parameters,
    std::size_t hash_output_count) {
    commitment_parameters.validate();
    if (hash_output_count == 0) {
        throw std::invalid_argument("hash-to-challenges output count must be positive");
    }
    if (commitment_parameters.q <= 2 * commitment_parameters.B) {
        throw std::invalid_argument(
            "modulus q must be greater than 2B for unambiguous S_B coefficients");
    }
    (void)challenge_set_size(commitment_parameters.degree);
}

ChallengeSet make_challenge_set(
    const commitment::Parameters& commitment_parameters) {
    const std::size_t count = challenge_set_size(commitment_parameters.degree);
    ChallengeSet result;
    result.reserve(count);
    for (std::size_t exponent = 0; exponent < count; ++exponent) {
        result.push_back(
            proofs::BinaryChallengeFromExponent(commitment_parameters, exponent));
    }
    return result;
}

}  // namespace

void SetupParameters::validate() const {
    validate_ring_signature_parameters(commitment, hash_output_count);
}

PublicParameters::PublicParameters(
    commitment::CommitmentKey commitment_key,
    std::size_t hash_output_count,
    std::shared_ptr<const HashToChallenges> hash_to_challenges)
    : commitment_key_(std::move(commitment_key)),
      challenge_set_(make_challenge_set(commitment_key_.parameters())),
      hash_output_count_(hash_output_count),
      hash_to_challenges_(std::move(hash_to_challenges)) {}

void PublicParameters::validate() const {
    const commitment::Parameters& parameters = commitment_key_.parameters();
    validate_ring_signature_parameters(parameters, hash_output_count_);
    if (!hash_to_challenges_) {
        throw std::invalid_argument("hash-to-challenges provider must not be null");
    }
    const ChallengeSet expected = make_challenge_set(parameters);
    if (challenge_set_ != expected) {
        throw std::invalid_argument(
            "public challenge set is incompatible with the commitment key ring");
    }
}

ChallengeVector PublicParameters::hash_to_challenges(
    const std::vector<std::uint8_t>& input) const {
    validate();
    ChallengeVector result = hash_to_challenges_->hash(
        input, challenge_set_, hash_output_count_);
    if (result.size() != hash_output_count_ ||
        std::any_of(result.begin(), result.end(), [this](const auto& challenge) {
            return std::find(challenge_set_.begin(), challenge_set_.end(),
                             challenge) == challenge_set_.end();
        })) {
        throw std::runtime_error(
            "hash-to-challenges provider returned an invalid challenge vector");
    }
    return result;
}

PublicParameters RSetup(
    const SetupParameters& parameters,
    std::shared_ptr<const HashToChallenges> hash_to_challenges,
    sampling::RandomSource& random) {
    parameters.validate();
    if (!hash_to_challenges) {
        throw std::invalid_argument("hash-to-challenges provider must not be null");
    }

    commitment::CommitmentKey key =
        commitment::CKeygen(parameters.commitment, random);
    PublicParameters result(std::move(key), parameters.hash_output_count,
                            std::move(hash_to_challenges));
    result.validate();
    return result;
}

KeyPair RKeygen(const PublicParameters& public_parameters,
                sampling::RandomSource& random) {
    public_parameters.validate();
    const commitment::Parameters& parameters =
        public_parameters.commitment_key().parameters();

    sampling::PolynomialVector randomness = sampling::sample_bounded_vector(
        parameters.m, parameters.degree, parameters.q, parameters.B, random);
    const arithmetic::Polynomial zero(parameters.degree, parameters.q);
    const sampling::PolynomialVector zero_message(parameters.v, zero);
    sampling::PolynomialVector public_commitment = commitment::Com(
        public_parameters.commitment_key(), zero_message, randomness);

    return KeyPair{PublicKey{std::move(public_commitment)},
                   SecretKey{std::move(randomness)}};
}

std::size_t ComputeRSignRepetitionCount(
    std::size_t security_parameter_lambda,
    std::size_t degree,
    std::size_t k) {
    if (security_parameter_lambda == 0 || degree < 2 || k == 0) {
        throw std::invalid_argument(
            "RSign lambda and k must be positive and degree must exceed one");
    }
    const std::size_t k_prime = std::max(std::size_t{2}, k);
    const NTL::ZZ two_degree = 2 * zz(degree);
    const NTL::ZZ k_prime_zz = zz(k_prime);
    if (k_prime_zz >= two_degree) {
        throw std::invalid_argument(
            "RSign requires max(2,k) to be smaller than 2*degree");
    }

    NTL::ZZ numerator(1);
    for (std::size_t i = 0; i < security_parameter_lambda; ++i) {
        numerator *= 2;
    }
    NTL::ZZ denominator(1);
    std::size_t repetitions = 0;
    while (numerator > denominator) {
        if (repetitions == std::numeric_limits<std::size_t>::max()) {
            throw std::length_error("RSign repetition count overflows size_t");
        }
        numerator *= k_prime_zz;
        denominator *= two_degree;
        ++repetitions;
    }
    return repetitions;
}

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
    sampling::RandomSource& random) {
    public_parameters.validate();
    const commitment::CommitmentKey& key = public_parameters.commitment_key();
    const commitment::Parameters& p = key.parameters();
    proof_parameters.validate(key);
    if (!gaussian.supports_section6_distributions()) {
        throw UnsupportedRSignConfiguration(
            "RSign Gaussian provider does not support the Section 6 distributions");
    }
    if (!rejection.supports_section6_rejection()) {
        throw UnsupportedRSignConfiguration(
            "RSign rejection provider does not support Section 6 parameters");
    }

    const std::size_t repetitions = public_parameters.hash_output_count();
    const std::size_t expected_ring_size =
        checked_ring_size(proof_parameters.k, proof_parameters.beta);
    if (ring.size() != expected_ring_size ||
        witness.index >= expected_ring_size) {
        throw std::invalid_argument("RSign ring size or witness index is invalid");
    }
    const std::size_t f_per_run = checked_product(
        checked_product(proof_parameters.k, proof_parameters.beta - 1),
        p.degree);
    const std::size_t f_dimension = checked_product(repetitions, f_per_run);
    const std::size_t md = checked_product(p.m, p.degree);
    const std::size_t response_dimension =
        checked_product(checked_product(repetitions, 3), md);
    const NTL::ZZ k_squared_f =
        zz(proof_parameters.k) * zz(repetitions);
    const NTL::ZZ k_squared_z =
        3 * p.B * p.B * zz(p.m) * zz(p.degree) * zz(repetitions);
    const NTL::ZZ target_f_squared =
        144 * zz(p.degree) * zz(p.degree) * k_squared_f;
    const NTL::ZZ target_z_squared =
        144 * p.B * p.B * 3 * zz(p.m) * zz(p.degree) * zz(repetitions);

    while (true) {
        std::vector<proofs::Protocol2FirstMessage> first_messages;
        std::vector<proofs::Protocol2ProverState> states;
        first_messages.reserve(repetitions);
        states.reserve(repetitions);
        for (std::size_t run = 0; run < repetitions; ++run) {
            proofs::Protocol2ProofBeginResult started =
                proofs::BeginProtocol2ProofForRSign(
                    key, proof_parameters, ring, witness, run, repetitions,
                    random, gaussian, auxiliary_commitment);
            first_messages.push_back(std::move(started.first_message));
            states.push_back(std::move(started.state));
        }

        const std::vector<std::uint8_t> transcript =
            transcript_encoder.encode(key, message, ring, first_messages);
        ChallengeVector challenges =
            public_parameters.hash_to_challenges(transcript);

        std::vector<NTL::ZZ> f_values;
        std::vector<NTL::ZZ> f_center;
        f_values.reserve(f_dimension);
        f_center.reserve(f_dimension);
        std::vector<proofs::Protocol2FirstStageLiftResponse> first_stage;
        first_stage.reserve(repetitions);
        for (std::size_t run = 0; run < repetitions; ++run) {
            first_stage.push_back(
                proofs::ComputeProtocol2FirstStageLiftResponse(
                    states[run], key, proof_parameters, challenges[run]));
            append(f_values, first_stage.back().f_nonzero_lift);
            append(f_center, first_stage.back().center_f_lift);
        }
        if (f_values.size() != f_dimension ||
            f_center.size() != f_dimension ||
            norm_squared(f_center) > k_squared_f) {
            throw std::logic_error("RSign f-vector construction violated its bounds");
        }
        const RSignBatchRejectionParameters f_rejection_parameters{
            RSignRejectionStage::f_vector,
            repetitions,
            proof_parameters.k,
            proof_parameters.beta,
            p.m,
            p.degree,
            p.B,
            k_squared_f,
            target_f_squared,
            NTL::ZZ(1)};
        if (!rejection.accept(f_values, f_center, f_rejection_parameters,
                             random)) {
            continue;
        }

        std::vector<proofs::Protocol2ResponseLiftData> response_lifts;
        response_lifts.reserve(repetitions);
        std::vector<NTL::ZZ> response_values;
        std::vector<NTL::ZZ> response_center;
        response_values.reserve(response_dimension);
        response_center.reserve(response_dimension);
        for (std::size_t run = 0; run < repetitions; ++run) {
            response_lifts.push_back(
                proofs::ComputeProtocol2ResponseLiftData(
                    states[run], key, proof_parameters, challenges[run]));
            const auto& lifts = response_lifts.back();
            append(response_values, lifts.responses.z_lift);
            append(response_values, lifts.responses.z_b_lift);
            append(response_values, lifts.responses.z_c_lift);
            append(response_center, lifts.center_z_lift);
            append(response_center, lifts.center_z_b_lift);
            append(response_center, lifts.center_z_c_lift);
        }
        if (response_values.size() != response_dimension ||
            response_center.size() != response_dimension ||
            norm_squared(response_center) > k_squared_z) {
            throw std::logic_error(
                "RSign response-vector construction violated its bounds");
        }
        const RSignBatchRejectionParameters response_rejection_parameters{
            RSignRejectionStage::response_vector,
            repetitions,
            proof_parameters.k,
            proof_parameters.beta,
            p.m,
            p.degree,
            p.B,
            k_squared_z,
            target_z_squared,
            NTL::ZZ(1)};
        if (!rejection.accept(response_values, response_center,
                             response_rejection_parameters, random)) {
            continue;
        }

        std::vector<proofs::Protocol2Response> responses;
        responses.reserve(repetitions);
        for (std::size_t run = 0; run < repetitions; ++run) {
            responses.push_back(proofs::EncodeProtocol2Response(
                first_stage[run], std::move(response_lifts[run]), key,
                proof_parameters));
        }
        return RSignSignature{
            std::move(first_messages), std::move(challenges),
            std::move(responses)};
    }
}

bool RVerify(
    const PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring,
    const std::vector<std::uint8_t>& message,
    const RSignSignature& signature,
    const RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    public_parameters.validate();
    const commitment::CommitmentKey& key = public_parameters.commitment_key();
    proof_parameters.validate(key);
    const std::size_t repetitions = public_parameters.hash_output_count();
    if (signature.first_messages.size() != repetitions ||
        signature.challenges.size() != repetitions ||
        signature.responses.size() != repetitions) {
        return false;
    }
    const std::vector<std::uint8_t> transcript =
        transcript_encoder.encode(key, message, ring, signature.first_messages);
    const ChallengeVector expected =
        public_parameters.hash_to_challenges(transcript);
    if (signature.challenges != expected) return false;
    for (std::size_t run = 0; run < repetitions; ++run) {
        if (!proofs::VerifyProtocol2Proof(
                key, proof_parameters, ring, signature.first_messages[run],
                signature.challenges[run], signature.responses[run],
                auxiliary_commitment)) {
            return false;
        }
    }
    return true;
}

}  // namespace lattice_lrs::ring_signature
