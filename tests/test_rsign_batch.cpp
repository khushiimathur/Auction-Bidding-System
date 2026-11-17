#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include "lattice_lrs/proofs/binary_proof.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lattice_lrs::arithmetic;
using namespace lattice_lrs::commitment;
using namespace lattice_lrs::proofs;
using namespace lattice_lrs::ring_signature;
using namespace lattice_lrs::sampling;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    const std::uint64_t encoded = static_cast<std::uint64_t>(value);
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        output.push_back(static_cast<std::uint8_t>(encoded >> shift));
    }
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& value) {
    append_size(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_integer(std::vector<std::uint8_t>& output, const NTL::ZZ& value) {
    std::ostringstream stream;
    stream << value;
    const std::string text = stream.str();
    append_size(output, text.size());
    output.insert(output.end(), text.begin(), text.end());
}

void append_polynomial(std::vector<std::uint8_t>& output,
                      const Polynomial& polynomial) {
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
    for (const Polynomial& value : values) {
        append_polynomial(output, value);
    }
}

void append_matrix(std::vector<std::uint8_t>& output, const Matrix& matrix) {
    append_size(output, matrix.rows());
    append_size(output, matrix.columns());
    append_size(output, matrix.degree());
    append_integer(output, matrix.modulus());
    for (std::size_t row = 0; row < matrix.rows(); ++row) {
        for (std::size_t column = 0; column < matrix.columns(); ++column) {
            append_polynomial(output, matrix.at(row, column));
        }
    }
}

void change_constant_coefficient(Polynomial& polynomial) {
    std::vector<NTL::ZZ> coefficients = polynomial.coefficients();
    coefficients[0] += 1;
    polynomial = Polynomial(polynomial.degree(), polynomial.modulus(),
                            coefficients);
}

class ZeroByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        std::fill(output, output + length, std::uint8_t(0));
    }
};

class PatternedByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        for (std::size_t i = 0; i < length; ++i) {
            const std::size_t position = calls_++ % 344;
            const std::size_t run = position / 172;
            const bool sampling_r_b = (position % 172) % 2 == 0;
            output[i] = static_cast<std::uint8_t>(
                (run == 0) == sampling_r_b ? 0 : 2);
        }
    }

private:
    std::size_t calls_ = 0;
};

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("simulated entropy failure");
    }
};

class InputDependentHash final : public HashToChallenges {
public:
    ChallengeVector hash(const std::vector<std::uint8_t>& input,
                         const ChallengeSet& challenge_set,
                         std::size_t output_count) const override {
        if (input.empty() || output_count > challenge_set.size()) {
            throw std::invalid_argument("invalid test transcript");
        }
        const auto [entry, inserted] =
            indices.emplace(input, indices.size());
        (void)inserted;
        const std::size_t max_start = challenge_set.size() - output_count;
        const std::size_t start = (5 + entry->second) % (max_start + 1);
        ChallengeVector result;
        result.reserve(output_count);
        for (std::size_t i = 0; i < output_count; ++i) {
            result.push_back(challenge_set[start + i]);
        }
        observed.push_back(result);
        return result;
    }

    mutable std::vector<ChallengeVector> observed;

private:
    mutable std::map<std::vector<std::uint8_t>, std::size_t> indices;
};

class InsecureIdAuxiliaryCommitmentForTesting final
    : public Protocol2AuxiliaryCommitmentProvider {
public:
    AuxiliaryCommitmentOpening commit(
        const PolynomialVector&, const PolynomialVector&,
        const PolynomialVector&, const PolynomialVector&,
        const std::vector<PolynomialVector>&, RandomSource&) override {
        ++next_id;
        const auto id = static_cast<std::uint8_t>(next_id);
        committed_ids.push_back(id);
        return {AuxiliaryCommitmentValue{{id}}, {id}};
    }

    bool verify(
        const PolynomialVector&, const PolynomialVector&,
        const PolynomialVector&, const PolynomialVector&,
        const std::vector<PolynomialVector>&,
        const AuxiliaryCommitmentValue& commitment,
        const std::vector<std::uint8_t>& opening) const override {
        return commitment.bytes.size() == 1 && opening.size() == 1 &&
               commitment.bytes.front() == opening.front();
    }

    std::uint8_t next_id = 0;
    std::vector<std::uint8_t> committed_ids;
};

class RunIndexedGaussian final : public Protocol2RSignGaussianProvider {
public:
    bool supports_section6_distributions() const noexcept override {
        return true;
    }

    NTL::ZZ sample_coefficient(
        Protocol2GaussianSampleKind kind, std::size_t run_index,
        std::size_t repetitions, const CommitmentKey& key,
        const Protocol2Parameters& proof, RandomSource&) override {
        require(repetitions == 2, "Gaussian provider received wrong batch size");
        requests.emplace_back(kind, run_index);
        if (kind == Protocol2GaussianSampleKind::binary_mask) {
            return z(static_cast<long>(run_index));
        }
        const std::size_t md =
            key.parameters().m * key.parameters().degree;
        if (kind == Protocol2GaussianSampleKind::response_mask) {
            const std::size_t local = response_mask_calls_[run_index]++ %
                                      (2 * md);
            return key.parameters().q + z(static_cast<long>(100 * run_index)) +
                   z(local < md ? 1000 : 2000);
        }
        const std::size_t local = rho_calls_[run_index]++ %
                                  (proof.k * md);
        const std::size_t rho_index = local / md;
        return key.parameters().q + z(static_cast<long>(100 * run_index)) +
               z(static_cast<long>(3000 + 500 * rho_index));
    }

    std::vector<std::pair<Protocol2GaussianSampleKind, std::size_t>> requests;

private:
    std::vector<std::size_t> response_mask_calls_ =
        std::vector<std::size_t>(2, 0);
    std::vector<std::size_t> rho_calls_ = std::vector<std::size_t>(2, 0);
};

class ScriptedRejection final : public RSignBatchRejectionProvider {
public:
    explicit ScriptedRejection(std::vector<bool> f_decisions,
                               std::vector<bool> response_decisions)
        : f_decisions_(std::move(f_decisions)),
          response_decisions_(std::move(response_decisions)) {}

    bool supports_section6_rejection() const noexcept override { return true; }

    bool accept(const std::vector<NTL::ZZ>& values,
                const std::vector<NTL::ZZ>& center,
                const RSignBatchRejectionParameters& parameters,
                RandomSource&) override {
        require(values.size() == center.size(),
                "global rejection values and centers must match");
        recorded_stages.push_back(parameters.stage);
        recorded_values.push_back(values);
        recorded_centers.push_back(center);
        recorded_parameters.push_back(parameters);
        if (parameters.stage == RSignRejectionStage::f_vector) {
            require(values.size() == 2 * 2 * 1 * 86,
                    "f vector must use the complete concatenated dimension");
            require(parameters.K_squared == z(4),
                    "f rejection must use K_1^2=kr");
            require(parameters.target_s_squared_numerator == z(144 * 86 * 86 * 4),
                    "f target scale must use the Section 6 batch width");
            require(f_index_ < f_decisions_.size(),
                    "unexpected f rejection invocation");
            return f_decisions_[f_index_++];
        }
        require(values.size() == 3 * 2 * 1 * 86,
                "response vector must contain all three blocks for all runs");
        require(parameters.K_squared == z(3 * 1 * 1 * 86 * 2),
                "response rejection must use K_2^2=3B^2mdr");
        require(parameters.target_s_squared_numerator ==
                    z(144 * 1 * 1 * 3 * 86 * 2),
                "response target scale must use the Section 6 batch width");
        require(response_index_ < response_decisions_.size(),
                "unexpected response rejection invocation");
        return response_decisions_[response_index_++];
    }

    std::vector<RSignRejectionStage> recorded_stages;
    std::vector<std::vector<NTL::ZZ>> recorded_values;
    std::vector<std::vector<NTL::ZZ>> recorded_centers;
    std::vector<RSignBatchRejectionParameters> recorded_parameters;

private:
    std::vector<bool> f_decisions_;
    std::vector<bool> response_decisions_;
    std::size_t f_index_ = 0;
    std::size_t response_index_ = 0;
};

class ThrowingRejection final : public RSignBatchRejectionProvider {
public:
    bool supports_section6_rejection() const noexcept override { return true; }
    bool accept(const std::vector<NTL::ZZ>&, const std::vector<NTL::ZZ>&,
                const RSignBatchRejectionParameters&,
                RandomSource&) override {
        throw std::runtime_error("simulated global rejection failure");
    }
};

class UnsupportedRejection final : public RSignBatchRejectionProvider {
public:
    bool supports_section6_rejection() const noexcept override { return false; }
    bool accept(const std::vector<NTL::ZZ>&, const std::vector<NTL::ZZ>&,
                const RSignBatchRejectionParameters&,
                RandomSource&) override {
        return true;
    }
};

class ThrowingGaussian final : public Protocol2RSignGaussianProvider {
public:
    bool supports_section6_distributions() const noexcept override {
        return true;
    }
    NTL::ZZ sample_coefficient(
        Protocol2GaussianSampleKind, std::size_t, std::size_t,
        const CommitmentKey&, const Protocol2Parameters&,
        RandomSource&) override {
        throw std::runtime_error("simulated Gaussian-provider failure");
    }
};

class RecordingDsSampler final : public DiscreteGaussianSProvider {
public:
    NTL::ZZ sample_coefficient_from_scale_squared(
        const NTL::ZZ& numerator, const NTL::ZZ& denominator,
        RandomSource&) override {
        observed_scale = {numerator, denominator};
        return numerator + denominator;
    }

    std::pair<NTL::ZZ, NTL::ZZ> observed_scale;
};

class FixedScaleProfile final : public Protocol2RSignGaussianScaleProfile {
public:
    bool supports_section6_distributions() const noexcept override {
        return true;
    }
    Protocol2GaussianScaleSquared scale_squared(
        Protocol2GaussianSampleKind requested_kind,
        std::size_t requested_run,
        std::size_t requested_repetitions,
        const CommitmentKey&,
        const Protocol2Parameters&) const override {
        kind = requested_kind;
        run_index = requested_run;
        repetitions = requested_repetitions;
        return {z(7), z(3)};
    }

    mutable Protocol2GaussianSampleKind kind =
        Protocol2GaussianSampleKind::binary_mask;
    mutable std::size_t run_index = 0;
    mutable std::size_t repetitions = 0;
};

class TestEncoder final : public RSignTranscriptEncoder {
public:
    std::vector<std::uint8_t> encode(
        const CommitmentKey&, const std::vector<std::uint8_t>&,
        const Protocol2PublicList&,
        const std::vector<Protocol2FirstMessage>& first_messages) const override {
        std::vector<std::uint8_t> bytes;
        bytes.reserve(first_messages.size());
        for (const auto& first : first_messages) {
            bytes.push_back(first.auxiliary_commitment.bytes.at(0));
        }
        encoded_inputs.push_back(bytes);
        return bytes;
    }

    mutable std::vector<std::vector<std::uint8_t>> encoded_inputs;
};

class BindingAwareEncoder final : public RSignTranscriptEncoder {
public:
    std::vector<std::uint8_t> encode(
        const CommitmentKey& key,
        const std::vector<std::uint8_t>& message,
        const Protocol2PublicList& ring,
        const std::vector<Protocol2FirstMessage>& first_messages) const override {
        std::vector<std::uint8_t> output{'R', 'S', 'I', 'G', 'N', 1};
        const auto& p = key.parameters();
        append_size(output, p.n);
        append_size(output, p.m);
        append_size(output, p.v);
        append_size(output, p.degree);
        append_integer(output, p.q);
        append_integer(output, p.B);
        append_integer(output, p.T_com_squared.numerator);
        append_integer(output, p.T_com_squared.denominator);
        append_matrix(output, key.G_r());
        append_matrix(output, key.G_m());
        append_matrix(output, key.G());
        append_bytes(output, message);

        append_size(output, ring.size());
        for (const PolynomialVector& entry : ring) {
            append_polynomial_vector(output, entry);
        }

        append_size(output, first_messages.size());
        for (const Protocol2FirstMessage& first : first_messages) {
            append_polynomial_vector(output, first.A);
            append_polynomial_vector(output, first.B);
            append_polynomial_vector(output, first.C);
            append_polynomial_vector(output, first.D);
            append_size(output, first.E.size());
            for (const PolynomialVector& value : first.E) {
                append_polynomial_vector(output, value);
            }
            append_bytes(output, first.auxiliary_commitment.bytes);
        }
        return output;
    }
};

struct TestContext {
    std::shared_ptr<InputDependentHash> hash;
    PublicParameters public_parameters;
    Protocol2Parameters proof_parameters;
    Protocol2PublicList ring;
    Protocol2Witness witness;
    TestContext(std::shared_ptr<InputDependentHash> h, PublicParameters pp,
                Protocol2Parameters p, Protocol2PublicList r,
                Protocol2Witness w)
        : hash(std::move(h)), public_parameters(std::move(pp)),
          proof_parameters(std::move(p)), ring(std::move(r)),
          witness(std::move(w)) {}
};

TestContext make_context(ZeroByteSource& random) {
    const std::size_t degree = 86;
    TestOnlySetupParameters setup{
        Parameters{1, 1, 4, degree, z(1000000007), z(1),
                   SquaredNormBound(z(1) << 256, z(1))},
        2};
    auto hash = std::make_shared<InputDependentHash>();
    PublicParameters public_parameters =
        RSetupForTesting(setup, hash, random);
    const CommitmentKey& key = public_parameters.commitment_key();
    const auto& p = key.parameters();
    const Polynomial zero(p.degree, p.q);
    const PolynomialVector zero_message(p.v, zero);
    const PolynomialVector zero_randomness(p.m, zero);
    const PolynomialVector zero_commitment =
        lattice_lrs::commitment::Com(key, zero_message, zero_randomness);
    PolynomialVector witness_randomness = zero_randomness;
    witness_randomness[0] = Polynomial(p.degree, p.q, {z(1)});
    const PolynomialVector witness_commitment =
        lattice_lrs::commitment::Com(key, zero_message, witness_randomness);
    Protocol2PublicList ring{
        zero_commitment, witness_commitment, zero_commitment, zero_commitment};
    Protocol2Witness witness{1, witness_randomness};
    Protocol2Parameters proof{
        2, 2,
        PositiveRational(z(1), z(1)),
        PositiveRational(z(1000000000), z(1))};
    return TestContext(hash, std::move(public_parameters), std::move(proof),
                       std::move(ring), std::move(witness));
}

void test_repetition_count() {
    struct Table3Case {
        std::size_t degree;
        std::size_t k;
        std::size_t repetitions;
    };
    const Table3Case table3_cases[] = {
        {256, 2, 16},
        {128, 2, 19},
        {64, 2, 22},
        {64, 3, 24},
        {32, 3, 29},
        {32, 5, 35},
    };
    for (const Table3Case& test_case : table3_cases) {
        require(ComputeRSignRepetitionCount(
                    128, test_case.degree, test_case.k) ==
                    test_case.repetitions,
                "repetition count must match the Section 6/Table 3 bound");
    }
    require(ComputeRSignRepetitionCount(7, 3, 1) == 5,
            "repetition count must use the least integer satisfying the bound");
}

void test_section6_phi22_rejection_factor() {
    constexpr double phi = 22.0;
    const double mu = std::exp(12.0 / phi + 1.0 / (2.0 * phi * phi));
    const double two_stage_mu = mu * mu;
    require(two_stage_mu > 2.9 && two_stage_mu < 3.0,
            "Section 6.1 phi=22 must give mu(phi)^2 in (2.9, 3.0)");
}

void test_batch_restart_global_rejections_and_verification() {
    ZeroByteSource random;
    TestContext context = make_context(random);
    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({false, true, true}, {false, true});
    TestEncoder encoder;

    bool production_sign_rejected = false;
    try {
        (void)RSign(context.public_parameters, context.proof_parameters,
                    context.ring, context.witness, {0x41, 0x42}, encoder,
                    gaussian, auxiliary, rejection, random);
    } catch (const std::invalid_argument&) {
        production_sign_rejected = true;
    }
    require(production_sign_rejected,
            "production RSign must reject TestOnly setup parameters");
    require(!RVerify(context.public_parameters, context.proof_parameters,
                     context.ring, {0x41, 0x42}, RSignSignature{}, encoder,
                     auxiliary),
            "production RVerify must reject TestOnly setup parameters");

    const RSignSignature signature = RSignForTesting(
        context.public_parameters, context.proof_parameters, context.ring,
        context.witness, {0x41, 0x42}, encoder, gaussian, auxiliary,
        rejection, random);

    require(signature.first_messages.size() == 2 &&
                signature.challenges.size() == 2 &&
                signature.responses.size() == 2,
            "successful RSign must return all r transcripts");
    require((rejection.recorded_stages ==
             std::vector<RSignRejectionStage>{
                 RSignRejectionStage::f_vector,
                 RSignRejectionStage::f_vector,
                 RSignRejectionStage::response_vector,
                 RSignRejectionStage::f_vector,
                 RSignRejectionStage::response_vector}),
            "each attempt must use one f decision and, after acceptance, one response decision");
    require(rejection.recorded_values[0].size() == 344 &&
                rejection.recorded_values[2].size() == 516,
            "global vectors must have the specified dimensions");

    const auto& first_attempt_f = rejection.recorded_values[0];
    const auto& first_attempt_f_center = rejection.recorded_centers[0];
    for (std::size_t i = 0; i < 172; ++i) {
        require(first_attempt_f[i] - first_attempt_f_center[i] == 0 &&
                    first_attempt_f[172 + i] -
                            first_attempt_f_center[172 + i] == 1,
                "f concatenation must be run-major with each run's lift intact");
    }
    require(std::any_of(rejection.recorded_values[2].begin(),
                        rejection.recorded_values[2].end(),
                        [](const NTL::ZZ& value) {
                            return value > z(500000003) ||
                                   value < z(-500000003);
                        }),
            "response rejection must see unreduced integer lifts");
    require(auxiliary.committed_ids ==
                std::vector<std::uint8_t>{1, 2, 3, 4, 5, 6},
            "every retry must regenerate both runs' first-message states");
    require(encoder.encoded_inputs ==
                std::vector<std::vector<std::uint8_t>>{
                    {1, 2}, {3, 4}, {5, 6}},
            "the full transcript must be re-encoded after every restart");
    require(context.hash->observed.size() == 3 &&
                context.hash->observed[0] != context.hash->observed[1] &&
                context.hash->observed[1] != context.hash->observed[2],
            "challenges must be regenerated rather than reused after abort");
    require((gaussian.requests.size() >= 6) &&
                gaussian.requests[0].second == 0 &&
                gaussian.requests[1].second == 0,
            "Gaussian draws must be issued afresh for each run");
    require(RVerifyForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, {0x41, 0x42}, signature, encoder, auxiliary),
            "the complete batch signature must verify");

    RSignSignature bad_challenges = signature;
    bad_challenges.challenges[0] =
        context.public_parameters.challenge_set().front();
    require(!RVerifyForTesting(context.public_parameters, context.proof_parameters,
                     context.ring, {0x41, 0x42}, bad_challenges, encoder,
                     auxiliary),
            "verification must reject a changed challenge vector");
    RSignSignature bad_response = signature;
    bad_response.responses[0].z[0] =
        bad_response.responses[0].z[0] + Polynomial(86, z(1000000007), {z(1)});
    require(!RVerifyForTesting(context.public_parameters, context.proof_parameters,
                     context.ring, {0x41, 0x42}, bad_response, encoder,
                     auxiliary),
            "verification must reject an invalid transcript in any run");
    RSignSignature bad_later_response = signature;
    bad_later_response.responses[1].z[0] =
        bad_later_response.responses[1].z[0] +
        Polynomial(86, z(1000000007), {z(1)});
    require(!RVerifyForTesting(context.public_parameters, context.proof_parameters,
                     context.ring, {0x41, 0x42}, bad_later_response, encoder,
                     auxiliary),
            "verification must reject a failure in a later execution");
}

void test_transcript_binding_for_all_inputs() {
    ZeroByteSource setup_random;
    TestContext context = make_context(setup_random);
    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({true}, {true});
    PatternedByteSource random;
    BindingAwareEncoder encoder;

    const RSignSignature signature = RSignForTesting(
        context.public_parameters, context.proof_parameters, context.ring,
        context.witness, {0x41, 0x42}, encoder, gaussian, auxiliary,
        rejection, random);
    require(RVerifyForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, {0x41, 0x42}, signature, encoder, auxiliary),
            "binding-aware transcript should verify before tampering");

    const CommitmentKey& key = context.public_parameters.commitment_key();
    const std::vector<std::uint8_t> message{0x41, 0x42};
    const auto& first_messages = signature.first_messages;
    const std::vector<std::uint8_t> baseline =
        encoder.encode(key, message, context.ring, first_messages);
    const ChallengeVector baseline_challenges =
        context.public_parameters.hash_to_challenges(baseline);
    const auto require_binding = [&](const CommitmentKey& changed_key,
                                     const std::vector<std::uint8_t>& changed_message,
                                     const Protocol2PublicList& changed_ring,
                                     const std::vector<Protocol2FirstMessage>& changed_first) {
        const std::vector<std::uint8_t> encoded = encoder.encode(
            changed_key, changed_message, changed_ring, changed_first);
        require(encoded != baseline,
                "each modified transcript input must change the encoding");
        require(context.public_parameters.hash_to_challenges(encoded) !=
                    baseline_challenges,
                "each modified transcript input must change the challenge vector");
    };

    Matrix changed_g_r = key.G_r();
    change_constant_coefficient(changed_g_r.at(0, 0));
    const CommitmentKey changed_matrix_key(
        key.parameters(), std::move(changed_g_r), key.G_m());
    require_binding(changed_matrix_key, message, context.ring, first_messages);

    Parameters changed_parameters = key.parameters();
    changed_parameters.B += 1;
    const CommitmentKey changed_parameter_key(
        changed_parameters, key.G_r(), key.G_m());
    require_binding(changed_parameter_key, message, context.ring, first_messages);

    const std::vector<std::uint8_t> changed_message{0x41, 0x43};
    require_binding(key, changed_message, context.ring, first_messages);

    Protocol2PublicList reordered_ring = context.ring;
    std::swap(reordered_ring[0], reordered_ring[1]);
    require_binding(key, message, reordered_ring, first_messages);

    for (std::size_t run = 0; run < first_messages.size(); ++run) {
        for (std::size_t field = 0; field < 4; ++field) {
            std::vector<Protocol2FirstMessage> changed = first_messages;
            PolynomialVector* values = nullptr;
            if (field == 0) values = &changed[run].A;
            if (field == 1) values = &changed[run].B;
            if (field == 2) values = &changed[run].C;
            if (field == 3) values = &changed[run].D;
            change_constant_coefficient(values->at(0));
            require_binding(key, message, context.ring, changed);
        }
        for (std::size_t j = 0; j < first_messages[run].E.size(); ++j) {
            std::vector<Protocol2FirstMessage> changed = first_messages;
            change_constant_coefficient(changed[run].E[j].at(0));
            require_binding(key, message, context.ring, changed);
        }
        std::vector<Protocol2FirstMessage> changed = first_messages;
        changed[run].auxiliary_commitment.bytes[0] ^= 0x80;
        require_binding(key, message, context.ring, changed);
    }
}

std::vector<NTL::ZZ> multiply_lift_by_monomial(
    const std::vector<NTL::ZZ>& input,
    std::size_t polynomial_count,
    std::size_t degree,
    const Polynomial& monomial) {
    std::size_t exponent = 0;
    bool negative = false;
    std::size_t nonzero_count = 0;
    for (std::size_t i = 0; i < monomial.degree(); ++i) {
        if (monomial.coefficient(i) == 0) continue;
        ++nonzero_count;
        exponent = i;
        negative = monomial.coefficient(i) == monomial.modulus() - 1;
    }
    require(nonzero_count == 1, "test challenge must be a signed monomial");
    require(input.size() == polynomial_count * degree,
            "test lift dimension mismatch");
    std::vector<NTL::ZZ> output(input.size(), NTL::ZZ(0));
    for (std::size_t polynomial = 0; polynomial < polynomial_count;
         ++polynomial) {
        for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
            const std::size_t sum = coefficient + exponent;
            const std::size_t target = sum % degree;
            const bool negate = negative != (sum >= degree);
            const std::size_t offset = polynomial * degree;
            output[offset + target] = negate
                ? -input[offset + coefficient]
                : input[offset + coefficient];
        }
    }
    return output;
}

void append_lift(std::vector<NTL::ZZ>& output,
                 const std::vector<NTL::ZZ>& values) {
    output.insert(output.end(), values.begin(), values.end());
}

void test_exact_z_and_center_ordering() {
    ZeroByteSource setup_random;
    TestContext context = make_context(setup_random);
    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({true}, {true});
    PatternedByteSource random;
    TestEncoder encoder;

    const RSignSignature signature = RSignForTesting(
        context.public_parameters, context.proof_parameters, context.ring,
        context.witness, {0x21}, encoder, gaussian, auxiliary, rejection, random);
    require(rejection.recorded_stages.size() == 2,
            "test must observe exactly one global decision for each vector");

    const std::size_t degree = context.public_parameters.commitment_key()
                                   .parameters().degree;
    const std::size_t md = degree;
    const NTL::ZZ q =
        context.public_parameters.commitment_key().parameters().q;
    std::vector<NTL::ZZ> witness_lift(md, NTL::ZZ(0));
    witness_lift[0] = 1;

    std::vector<NTL::ZZ> expected_values;
    std::vector<NTL::ZZ> expected_centers;
    std::vector<std::vector<NTL::ZZ>> blocks;
    std::vector<std::vector<NTL::ZZ>> center_blocks;
    for (std::size_t run = 0; run < signature.challenges.size(); ++run) {
        std::vector<std::vector<NTL::ZZ>> rho_lifts(
            2, std::vector<NTL::ZZ>(md));
        for (std::size_t j = 0; j < 2; ++j) {
            const NTL::ZZ rho_value =
                q + z(static_cast<long>(100 * run + 3000 + 500 * j));
            std::fill(rho_lifts[j].begin(), rho_lifts[j].end(), rho_value);
        }
        std::vector<NTL::ZZ> r_b(md);
        std::vector<NTL::ZZ> r_c(md);
        std::vector<NTL::ZZ> r_a(md);
        std::vector<NTL::ZZ> r_d(md);
        std::fill(r_b.begin(), r_b.end(), run == 0 ? z(-1) : z(1));
        std::fill(r_c.begin(), r_c.end(), run == 0 ? z(1) : z(-1));
        std::fill(r_a.begin(), r_a.end(),
                  q + z(static_cast<long>(100 * run + 1000)));
        std::fill(r_d.begin(), r_d.end(),
                  q + z(static_cast<long>(100 * run + 2000)));

        const Protocol2IntegerLiftResponses lifts =
            ComputeProtocol2IntegerLiftResponses(
                signature.challenges[run], 2, witness_lift, rho_lifts,
                r_b, r_a, r_c, r_d);
        append_lift(expected_values, lifts.z_lift);
        append_lift(expected_values, lifts.z_b_lift);
        append_lift(expected_values, lifts.z_c_lift);
        blocks.push_back(lifts.z_lift);
        blocks.push_back(lifts.z_b_lift);
        blocks.push_back(lifts.z_c_lift);

        Polynomial challenge_power(degree, q, {z(1)});
        for (std::size_t i = 0; i < 2; ++i) {
            challenge_power = challenge_power * signature.challenges[run];
        }
        const auto center_z = multiply_lift_by_monomial(
            witness_lift, 1, degree, challenge_power);
        const auto center_z_b = multiply_lift_by_monomial(
            r_b, 1, degree, signature.challenges[run]);
        const auto center_z_c = multiply_lift_by_monomial(
            r_c, 1, degree, signature.challenges[run]);
        append_lift(expected_centers, center_z);
        append_lift(expected_centers, center_z_b);
        append_lift(expected_centers, center_z_c);
        center_blocks.push_back(center_z);
        center_blocks.push_back(center_z_b);
        center_blocks.push_back(center_z_c);
    }

    require(rejection.recorded_values[1] == expected_values,
            "global Z must concatenate each run's z, z_b, z_c lifts in order");
    require(rejection.recorded_centers[1] == expected_centers,
            "global Z center must concatenate x^k r, x r_b, x r_c in order");
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        for (std::size_t j = i + 1; j < blocks.size(); ++j) {
            require(blocks[i] != blocks[j],
                    "test Z blocks must have distinct sentinel values");
            require(center_blocks[i] != center_blocks[j],
                    "test center blocks must have distinct sentinel values");
        }
    }
    require(std::any_of(expected_values.begin(), expected_values.end(),
                        [&](const NTL::ZZ& value) {
                            return value > q / 2 || value < -q / 2;
                        }),
            "global rejection must observe unreduced lifts");
    for (std::size_t run = 0; run < signature.responses.size(); ++run) {
        const Polynomial expected_z(
            degree, q, blocks[3 * run]);
        require(signature.responses[run].z[0] == expected_z,
                "responses must be reduced only after global rejection accepts");
    }
}

void test_provider_and_entropy_failures() {
    ZeroByteSource setup_random;
    TestContext context = make_context(setup_random);
    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    TestEncoder encoder;
    ThrowingRejection rejection;
    ZeroByteSource random;
    bool rejection_failure_propagated = false;
    try {
        (void)RSignForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, context.witness, {}, encoder, gaussian,
                    auxiliary, rejection, random);
    } catch (const std::runtime_error&) {
        rejection_failure_propagated = true;
    }
    require(rejection_failure_propagated,
            "global rejection provider failures must propagate");

    class UnsupportedGaussian final : public Protocol2RSignGaussianProvider {
    public:
        bool supports_section6_distributions() const noexcept override {
            return false;
        }
        NTL::ZZ sample_coefficient(
            Protocol2GaussianSampleKind, std::size_t, std::size_t,
            const CommitmentKey&, const Protocol2Parameters&,
            RandomSource&) override {
            return NTL::ZZ(0);
        }
    } unsupported_gaussian;
    ScriptedRejection accepted({true}, {true});
    bool unsupported_reported = false;
    try {
        (void)RSignForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, context.witness, {}, encoder,
                    unsupported_gaussian, auxiliary, accepted, random);
    } catch (const UnsupportedRSignConfiguration&) {
        unsupported_reported = true;
    }
    require(unsupported_reported,
            "unresolved Section 6 Gaussian laws must fail explicitly");

    UnsupportedRejection unsupported_rejection;
    bool unsupported_rejection_reported = false;
    try {
        (void)RSignForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, context.witness, {}, encoder, gaussian,
                    auxiliary, unsupported_rejection, random);
    } catch (const UnsupportedRSignConfiguration&) {
        unsupported_rejection_reported = true;
    }
    require(unsupported_rejection_reported,
            "unresolved Section 6 rejection parameters must fail explicitly");

    ThrowingGaussian throwing_gaussian;
    bool gaussian_failure_propagated = false;
    try {
        (void)RSignForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, context.witness, {}, encoder,
                    throwing_gaussian, auxiliary, accepted, random);
    } catch (const std::runtime_error&) {
        gaussian_failure_propagated = true;
    }
    require(gaussian_failure_propagated,
            "Gaussian-provider failures must propagate");

    FailingRandomSource failing_random;
    ScriptedRejection unused({true}, {true});
    bool entropy_failure_propagated = false;
    try {
        (void)RSignForTesting(context.public_parameters, context.proof_parameters,
                    context.ring, context.witness, {}, encoder, gaussian,
                    auxiliary, unused, failing_random);
    } catch (const std::runtime_error&) {
        entropy_failure_propagated = true;
    }
    require(entropy_failure_propagated,
            "RandomSource failures must propagate through batch signing");
}

void test_exact_ds_provider_adapter() {
    ZeroByteSource random;
    TestContext context = make_context(random);
    RecordingDsSampler sampler;
    FixedScaleProfile profile;
    DsProtocol2RSignGaussianProvider gaussian(sampler, profile);
    const NTL::ZZ sample = gaussian.sample_coefficient(
        Protocol2GaussianSampleKind::rho, 1, 2,
        context.public_parameters.commitment_key(),
        context.proof_parameters, random);
    require(sample == z(10) &&
                sampler.observed_scale == std::pair<NTL::ZZ, NTL::ZZ>{z(7), z(3)},
            "RSign D_s adapter must pass exact rational scales through unchanged");
    require(profile.kind == Protocol2GaussianSampleKind::rho &&
                profile.run_index == 1 && profile.repetitions == 2,
            "scale profile must receive the sampling role and batch position");
}

}  // namespace

int main() {
    try {
        test_repetition_count();
        test_section6_phi22_rejection_factor();
        test_batch_restart_global_rejections_and_verification();
        test_transcript_binding_for_all_inputs();
        test_exact_z_and_center_ordering();
        test_provider_and_entropy_failures();
        test_exact_ds_provider_adapter();
    } catch (const std::exception& error) {
        std::cerr << "RSign batch test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
