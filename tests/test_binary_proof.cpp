#include "lattice_lrs/proofs/binary_proof.hpp"
#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/discrete_gaussian.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::CommitmentKey;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::proofs::AuxiliaryCommitmentOpening;
using lattice_lrs::proofs::AuxiliaryCommitmentProvider;
using lattice_lrs::proofs::AuxiliaryCommitmentValue;
using lattice_lrs::proofs::BernoulliExponentialProvider;
using lattice_lrs::proofs::BinaryProofFirstMessage;
using lattice_lrs::proofs::BinaryProofParameters;
using lattice_lrs::proofs::BinaryProofResponse;
using lattice_lrs::proofs::BinaryWitness;
using lattice_lrs::proofs::DiscreteGaussianProvider;
using lattice_lrs::proofs::ExactBernoulliExponentialProvider;
using lattice_lrs::proofs::ExactDiscreteGaussianProvider;
using lattice_lrs::sampling::PolynomialVector;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

// Deterministic source used only by these tests; it is not a production RNG.
class ZeroByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        for (std::size_t i = 0; i < length; ++i) output[i] = 0;
    }
};

// Deterministic stand-in for protocol wiring tests only. It does not sample a
// discrete Gaussian and must never be used for cryptographic signing.
class ZeroGaussian final : public DiscreteGaussianProvider {
public:
    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                               const NTL::ZZ& sigma_squared_denominator,
                               RandomSource&) override {
        require(sigma_squared_numerator > 0 && sigma_squared_denominator > 0,
                "Gaussian provider must receive positive exact sigma_squared");
        ++samples;
        return NTL::ZZ(0);
    }
    std::size_t samples = 0;
};

class OneThenZeroGaussian final : public DiscreteGaussianProvider {
public:
    explicit OneThenZeroGaussian(std::size_t nonzero_samples)
        : nonzero_samples_(nonzero_samples) {}

    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                               const NTL::ZZ& sigma_squared_denominator,
                               RandomSource&) override {
        require(sigma_squared_numerator > 0 && sigma_squared_denominator > 0,
                "Gaussian provider must receive positive exact sigma_squared");
        return calls_++ < nonzero_samples_ ? NTL::ZZ(1) : NTL::ZZ(0);
    }
    std::size_t calls() const noexcept { return calls_; }

private:
    std::size_t nonzero_samples_;
    std::size_t calls_ = 0;
};

// Deterministic wiring fixture: the first Gaussian coefficient is controlled
// to exercise the first rejection exponent; all later coefficients are zero.
class FirstValueThenZeroGaussian final : public DiscreteGaussianProvider {
public:
    explicit FirstValueThenZeroGaussian(NTL::ZZ first) : first_(std::move(first)) {}

    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                               const NTL::ZZ& sigma_squared_denominator,
                               RandomSource&) override {
        require(sigma_squared_numerator > 0 && sigma_squared_denominator > 0,
                "Gaussian provider must receive positive exact sigma_squared");
        return calls_++ == 0 ? first_ : NTL::ZZ(0);
    }

private:
    NTL::ZZ first_;
    std::size_t calls_ = 0;
};

class FixedExponential final : public BernoulliExponentialProvider {
public:
    explicit FixedExponential(bool result) : result_(result) {}

    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        require(numerator <= 0 && denominator > 0,
                "rejection sampler must receive a nonpositive rational log probability");
        ++calls;
        return result_;
    }
    std::size_t calls = 0;

private:
    bool result_;
};

class RecordingExponential final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        require(numerator < 0 && denominator > 0,
                "exact exponential provider must receive a negative rational log");
        arguments.emplace_back(numerator, denominator);
        return true;
    }

    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> arguments;
};

class AcceptingRecordingExponential final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        require(numerator < 0 && denominator > 0,
                "rejection provider must receive a negative rational log");
        arguments.emplace_back(numerator, denominator);
        return true;
    }

    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> arguments;
};

// Test-only coin outcomes force finite, deterministic sampler control flow.
class ScriptedExponential final : public BernoulliExponentialProvider {
public:
    explicit ScriptedExponential(std::vector<bool> outcomes)
        : outcomes_(std::move(outcomes)) {}

    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        require(numerator < 0 && denominator > 0,
                "Gaussian sampler must pass a negative rational log");
        if (next_ == outcomes_.size()) {
            throw std::runtime_error("scripted exponential outcomes exhausted");
        }
        return outcomes_[next_++];
    }

private:
    std::vector<bool> outcomes_;
    std::size_t next_ = 0;
};

class ThrowingExponential final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ&, const NTL::ZZ&, RandomSource&) override {
        throw std::runtime_error("injected Bernoulli-exponential failure");
    }
};

class FailingByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("injected random-source failure");
    }
};

class PrefixThenZeroByteSource final : public RandomSource {
public:
    explicit PrefixThenZeroByteSource(std::vector<std::uint8_t> prefix)
        : prefix_(std::move(prefix)) {}

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        for (std::size_t i = 0; i < length; ++i) {
            output[i] = offset_ < prefix_.size() ? prefix_[offset_++] : 0;
        }
    }

private:
    std::vector<std::uint8_t> prefix_;
    std::size_t offset_ = 0;
};

class RecordingExactGaussian final : public DiscreteGaussianProvider {
public:
    explicit RecordingExactGaussian(ExactDiscreteGaussianProvider& sampler)
        : sampler_(sampler) {}

    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                               const NTL::ZZ& sigma_squared_denominator,
                               RandomSource& random) override {
        arguments.emplace_back(sigma_squared_numerator,
                               sigma_squared_denominator);
        NTL::ZZ value = sampler_.sample_coefficient(
            sigma_squared_numerator, sigma_squared_denominator, random);
        samples.push_back(value);
        return value;
    }

    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> arguments;
    std::vector<NTL::ZZ> samples;

private:
    ExactDiscreteGaussianProvider& sampler_;
};

// Delegates the first coefficient to the exact sampler; later zeros keep the
// successful Bernoulli-exponential integration test bounded.
class FirstExactThenZeroGaussian final : public DiscreteGaussianProvider {
public:
    explicit FirstExactThenZeroGaussian(ExactDiscreteGaussianProvider& sampler)
        : sampler_(sampler) {}

    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                               const NTL::ZZ& sigma_squared_denominator,
                               RandomSource& random) override {
        arguments.emplace_back(sigma_squared_numerator,
                               sigma_squared_denominator);
        NTL::ZZ value(0);
        if (samples.empty()) {
            value = sampler_.sample_coefficient(
                sigma_squared_numerator, sigma_squared_denominator, random);
        }
        samples.push_back(value);
        return value;
    }

    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> arguments;
    std::vector<NTL::ZZ> samples;

private:
    ExactDiscreteGaussianProvider& sampler_;
};

std::vector<std::uint8_t> encode_for_test(const PolynomialVector& A,
                                         const PolynomialVector& C,
                                         const PolynomialVector& D) {
    // Deliberately transparent fixture encoding; this is not a secure aCom.
    std::ostringstream stream;
    const auto append = [&stream](const PolynomialVector& vector) {
        stream << '[';
        for (const auto& polynomial : vector) {
            stream << polynomial.degree() << ':' << polynomial.modulus() << ':';
            for (const auto& coefficient : polynomial.coefficients()) {
                stream << coefficient << ',';
            }
            stream << ';';
        }
        stream << ']';
    };
    append(A);
    append(C);
    append(D);
    const std::string text = stream.str();
    return {text.begin(), text.end()};
}

class InsecureAuxiliaryCommitmentForTesting final
    : public AuxiliaryCommitmentProvider {
public:
    AuxiliaryCommitmentOpening commit(const PolynomialVector& A,
                                      const PolynomialVector& C,
                                      const PolynomialVector& D,
                                      RandomSource&) override {
        return {AuxiliaryCommitmentValue{encode_for_test(A, C, D)}, {0xA5}};
    }

    bool verify(const PolynomialVector& A, const PolynomialVector& C,
                const PolynomialVector& D,
                const AuxiliaryCommitmentValue& commitment,
                const std::vector<std::uint8_t>& opening) const override {
        return commitment.bytes == encode_for_test(A, C, D) && opening ==
               std::vector<std::uint8_t>{0xA5};
    }
};

Parameters test_parameters(const NTL::ZZ& q = z(65535),
                           const NTL::ZZ& T_squared = z(100000000)) {
    // Small non-production profile chosen only to satisfy Protocol 1's
    // dimensional and q inequalities for deterministic tests.
    return {1, 11, 2, 8, q, z(1), SquaredNormBound(T_squared, z(1))};
}

BinaryProofParameters test_proof_parameters() {
    return {1, 2, {z(1), z(1)}, {z(1), z(1)}};
}

CommitmentKey test_key(const Parameters& parameters) {
    Matrix G_r(parameters.n, parameters.m, parameters.degree, parameters.q);
    G_r.at(0, 0) = Polynomial(parameters.degree, parameters.q, {z(1)});
    Matrix G_m(parameters.n, parameters.v, parameters.degree, parameters.q);
    G_m.at(0, 0) = Polynomial(parameters.degree, parameters.q, {z(1)});
    G_m.at(0, 1) = Polynomial(parameters.degree, parameters.q, {z(2)});
    return CommitmentKey(parameters, std::move(G_r), std::move(G_m));
}

BinaryWitness valid_witness(const Parameters& parameters) {
    return {{Polynomial(parameters.degree, parameters.q, {z(1)}),
             Polynomial(parameters.degree, parameters.q)},
            PolynomialVector(parameters.m, Polynomial(parameters.degree, parameters.q))};
}

void test_challenge_mapping_and_sampling() {
    const auto p = test_parameters();
    require(lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0) ==
                Polynomial(p.degree, p.q, {z(1)}),
            "challenge exponent zero must map to 1");
    std::vector<NTL::ZZ> negative_x_coefficients(p.degree, z(0));
    negative_x_coefficients[p.degree - 1] = z(-1);
    require(lattice_lrs::proofs::BinaryChallengeFromExponent(p, 2 * p.degree - 1) ==
                Polynomial(p.degree, p.q, negative_x_coefficients),
            "last challenge exponent must map to -X^(d-1)");

    bool rejected = false;
    try {
        (void)lattice_lrs::proofs::BinaryChallengeFromExponent(p, 2 * p.degree);
    } catch (const std::out_of_range&) {
        rejected = true;
    }
    require(rejected, "challenge exponent outside C must be rejected");

    ZeroByteSource random;
    require(lattice_lrs::proofs::SampleBinaryChallenge(p, random) ==
                lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0),
            "challenge sampling must use the configured byte source");
}

void test_protocol_one_honest_transcript_and_tampering() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    const BinaryWitness witness = valid_witness(p);
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);
    ZeroByteSource random;
    OneThenZeroGaussian gaussian(8);
    FixedExponential accept_all(true);
    InsecureAuxiliaryCommitmentForTesting auxiliary;

    auto begun = lattice_lrs::proofs::BeginBinaryProof(
        key, proof_parameters, public_commitment, witness,
        random, gaussian, auxiliary);
    const Polynomial challenge = lattice_lrs::proofs::BinaryChallengeFromExponent(p, p.degree);
    const auto response = lattice_lrs::proofs::RespondBinaryProof(
        begun.state, key, proof_parameters, challenge, random, accept_all);
    require(response.has_value(), "test provider should permit a complete transcript");
    require(accept_all.calls == 2, "Protocol 1 must apply both rejection steps");
    require(gaussian.calls() == 8 * (2 - 1) + 2 * p.m * p.degree,
            "Protocol 1 must request all Gaussian coordinates at their dimensions");
    require(begun.first_message.A[0] != Polynomial(p.degree, p.q) &&
                begun.first_message.C[0] != Polynomial(p.degree, p.q) &&
                begun.first_message.D[0] != Polynomial(p.degree, p.q),
            "nonzero test masks must exercise nontrivial first-message commitments");
    require(lattice_lrs::proofs::VerifyBinaryProof(
                key, proof_parameters, public_commitment, begun.first_message,
                challenge, *response, auxiliary),
            "honest Protocol 1 transcript must satisfy its equations");

    BinaryProofResponse changed_f = *response;
    changed_f.f_nonzero[0] = changed_f.f_nonzero[0] + Polynomial(p.degree, p.q, {z(1)});
    require(!lattice_lrs::proofs::VerifyBinaryProof(
                key, proof_parameters, public_commitment, begun.first_message,
                challenge, changed_f, auxiliary),
            "modified f response must be rejected");

    BinaryProofResponse changed_z = *response;
    changed_z.z_c[0] = changed_z.z_c[0] + Polynomial(p.degree, p.q, {z(1)});
    require(!lattice_lrs::proofs::VerifyBinaryProof(
                key, proof_parameters, public_commitment, begun.first_message,
                challenge, changed_z, auxiliary),
            "modified commitment randomness response must be rejected");

    BinaryProofResponse out_of_range = *response;
    out_of_range.z_b[0] = Polynomial(p.degree, p.q, {z(300)});
    require(!lattice_lrs::proofs::VerifyBinaryProof(
                key, proof_parameters, public_commitment, begun.first_message,
                challenge, out_of_range, auxiliary),
            "response exceeding the Euclidean norm bound must be rejected");

    auto changed_first = begun.first_message;
    changed_first.A[0] = changed_first.A[0] + Polynomial(p.degree, p.q, {z(1)});
    require(!lattice_lrs::proofs::VerifyBinaryProof(
                key, proof_parameters, public_commitment, changed_first,
                challenge, *response, auxiliary),
            "modified first-message commitment must be rejected");

    const Polynomial not_a_monomial(p.degree, p.q, {z(2)});
    require(!lattice_lrs::proofs::VerifyBinaryProof(
                key, proof_parameters, public_commitment, begun.first_message,
                not_a_monomial, *response, auxiliary),
            "challenge outside the monomial challenge set must be rejected");
}

void test_protocol_one_with_exact_gaussian_providers() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    BinaryWitness witness{
        {Polynomial(p.degree, p.q), Polynomial(p.degree, p.q, {z(1)})},
        PolynomialVector(p.m, Polynomial(p.degree, p.q))};
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);

    const std::size_t a_count =
        proof_parameters.k * (proof_parameters.beta - 1) * p.degree;
    const std::size_t randomness_count = p.m * p.degree;
    const std::size_t gaussian_count = a_count + 2 * randomness_count;
    // The production Gaussian implementation handles every draw; scripted
    // coins make this wiring and parameter test deterministic, not statistical.
    std::vector<bool> coin_outcomes;
    coin_outcomes.reserve(3 * gaussian_count);
    for (std::size_t i = 0; i < gaussian_count; ++i) {
        coin_outcomes.insert(coin_outcomes.end(), {false, false, true});
    }
    ZeroByteSource random;
    ScriptedExponential exponential(std::move(coin_outcomes));
    ExactDiscreteGaussianProvider exact_gaussian(exponential);
    RecordingExactGaussian gaussian(exact_gaussian);
    InsecureAuxiliaryCommitmentForTesting auxiliary;

    auto begun = lattice_lrs::proofs::BeginBinaryProof(
        key, proof_parameters, public_commitment, witness,
        random, gaussian, auxiliary);
    require(gaussian.arguments.size() == gaussian_count &&
                gaussian.samples.size() == gaussian_count,
            "Protocol 1 must draw every scalar coefficient through the exact provider");
    for (std::size_t i = 0; i < a_count; ++i) {
        require(gaussian.arguments[i].first == z(1) &&
                    gaussian.arguments[i].second == z(1),
                "digit masks must use sigma_squared=phi1^2*k exactly");
    }
    const NTL::ZZ expected_randomness_sigma_squared =
        p.B * p.B * 2 * z(p.m) * z(p.degree);
    for (std::size_t i = a_count; i < gaussian_count; ++i) {
        require(gaussian.arguments[i].first == expected_randomness_sigma_squared &&
                    gaussian.arguments[i].second == z(1),
                "r_a and r_d must use sigma_squared=phi2^2*B^2*2*m*d exactly");
    }
    for (const NTL::ZZ& sample : gaussian.samples) {
        require(sample == 0,
                "the bounded deterministic stream should produce zero Gaussian proposals");
    }

    const Polynomial challenge =
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);
    AcceptingRecordingExponential rejection_exponential;
    const auto response = lattice_lrs::proofs::RespondBinaryProof(
        begun.state, key, proof_parameters, challenge, random,
        rejection_exponential);
    require(response.has_value(),
            "the exact Gaussian and exponential providers should complete the test transcript");
}

void test_protocol_one_uses_exact_exponential_coin() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    BinaryWitness witness{
        {Polynomial(p.degree, p.q), Polynomial(p.degree, p.q, {z(1)})},
        PolynomialVector(p.m, Polynomial(p.degree, p.q))};
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);

    // The first three bytes produce G1=1, G2=0 for sigma_squared=1;
    // acceptance is then deterministic because the exact log is zero.
    PrefixThenZeroByteSource random({0x00, 0xFF, 0xFF});
    ExactBernoulliExponentialProvider exponential;
    ExactDiscreteGaussianProvider exact_gaussian(exponential);
    FirstExactThenZeroGaussian gaussian(exact_gaussian);
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    auto begun = lattice_lrs::proofs::BeginBinaryProof(
        key, proof_parameters, public_commitment, witness,
        random, gaussian, auxiliary);
    require(gaussian.samples.size() ==
                proof_parameters.k * (proof_parameters.beta - 1) * p.degree +
                    2 * p.m * p.degree,
            "Protocol 1 must finish its full scalar sampling schedule");
    require(gaussian.samples.front() == z(1),
            "Protocol 1 must receive the actual exact Bernoulli/Gaussian sample");

    AcceptingRecordingExponential rejection_exponential;
    const auto response = lattice_lrs::proofs::RespondBinaryProof(
        begun.state, key, proof_parameters,
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0),
        random, rejection_exponential);
    require(response.has_value(),
            "the exact exponential coin must compose with the Protocol 1 prover");
}

void test_protocol_one_preserves_gaussian_integer_lifts() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    BinaryWitness witness{
        {Polynomial(p.degree, p.q), Polynomial(p.degree, p.q, {z(1)})},
        PolynomialVector(p.m, Polynomial(p.degree, p.q))};
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);

    const std::size_t a_count =
        proof_parameters.k * (proof_parameters.beta - 1) * p.degree;
    const std::size_t gaussian_count =
        a_count + 2 * p.m * p.degree;
    // Script a rare above-q proposal to distinguish the integer lift from
    // its ring encoding; this does not assert a sampler probability.
    const std::size_t lifted_sample_count =
        static_cast<std::size_t>(NTL::to_long(p.q)) + 1;
    std::vector<bool> decisions(lifted_sample_count, true);
    decisions.insert(decisions.end(), {false, false, true});
    for (std::size_t i = 1; i < gaussian_count; ++i) {
        decisions.insert(decisions.end(), {false, false, true});
    }

    ZeroByteSource random;
    ScriptedExponential scripted_exponential(std::move(decisions));
    ExactDiscreteGaussianProvider exact_gaussian(scripted_exponential);
    RecordingExactGaussian gaussian(exact_gaussian);
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    auto begun = lattice_lrs::proofs::BeginBinaryProof(
        key, proof_parameters, public_commitment, witness,
        random, gaussian, auxiliary);
    require(gaussian.samples.size() == gaussian_count &&
                gaussian.samples.front() == p.q + 1,
            "the exact sampler must retain the scripted integer above q");

    AcceptingRecordingExponential rejection_exponential;
    const Polynomial challenge =
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);
    const auto response = lattice_lrs::proofs::RespondBinaryProof(
        begun.state, key, proof_parameters, challenge, random,
        rejection_exponential);
    require(response.has_value(),
            "scripted rejection coins should complete the lift-preservation transcript");
    require(response->f_nonzero[0].coefficient(0) == z(2),
            "the response should reduce q+2 only when encoding the ring element");
    require(!rejection_exponential.arguments.empty() &&
                rejection_exponential.arguments.front().first == -2 * p.q - 28 &&
                rejection_exponential.arguments.front().second == z(2),
            "the rejection exponent must use the unreduced q+1 Gaussian lift");
}

void test_protocol_one_sampler_failures_propagate() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    const BinaryWitness witness = valid_witness(p);
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);
    InsecureAuxiliaryCommitmentForTesting auxiliary;

    {
        FailingByteSource random;
        ExactBernoulliExponentialProvider exponential;
        ExactDiscreteGaussianProvider gaussian(exponential);
        bool propagated = false;
        try {
            (void)lattice_lrs::proofs::BeginBinaryProof(
                key, proof_parameters, public_commitment, witness,
                random, gaussian, auxiliary);
        } catch (const std::runtime_error&) {
            propagated = true;
        }
        require(propagated,
                "Protocol 1 must propagate RandomSource failure from Gaussian sampling");
    }

    {
        ZeroByteSource random;
        ThrowingExponential exponential;
        ExactDiscreteGaussianProvider gaussian(exponential);
        bool propagated = false;
        try {
            (void)lattice_lrs::proofs::BeginBinaryProof(
                key, proof_parameters, public_commitment, witness,
                random, gaussian, auxiliary);
        } catch (const std::runtime_error&) {
            propagated = true;
        }
        require(propagated,
                "Protocol 1 must propagate Bernoulli-exponential provider failure");
    }
}

void test_protocol_one_response_norm_boundaries() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    const Polynomial challenge = lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);
    const PolynomialVector public_commitment(p.n, Polynomial(p.degree, p.q));
    ZeroByteSource random;
    InsecureAuxiliaryCommitmentForTesting auxiliary;

    const auto make_transcript = [&](const Polynomial& f_nonzero,
                                     const PolynomialVector& z_b,
                                     const PolynomialVector& z_c) {
        BinaryProofResponse response;
        response.f_nonzero = {f_nonzero};
        response.z_b = z_b;
        response.z_c = z_c;

        const std::vector<Polynomial> f = {
            challenge - f_nonzero,
            f_nonzero
        };
        PolynomialVector g;
        g.reserve(f.size());
        for (const auto& value : f) g.push_back(value * (challenge - value));

        BinaryProofFirstMessage first;
        first.A = lattice_lrs::commitment::Com(key, f, z_b);
        first.C = PolynomialVector(p.n, Polynomial(p.degree, p.q));
        first.D = lattice_lrs::commitment::Com(key, g, z_c);
        auto opening = auxiliary.commit(first.A, first.C, first.D, random);
        first.auxiliary_commitment = std::move(opening.commitment);
        response.auxiliary_opening = std::move(opening.opening);
        return std::make_pair(std::move(first), std::move(response));
    };

    const auto verify_f_norm = [&](const std::vector<long>& coefficients,
                                   bool expected, const std::string& label) {
        std::vector<NTL::ZZ> lifted(p.degree, z(0));
        for (std::size_t i = 0; i < coefficients.size(); ++i) {
            lifted[i] = z(coefficients[i]);
        }
        const Polynomial f_nonzero(p.degree, p.q, lifted);
        const PolynomialVector zeros(p.m, Polynomial(p.degree, p.q));
        auto transcript = make_transcript(f_nonzero, zeros, zeros);
        const bool accepted = lattice_lrs::proofs::VerifyBinaryProof(
            key, proof_parameters, public_commitment, transcript.first,
            challenge, transcript.second, auxiliary);
        require(accepted == expected, label);
    };

    // For phi1=1, d=8, k=1, beta=2, the squared bound for f_{0,1} is
    // 25*phi1^2*d*k = 200. The reconstructed f_{0,0}=1-f_{0,1} remains
    // within its same bound in all three fixtures. Exact integer coefficient
    // lifts avoid floating-point rounding at the boundary.
    verify_f_norm({10, 9}, true, "f norm just below its verifier bound must pass"); // 181
    verify_f_norm({10, 10}, true, "f norm exactly at its verifier bound must pass"); // 200
    verify_f_norm({14, 2, 1}, false, "f norm just above its verifier bound must fail"); // 201

    const auto verify_z_norm = [&](long largest_coefficient, bool exact_boundary,
                                   bool expected, const std::string& label) {
        std::vector<NTL::ZZ> flattened(p.m * p.degree, z(0));
        flattened[0] = z(largest_coefficient);
        if (exact_boundary) {
            // 248^2 + 7*8^2 = 61,952, exactly the squared z_b bound
            // 8*phi2^2*B^2*m^2*d^2 for this toy profile.
            for (std::size_t i = 1; i <= 7; ++i) flattened[i] = z(8);
        }
        PolynomialVector z_b;
        z_b.reserve(p.m);
        for (std::size_t i = 0; i < p.m; ++i) {
            std::vector<NTL::ZZ> block(p.degree, z(0));
            for (std::size_t j = 0; j < p.degree; ++j) {
                block[j] = flattened[i * p.degree + j];
            }
            z_b.emplace_back(p.degree, p.q, block);
        }
        const PolynomialVector z_c(p.m, Polynomial(p.degree, p.q));
        const auto safe_f = Polynomial(p.degree, p.q);
        auto transcript = make_transcript(safe_f, z_b, z_c);
        const bool accepted = lattice_lrs::proofs::VerifyBinaryProof(
            key, proof_parameters, public_commitment, transcript.first,
            challenge, transcript.second, auxiliary);
        require(accepted == expected, label);
    };

    // The squared z_b and z_c bound is 61,952. Centered lifts are unchanged
    // for these coefficients because q=65,535.
    verify_z_norm(248, false, true, "z norm just below its verifier bound must pass"); // 61,504
    verify_z_norm(248, true, true, "z norm exactly at its verifier bound must pass"); // 61,952
    verify_z_norm(249, false, false, "z norm just above its verifier bound must fail"); // 62,001
}

void test_rejection_abort_and_single_use_state() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    const BinaryWitness witness = valid_witness(p);
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);
    ZeroByteSource random;
    ZeroGaussian gaussian;
    FixedExponential reject_first(false);
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    auto begun = lattice_lrs::proofs::BeginBinaryProof(
        key, proof_parameters, public_commitment, witness,
        random, gaussian, auxiliary);
    const Polynomial challenge = lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);
    require(!lattice_lrs::proofs::RespondBinaryProof(
                begun.state, key, proof_parameters, challenge, random, reject_first),
            "a rejected first rejection-sampling step must abort");
    require(reject_first.calls == 1, "first rejection must abort before the second test");

    bool state_rejected = false;
    try {
        (void)lattice_lrs::proofs::RespondBinaryProof(
            begun.state, key, proof_parameters, challenge, random, reject_first);
    } catch (const std::logic_error&) {
        state_rejected = true;
    }
    require(state_rejected, "prover state must be single-use after response/abort");
}

void test_rejection_exponent_sign_branches() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    BinaryWitness witness{
        {Polynomial(p.degree, p.q), Polynomial(p.degree, p.q, {z(1)})},
        PolynomialVector(p.m, Polynomial(p.degree, p.q))};
    const PolynomialVector public_commitment = lattice_lrs::commitment::Com(
        key, witness.bits, witness.randomness);
    const Polynomial challenge = lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);

    const auto run_case = [&](long first_gaussian, std::size_t expected_provider_calls,
                              const NTL::ZZ* expected_first_numerator,
                              const NTL::ZZ* expected_first_denominator) {
        ZeroByteSource random;
        FirstValueThenZeroGaussian gaussian(z(first_gaussian));
        RecordingExponential exponential;
        InsecureAuxiliaryCommitmentForTesting auxiliary;
        auto begun = lattice_lrs::proofs::BeginBinaryProof(
            key, proof_parameters, public_commitment, witness,
            random, gaussian, auxiliary);
        const auto response = lattice_lrs::proofs::RespondBinaryProof(
            begun.state, key, proof_parameters, challenge, random, exponential);
        require(response.has_value(), "accepting deterministic test coins must produce a response");
        require(exponential.arguments.size() == expected_provider_calls,
                "only strictly negative rejection logs may call the exponential provider");
        if (expected_first_numerator != nullptr) {
            require(exponential.arguments.front().first == *expected_first_numerator &&
                        exponential.arguments.front().second == *expected_first_denominator,
                    "negative first-stage log must reach the provider as its exact rational");
        }
    };

    // With phi1=1, K^2=k=1, witness digit 1, and first mask a, the corrected
    // first Protocol 1 log probability is -a-13: a=-14 => +1, a=-13 => 0,
    // and a=-12 => -1. These are deterministic branch tests, not sampler tests.
    run_case(-14, 1, nullptr, nullptr);
    run_case(-13, 1, nullptr, nullptr);
    const NTL::ZZ negative_numerator = z(-2);
    const NTL::ZZ negative_denominator = z(2);
    run_case(-12, 2, &negative_numerator, &negative_denominator);
}

void test_invalid_witness_and_parameters() {
    const Parameters p = test_parameters();
    const CommitmentKey key = test_key(p);
    const BinaryProofParameters proof_parameters = test_proof_parameters();
    ZeroByteSource random;
    ZeroGaussian gaussian;
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    BinaryWitness bad = valid_witness(p);
    bad.bits[1] = Polynomial(p.degree, p.q, {z(1)});
    bool rejected = false;
    try {
        (void)lattice_lrs::proofs::BeginBinaryProof(
            key, proof_parameters, lattice_lrs::commitment::Com(key, valid_witness(p).bits,
                valid_witness(p).randomness), bad, random, gaussian, auxiliary);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "non-one-hot binary witness must be rejected");

    rejected = false;
    try {
        BinaryWitness wrong_opening = valid_witness(p);
        wrong_opening.randomness[0] = Polynomial(p.degree, p.q, {z(1)});
        (void)lattice_lrs::proofs::BeginBinaryProof(
            key, proof_parameters, PolynomialVector(p.n, Polynomial(p.degree, p.q)),
            wrong_opening, random, gaussian, auxiliary);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "witness not opening the public commitment must be rejected");

    rejected = false;
    try {
        const CommitmentKey bad_q_key = test_key(test_parameters(z(50001)));
        proof_parameters.validate(bad_q_key);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "modulus below the paper's Protocol 1 lower bound must be rejected");

    rejected = false;
    try {
        const CommitmentKey bad_bound_key = test_key(test_parameters(z(65535), z(1)));
        proof_parameters.validate(bad_bound_key);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "commitment binding bound below Theorem 1's T must be rejected");

    rejected = false;
    try {
        BinaryProofParameters invalid_phi = proof_parameters;
        invalid_phi.phi1.numerator = z(0);
        invalid_phi.validate(key);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "zero rejection parameter must be rejected");

    rejected = false;
    try {
        (void)lattice_lrs::proofs::PositiveRational(z(1), z(0));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "zero rational denominator must be rejected");
}

}  // namespace

int main() {
    try {
        test_challenge_mapping_and_sampling();
        test_protocol_one_honest_transcript_and_tampering();
        test_protocol_one_with_exact_gaussian_providers();
        test_protocol_one_uses_exact_exponential_coin();
        test_protocol_one_preserves_gaussian_integer_lifts();
        test_protocol_one_sampler_failures_propagate();
        test_protocol_one_response_norm_boundaries();
        test_rejection_abort_and_single_use_state();
        test_rejection_exponent_sign_branches();
        test_invalid_witness_and_parameters();
    } catch (const std::exception& error) {
        std::cerr << "binary proof test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
