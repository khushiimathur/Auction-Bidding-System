#include "lattice_lrs/proofs/protocol2_proof.hpp"

#include "lattice_lrs/sampling/random_source.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
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
using lattice_lrs::proofs::AuxiliaryCommitmentValue;
using lattice_lrs::proofs::BernoulliExponentialProvider;
using lattice_lrs::proofs::DiscreteGaussianProvider;
using lattice_lrs::proofs::Protocol2AuxiliaryCommitmentProvider;
using lattice_lrs::proofs::Protocol2FirstMessage;
using lattice_lrs::proofs::Protocol2Parameters;
using lattice_lrs::proofs::Protocol2PublicList;
using lattice_lrs::proofs::Protocol2Response;
using lattice_lrs::proofs::Protocol2Witness;
using lattice_lrs::proofs::BeginProtocol2Proof;
using lattice_lrs::proofs::BinaryChallengeFromExponent;
using lattice_lrs::proofs::RespondProtocol2Proof;
using lattice_lrs::proofs::VerifyProtocol2Proof;
using lattice_lrs::sampling::PolynomialVector;
using lattice_lrs::sampling::RandomSource;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

class ZeroByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        std::fill(output, output + length, std::uint8_t(0));
    }
};

class ZeroGaussian final : public DiscreteGaussianProvider {
public:
    NTL::ZZ sample_coefficient(const NTL::ZZ& numerator,
                               const NTL::ZZ& denominator,
                               RandomSource&) override {
        widths.emplace_back(numerator, denominator);
        return NTL::ZZ(0);
    }

    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> widths;
};

class AlwaysAccept final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ& numerator, const NTL::ZZ& denominator,
                    RandomSource&) override {
        require(numerator < 0 && denominator > 0,
                "rejection provider must receive a negative rational exponent");
        arguments.emplace_back(numerator, denominator);
        ++calls;
        return true;
    }
    std::size_t calls = 0;
    std::vector<std::pair<NTL::ZZ, NTL::ZZ>> arguments;
};

class RejectFirst final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ&, const NTL::ZZ&,
                    RandomSource&) override {
        ++calls;
        return false;
    }
    std::size_t calls = 0;
};

class AcceptThenThrow final : public BernoulliExponentialProvider {
public:
    bool sample_exp(const NTL::ZZ&, const NTL::ZZ&,
                    RandomSource&) override {
        if (calls++ == 0) return true;
        throw std::runtime_error("joint rejection provider failure");
    }
    std::size_t calls = 0;
};

struct AuxiliaryTuple {
    PolynomialVector A;
    PolynomialVector B;
    PolynomialVector C;
    PolynomialVector D;
    std::vector<PolynomialVector> E;

    bool operator==(const AuxiliaryTuple& other) const {
        return A == other.A && B == other.B && C == other.C &&
               D == other.D && E == other.E;
    }
};

class TransparentTestAuxiliary final : public Protocol2AuxiliaryCommitmentProvider {
public:
    AuxiliaryCommitmentOpening commit(
        const PolynomialVector& A, const PolynomialVector& B,
        const PolynomialVector& C, const PolynomialVector& D,
        const std::vector<PolynomialVector>& E, RandomSource&) override {
        tuple_ = {A, B, C, D, E};
        return {AuxiliaryCommitmentValue{{0xa2}}, {0x5a}};
    }

    bool verify(
        const PolynomialVector& A, const PolynomialVector& B,
        const PolynomialVector& C, const PolynomialVector& D,
        const std::vector<PolynomialVector>& E,
        const AuxiliaryCommitmentValue& commitment,
        const std::vector<std::uint8_t>& opening) const override {
        return commitment.bytes == std::vector<std::uint8_t>{0xa2} &&
               opening == std::vector<std::uint8_t>{0x5a} &&
               tuple_ == AuxiliaryTuple{A, B, C, D, E};
    }

private:
    AuxiliaryTuple tuple_;
};

CommitmentKey make_key(std::size_t message_dimension = 2) {
    const std::size_t degree = 86;
    const NTL::ZZ q = z(1000000007);
    const NTL::ZZ large_bound =
        z(1000000000) * z(1000000000) * z(1000000000) * z(1000000000);
    Parameters parameters{
        1, 1, message_dimension, degree, q, z(1),
        SquaredNormBound(large_bound, z(1))};
    Matrix G_r(1, 1, degree, q);
    Matrix G_m(1, message_dimension, degree, q);
    G_r.at(0, 0) = Polynomial(degree, q, {z(1)});
    return CommitmentKey(parameters, std::move(G_r), std::move(G_m));
}

Protocol2Parameters make_parameters() {
    return {1, 2,
            lattice_lrs::proofs::PositiveRational(z(1), z(1)),
            lattice_lrs::proofs::PositiveRational(z(1), z(1))};
}

Protocol2PublicList make_public_list(const CommitmentKey& key) {
    const auto& p = key.parameters();
    const PolynomialVector zero_message(
        p.v, Polynomial(p.degree, p.q));
    const PolynomialVector zero_randomness(
        p.m, Polynomial(p.degree, p.q));
    return {
        lattice_lrs::commitment::Com(key, zero_message, zero_randomness),
        PolynomialVector(p.n, Polynomial(p.degree, p.q)),
    };
}

Protocol2Witness make_witness(const CommitmentKey& key) {
    const auto& p = key.parameters();
    return {0, PolynomialVector(p.m, Polynomial(p.degree, p.q))};
}

struct ProverRun {
    Protocol2FirstMessage first;
    lattice_lrs::proofs::Protocol2ProverState state;
};

ProverRun begin_proof(const CommitmentKey& key,
                      const Protocol2Parameters& parameters,
                      const Protocol2PublicList& list,
                      const Protocol2Witness& witness,
                      RandomSource& random,
                      DiscreteGaussianProvider& gaussian,
                      Protocol2AuxiliaryCommitmentProvider& auxiliary) {
    auto begun = BeginProtocol2Proof(
        key, parameters, list, witness, random, gaussian, auxiliary);
    return {std::move(begun.first_message), std::move(begun.state)};
}

void rebind_auxiliary(Protocol2FirstMessage& first,
                      Protocol2Response& response,
                      TransparentTestAuxiliary& auxiliary,
                      RandomSource& random) {
    const AuxiliaryCommitmentOpening opening = auxiliary.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = opening.commitment;
    response.auxiliary_opening = opening.opening;
}

void test_round_trip_and_protocol2_widths() {
    const CommitmentKey key = make_key();
    const Protocol2Parameters parameters = make_parameters();
    const Protocol2PublicList list = make_public_list(key);
    const Protocol2Witness witness = make_witness(key);
    const Polynomial challenge = BinaryChallengeFromExponent(key.parameters(), 0);
    ZeroByteSource random;
    ZeroGaussian gaussian;
    AlwaysAccept exponential;
    TransparentTestAuxiliary auxiliary;

    ProverRun prover = begin_proof(
        key, parameters, list, witness, random, gaussian, auxiliary);
    const auto response = RespondProtocol2Proof(
        prover.state, key, parameters, challenge, random, exponential);
    require(response.has_value(), "deterministic test proof should not abort");
    require(VerifyProtocol2Proof(
                key, parameters, list, prover.first, challenge,
                *response, auxiliary),
            "Protocol 2 prover output should verify");
    require(exponential.calls == 2,
            "the first-stage and joint rejection decisions should both run");
    require(exponential.arguments.front() ==
                std::pair<NTL::ZZ, NTL::ZZ>{z(-25), z(2)},
            "Protocol 2 first-stage rejection must use the corrected -12/phi term");

    const NTL::ZZ p2_sigma_squared = z(3 * key.parameters().m *
                                        key.parameters().degree);
    require(gaussian.widths.size() == 4 * key.parameters().degree,
            "expected a, r_a, r_d, and rho Gaussian coefficient samples");
    for (std::size_t i = 0; i < key.parameters().degree; ++i) {
        require(gaussian.widths[i] ==
                    std::pair<NTL::ZZ, NTL::ZZ>{z(1), z(1)},
                "embedded binary masks must use phi1^2*k");
    }
    for (std::size_t i = key.parameters().degree;
         i < gaussian.widths.size(); ++i) {
        require(gaussian.widths[i] ==
                    std::pair<NTL::ZZ, NTL::ZZ>{p2_sigma_squared, z(1)},
                "Protocol 2 Gaussian widths must use sqrt(3md)");
    }
}

void test_protocol2_zero_digit_norm_bound() {
    const CommitmentKey key = make_key(3);
    const Protocol2Parameters parameters{
        1, 3,
        lattice_lrs::proofs::PositiveRational(z(1), z(1)),
        lattice_lrs::proofs::PositiveRational(z(1), z(1))};
    const auto& p = key.parameters();
    const Polynomial zero(p.degree, p.q);
    const PolynomialVector zero_n(p.n, zero);
    const PolynomialVector zero_message(p.v, zero);
    const PolynomialVector zero_opening(p.m, zero);
    const PolynomialVector zero_commitment =
        lattice_lrs::commitment::Com(key, zero_message, zero_opening);
    const Protocol2PublicList list(3, zero_commitment);

    Protocol2FirstMessage first;
    first.A = zero_n;
    first.B = zero_n;
    first.C = zero_n;
    first.D = zero_n;
    first.E = {zero_n};
    ZeroByteSource random;
    TransparentTestAuxiliary auxiliary;
    const AuxiliaryCommitmentOpening opening = auxiliary.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = opening.commitment;

    Protocol2Response response;
    response.f_nonzero = {
        Polynomial(p.degree, p.q, {z(35)}),
        Polynomial(p.degree, p.q, {z(35)})};
    response.auxiliary_opening = opening.opening;
    response.z = zero_opening;
    response.z_b = zero_opening;
    response.z_c = zero_opening;

    const Polynomial challenge =
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);
    require(VerifyProtocol2Proof(
                key, parameters, list, first, challenge, response, auxiliary),
            "Protocol 2 f_{j,0} bound must scale by (beta - 1) outside sqrt");
}

void test_hand_calculated_protocol2_list_equation_and_ordering() {
    const CommitmentKey key = make_key(4);
    const Protocol2Parameters parameters{
        2, 2,
        lattice_lrs::proofs::PositiveRational(z(1), z(1)),
        lattice_lrs::proofs::PositiveRational(z(1), z(1))};
    const auto& p = key.parameters();
    const Polynomial zero(p.degree, p.q);
    const PolynomialVector zero_n(p.n, zero);
    const PolynomialVector zero_m(p.m, zero);
    const PolynomialVector c0{Polynomial(p.degree, p.q, {z(1)})};
    const PolynomialVector c1{Polynomial(p.degree, p.q, {z(2)})};
    const PolynomialVector c2{Polynomial(p.degree, p.q, {z(3)})};
    const PolynomialVector c3{Polynomial(p.degree, p.q, {z(4)})};
    const Protocol2PublicList list{c0, c1, c2, c3};

    Protocol2FirstMessage first;
    first.A = zero_n;
    first.B = zero_n;
    first.C = zero_n;
    first.D = zero_n;
    first.E = {
        {Polynomial(p.degree, p.q, {z(5)})},
        {Polynomial(p.degree, p.q, {z(6)})},
    };
    ZeroByteSource random;
    TransparentTestAuxiliary auxiliary;
    Protocol2Response response;
    rebind_auxiliary(first, response, auxiliary, random);
    response.f_nonzero = {
        Polynomial(p.degree, p.q, {z(2)}),
        Polynomial(p.degree, p.q, {z(2)})};
    response.z = {
        Polynomial(p.degree, p.q, {z(-5), z(0), z(1)})};
    response.z_b = zero_m;
    response.z_c = zero_m;

    const Polynomial challenge =
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 1);
    require(VerifyProtocol2Proof(
                key, parameters, list, first, challenge, response, auxiliary),
            "hand-calculated ordered P2 list equation must verify");

    Protocol2PublicList reordered_list = list;
    std::swap(reordered_list[0], reordered_list[1]);
    require(!VerifyProtocol2Proof(
                key, parameters, reordered_list, first, challenge,
                response, auxiliary),
            "changing list order must change the P2 list equation");

    Protocol2FirstMessage reordered_E = first;
    std::swap(reordered_E.E[0], reordered_E.E[1]);
    Protocol2Response rebound_response = response;
    rebind_auxiliary(reordered_E, rebound_response, auxiliary, random);
    require(!VerifyProtocol2Proof(
                key, parameters, list, reordered_E, challenge,
                rebound_response, auxiliary),
            "E_j entries must be paired with the corresponding x^j");
}

void test_challenge_response_commitment_and_opening_failures() {
    const CommitmentKey key = make_key();
    const Protocol2Parameters parameters = make_parameters();
    const Protocol2PublicList list = make_public_list(key);
    const Protocol2Witness witness = make_witness(key);
    const Polynomial challenge = BinaryChallengeFromExponent(key.parameters(), 0);
    ZeroByteSource random;
    ZeroGaussian gaussian;
    AlwaysAccept exponential;
    TransparentTestAuxiliary auxiliary;

    ProverRun prover = begin_proof(
        key, parameters, list, witness, random, gaussian, auxiliary);
    auto response = RespondProtocol2Proof(
        prover.state, key, parameters, challenge, random, exponential);
    require(response.has_value(), "test proof should be produced");

    const Polynomial invalid_challenge(
        key.parameters().degree, key.parameters().q, {z(1), z(1)});
    require(!VerifyProtocol2Proof(
                key, parameters, list, prover.first, invalid_challenge,
                *response, auxiliary),
            "non-monomial challenge must be rejected");

    Protocol2Response tampered_response = *response;
    tampered_response.z_b[0] = Polynomial(
        key.parameters().degree, key.parameters().q, {z(7)});
    require(!VerifyProtocol2Proof(
                key, parameters, list, prover.first, challenge,
                tampered_response, auxiliary),
            "tampered response must be rejected");

    tampered_response = *response;
    tampered_response.auxiliary_opening[0] ^= 0x01;
    require(!VerifyProtocol2Proof(
                key, parameters, list, prover.first, challenge,
                tampered_response, auxiliary),
            "invalid auxiliary opening must be rejected");

    Protocol2FirstMessage tampered_first = prover.first;
    tampered_first.B[0] = tampered_first.B[0] + Polynomial(
        key.parameters().degree, key.parameters().q, {z(1)});
    Protocol2Response rebound_response = *response;
    rebind_auxiliary(tampered_first, rebound_response, auxiliary, random);
    require(!VerifyProtocol2Proof(
                key, parameters, list, tampered_first, challenge,
                rebound_response, auxiliary),
            "a changed proof commitment must fail the commitment equations");

    Protocol2PublicList tampered_list = list;
    tampered_list[0][0] = tampered_list[0][0] + Polynomial(
        key.parameters().degree, key.parameters().q, {z(1)});
    require(!VerifyProtocol2Proof(
                key, parameters, tampered_list, prover.first, challenge,
                *response, auxiliary),
            "a changed list commitment must fail verification");
}

void test_response_bounds_and_malformed_dimensions() {
    const CommitmentKey key = make_key();
    const Protocol2Parameters parameters = make_parameters();
    const Protocol2PublicList list = make_public_list(key);
    const Protocol2Witness witness = make_witness(key);
    const Polynomial challenge = BinaryChallengeFromExponent(key.parameters(), 0);
    ZeroByteSource random;
    ZeroGaussian gaussian;
    AlwaysAccept exponential;
    TransparentTestAuxiliary auxiliary;
    ProverRun prover = begin_proof(
        key, parameters, list, witness, random, gaussian, auxiliary);
    const auto response = RespondProtocol2Proof(
        prover.state, key, parameters, challenge, random, exponential);
    require(response.has_value(), "test proof should be produced");

    for (std::size_t block = 0; block < 3; ++block) {
        Protocol2Response over_bound = *response;
        PolynomialVector* values = block == 0 ? &over_bound.z
                                   : block == 1 ? &over_bound.z_b
                                                : &over_bound.z_c;
        (*values)[0] = Polynomial(
            key.parameters().degree, key.parameters().q, {z(1000)});
        require(!VerifyProtocol2Proof(
                    key, parameters, list, prover.first, challenge,
                    over_bound, auxiliary),
                "each response block exceeding its norm bound must be rejected");
    }

    Protocol2Response malformed = *response;
    malformed.z.pop_back();
    require(!VerifyProtocol2Proof(
                key, parameters, list, prover.first, challenge,
                malformed, auxiliary),
            "malformed response dimensions must be rejected");
    Protocol2FirstMessage malformed_first = prover.first;
    malformed_first.E.pop_back();
    require(!VerifyProtocol2Proof(
                key, parameters, list, malformed_first, challenge,
                *response, auxiliary),
            "malformed E_j dimensions must be rejected");
    Protocol2PublicList malformed_list = list;
    malformed_list.pop_back();
    require(!VerifyProtocol2Proof(
                key, parameters, malformed_list, prover.first, challenge,
                *response, auxiliary),
            "incorrect list size must be rejected");

    Protocol2Parameters invalid_parameters = make_parameters();
    invalid_parameters.k = 0;
    require(!VerifyProtocol2Proof(
                key, invalid_parameters, list, prover.first, challenge,
                *response, auxiliary),
            "invalid Protocol 2 parameters must be rejected");
}

void test_rejection_failures_propagate() {
    const CommitmentKey key = make_key();
    const Protocol2Parameters parameters = make_parameters();
    const Protocol2PublicList list = make_public_list(key);
    const Protocol2Witness witness = make_witness(key);
    const Polynomial challenge = BinaryChallengeFromExponent(key.parameters(), 0);
    ZeroByteSource random;
    ZeroGaussian gaussian;
    TransparentTestAuxiliary auxiliary;

    ProverRun aborting = begin_proof(
        key, parameters, list, witness, random, gaussian, auxiliary);
    RejectFirst rejecting;
    const auto aborted = RespondProtocol2Proof(
        aborting.state, key, parameters, challenge, random, rejecting);
    require(!aborted && rejecting.calls == 1,
            "rejection at the embedded binary stage should abort");

    ProverRun failing = begin_proof(
        key, parameters, list, witness, random, gaussian, auxiliary);
    AcceptThenThrow throwing;
    bool propagated = false;
    try {
        (void)RespondProtocol2Proof(
            failing.state, key, parameters, challenge, random, throwing);
    } catch (const std::runtime_error&) {
        propagated = true;
    }
    require(propagated && throwing.calls == 2,
            "joint rejection provider failure must propagate after stage one");
}

}  // namespace

int main() {
    try {
        test_round_trip_and_protocol2_widths();
        test_protocol2_zero_digit_norm_bound();
        test_hand_calculated_protocol2_list_equation_and_ordering();
        test_challenge_response_commitment_and_opening_failures();
        test_response_bounds_and_malformed_dimensions();
        test_rejection_failures_propagate();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 proof test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
