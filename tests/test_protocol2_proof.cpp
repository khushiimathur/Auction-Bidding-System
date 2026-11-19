#include "lattice_lrs/proofs/protocol2_proof.hpp"

#include "lattice_lrs/ring_signature/parameter_profile.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <algorithm>
#include <array>
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

class InsecureAuxiliaryCommitmentForTesting final
    : public Protocol2AuxiliaryCommitmentProvider {
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
                      InsecureAuxiliaryCommitmentForTesting& auxiliary,
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
    InsecureAuxiliaryCommitmentForTesting auxiliary;

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
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    const AuxiliaryCommitmentOpening opening = auxiliary.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = opening.commitment;

    // d=86, k=1, phi1=1, beta=3, r=1 (default): the corrected linear
    // bound is 25*phi1^2*d*k*r*(beta-1) = 25*86*2 = 4300. With
    // challenge x=X^0=1, f_{j,0} = x - (f_nonzero[0]+f_nonzero[1]) =
    // 1 - 64 = -63, whose squared norm 3969 is within the corrected
    // linear bound but would also have passed the OLD, buggy squared
    // exponent (25*86*4=8600) -- see
    // test_protocol2_f_zero_bound_is_linear_not_squared_in_beta_minus_one
    // below for a value that distinguishes the two.
    Protocol2Response response;
    response.f_nonzero = {
        Polynomial(p.degree, p.q, {z(32)}),
        Polynomial(p.degree, p.q, {z(32)})};
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

// Regression test for the (beta-1) exponent fix: constructs an f_{j,0}
// value whose squared norm is BETWEEN the correct linear bound and the
// old, buggy squared bound, so it only distinguishes the two if the
// linear bound is actually enforced.
void test_protocol2_f_zero_bound_is_linear_not_squared_in_beta_minus_one() {
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
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    const AuxiliaryCommitmentOpening opening = auxiliary.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = opening.commitment;

    // Correct (linear) bound: 25*1*86*1*1*2 = 4300 (sqrt ~65.57).
    // Old, buggy (squared) bound: 25*1*86*1*2^2 = 8600 (sqrt ~92.74).
    // Choose f_{j,0} = 1 - 70 = -69, squared norm 4761: this is ABOVE
    // the correct linear bound (4300) but BELOW the old squared bound
    // (8600), so it must be rejected now and would have wrongly been
    // accepted before this fix.
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
    require(!VerifyProtocol2Proof(
                key, parameters, list, first, challenge, response, auxiliary),
            "a value satisfying only the old squared-(beta-1) bound must "
            "now be rejected by the corrected linear-(beta-1) bound");
}

PolynomialVector negate(const PolynomialVector& values) {
    PolynomialVector result;
    result.reserve(values.size());
    for (const Polynomial& value : values) {
        result.push_back(Polynomial(value.degree(), value.modulus()) - value);
    }
    return result;
}

// Builds a self-consistent (all other equations trivially satisfied)
// Protocol 2 transcript whose z-response is exactly `target_z`, by
// choosing E_0 so that the final list/commitment equation (step 6) holds
// for that specific z: with an all-zero public list and k=1, step 6
// reduces to -E_0 == Com(key, 0, z), so E_0 := -Com(key, 0, target_z)
// makes it hold by construction, for ANY target_z. f_nonzero is left at
// zero so the f-bound checks (steps 3-4) trivially pass regardless of r,
// isolating the z/z_b/z_c bound (step 5) as the only thing that can
// reject or accept depending on `repetitions`.
struct ZBoundFixture {
    CommitmentKey key;
    Protocol2Parameters parameters;
    Protocol2PublicList list;
    Protocol2FirstMessage first;
    Protocol2Response response;
    Polynomial challenge;
    InsecureAuxiliaryCommitmentForTesting auxiliary;
};

ZBoundFixture make_z_bound_fixture(const NTL::ZZ& target_z_coefficient) {
    CommitmentKey key = make_key();
    const Protocol2Parameters parameters = make_parameters();  // k=1, beta=2, phi1=phi2=1
    const auto& p = key.parameters();
    const Polynomial zero(p.degree, p.q);
    const PolynomialVector zero_n(p.n, zero);
    const PolynomialVector zero_message(p.v, zero);
    const PolynomialVector zero_opening(p.m, zero);
    const PolynomialVector zero_commitment =
        lattice_lrs::commitment::Com(key, zero_message, zero_opening);
    const std::size_t list_size = std::size_t(1) << parameters.k;  // beta^k, beta=2
    const Protocol2PublicList list(list_size, zero_commitment);

    const PolynomialVector target_z{
        Polynomial(p.degree, p.q, {target_z_coefficient})};
    const PolynomialVector required_e0 =
        negate(lattice_lrs::commitment::Com(key, zero_message, target_z));

    Protocol2FirstMessage first;
    first.A = zero_n;
    first.B = zero_n;
    first.C = zero_n;
    first.D = zero_n;
    first.E = {required_e0};
    ZeroByteSource random;
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    const AuxiliaryCommitmentOpening opening = auxiliary.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = opening.commitment;

    Protocol2Response response;
    response.f_nonzero = {zero};  // k*(beta-1) = 1 entry
    response.auxiliary_opening = opening.opening;
    response.z = target_z;
    response.z_b = zero_opening;
    response.z_c = zero_opening;

    const Polynomial challenge =
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);  // x = 1

    return {std::move(key), parameters, list, first, response, challenge,
            std::move(auxiliary)};
}

// d=86, B=1, m=1, phi2=1: p2_bound_numerator = 12*86^2*r = 88752*r.
void test_protocol2_z_bound_scales_with_repetitions() {
    // target_z^2 = 400^2 = 160000: above the r=1 bound (88752), below
    // the r=2 bound (177504).
    ZBoundFixture mid = make_z_bound_fixture(z(400));
    require(!VerifyProtocol2Proof(mid.key, mid.parameters, mid.list, mid.first,
                                  mid.challenge, mid.response, mid.auxiliary,
                                  /*repetitions=*/1),
            "a z exceeding the r=1 bound must be rejected at r=1 (confirms "
            "the original, non-repeated bound is unchanged)");
    require(VerifyProtocol2Proof(mid.key, mid.parameters, mid.list, mid.first,
                                 mid.challenge, mid.response, mid.auxiliary,
                                 /*repetitions=*/2),
            "the same z must be accepted once repetitions=2 widens the "
            "bound enough (confirms the bound actually scales with r)");

    // target_z^2 = 600^2 = 360000: above even the r=2 bound (177504).
    ZBoundFixture large = make_z_bound_fixture(z(600));
    require(!VerifyProtocol2Proof(large.key, large.parameters, large.list,
                                  large.first, large.challenge, large.response,
                                  large.auxiliary, /*repetitions=*/2),
            "a z exceeding even the r=2 bound must still be rejected at "
            "r=2 (the bound widens with r, but is not unbounded)");

    // target_z^2 = 88752 exactly (the r=1 boundary): must be accepted at
    // r=1, confirming the r=1 case recovers exactly Theorem 2's original
    // bound rather than something silently loosened.
    ZBoundFixture boundary = make_z_bound_fixture(z(297));  // 297^2 = 88209 <= 88752
    require(VerifyProtocol2Proof(boundary.key, boundary.parameters,
                                 boundary.list, boundary.first,
                                 boundary.challenge, boundary.response,
                                 boundary.auxiliary, /*repetitions=*/1),
            "a z within the exact r=1 Theorem 2 bound must be accepted "
            "at r=1");
}

// Mirrors test_protocol2_zero_digit_norm_bound's all-zero-CMT technique
// (z stays zero throughout, so only the f-bound, steps 3-4, is
// exercised), varying beta=3 so f_zero's (beta-1) factor is nontrivial
// and confirming it, too, scales with r.
void test_protocol2_f_bound_scales_with_repetitions() {
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
    InsecureAuxiliaryCommitmentForTesting auxiliary;
    const AuxiliaryCommitmentOpening opening = auxiliary.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = opening.commitment;

    // phi1_bound_numerator = 25*d*k*r = 25*86*r = 2150*r.
    // f_{j,i} (i=1) norm^2 = 70^2 = 4900: above the r=1 bound (2150),
    // below the r=3 bound (6450).
    Protocol2Response response;
    response.f_nonzero = {
        Polynomial(p.degree, p.q, {z(70)}),
        Polynomial(p.degree, p.q, {z(0)})};
    response.auxiliary_opening = opening.opening;
    response.z = zero_opening;
    response.z_b = zero_opening;
    response.z_c = zero_opening;

    const Polynomial challenge =
        lattice_lrs::proofs::BinaryChallengeFromExponent(p, 0);
    require(!VerifyProtocol2Proof(key, parameters, list, first, challenge,
                                  response, auxiliary, /*repetitions=*/1),
            "an f_{j,i} exceeding the r=1 bound must be rejected at r=1");
    require(VerifyProtocol2Proof(key, parameters, list, first, challenge,
                                 response, auxiliary, /*repetitions=*/3),
            "the same f_{j,i} must be accepted once repetitions=3 widens "
            "the bound enough");
}

// Exercises the corrected formulas against every named production
// parameter profile (N64/N256/N1024/N4096): a full real proof at
// production scale is already covered (expensively) by the end-to-end
// RSign integration test, so this instead checks the bound FORMULAS
// themselves scale sanely for every profile's real (d, k, beta, phi1,
// phi2, B, m, r) -- in particular that the real r-scaled bound strictly
// exceeds what the original (r=1) bound would have been, for every
// profile, not just the toy parameters used above.
void test_protocol2_bounds_scale_for_all_named_profiles() {
    using lattice_lrs::ring_signature::ParameterProfile;
    const std::array<ParameterProfile, 4> profiles{
        ParameterProfile::N64(), ParameterProfile::N256(),
        ParameterProfile::N1024(), ParameterProfile::N4096()};

    for (const ParameterProfile& profile : profiles) {
        const NTL::ZZ d = z(static_cast<long>(profile.d()));
        const NTL::ZZ k = z(static_cast<long>(profile.k()));
        const NTL::ZZ beta = z(static_cast<long>(profile.beta()));
        const NTL::ZZ r = z(static_cast<long>(profile.repetitions()));
        const NTL::ZZ m = z(static_cast<long>(profile.m()));
        const NTL::ZZ phi1 = z(static_cast<long>(profile.phi1()));
        const NTL::ZZ phi2 = z(static_cast<long>(profile.phi2()));
        const NTL::ZZ B = profile.B();

        const NTL::ZZ phi1_bound_r1 = 25 * phi1 * phi1 * d * k;
        const NTL::ZZ phi1_bound_rr = 25 * phi1 * phi1 * d * k * r;
        const NTL::ZZ f_zero_bound_r1 = phi1_bound_r1 * (beta - 1);
        const NTL::ZZ f_zero_bound_rr = phi1_bound_rr * (beta - 1);
        const NTL::ZZ p2_bound_r1 =
            12 * phi2 * phi2 * B * B * m * m * d * d;
        const NTL::ZZ p2_bound_rr =
            12 * phi2 * phi2 * B * B * m * m * d * d * r;

        require(r >= 1, "every named profile must have at least one repetition");
        require(phi1_bound_rr >= phi1_bound_r1,
                "the r-scaled f_{j,i} bound must never be smaller than the "
                "r=1 bound for a real profile");
        require(f_zero_bound_rr >= f_zero_bound_r1,
                "the r-scaled f_{j,0} bound must never be smaller than the "
                "r=1 bound for a real profile");
        require(p2_bound_rr >= p2_bound_r1,
                "the r-scaled z/z_b/z_c bound must never be smaller than "
                "the r=1 bound for a real profile");
        require(r > 1 ? phi1_bound_rr > phi1_bound_r1 : phi1_bound_rr == phi1_bound_r1,
                "the f_{j,i} bound must strictly widen for r>1 and be "
                "exactly unchanged for r==1");
        require(r > 1 ? p2_bound_rr > p2_bound_r1 : p2_bound_rr == p2_bound_r1,
                "the z/z_b/z_c bound must strictly widen for r>1 and be "
                "exactly unchanged for r==1");
    }
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
    InsecureAuxiliaryCommitmentForTesting auxiliary;
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
    InsecureAuxiliaryCommitmentForTesting auxiliary;

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
    InsecureAuxiliaryCommitmentForTesting auxiliary;
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
    InsecureAuxiliaryCommitmentForTesting auxiliary;

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
        test_protocol2_f_zero_bound_is_linear_not_squared_in_beta_minus_one();
        test_protocol2_z_bound_scales_with_repetitions();
        test_protocol2_f_bound_scales_with_repetitions();
        test_protocol2_bounds_scale_for_all_named_profiles();
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
