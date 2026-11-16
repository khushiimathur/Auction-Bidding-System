#include "lattice_lrs/proofs/binary_proof.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace lattice_lrs::proofs {
namespace {

using sampling::PolynomialVector;

struct RationalBound {
    NTL::ZZ numerator;
    NTL::ZZ denominator;
};

NTL::ZZ zz(std::size_t value) {
    if (value > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        throw std::length_error("binary-proof dimensions exceed NTL's signed index range");
    }
    return NTL::to_ZZ(static_cast<long>(value));
}

std::size_t checked_product(std::size_t left, std::size_t right) {
    if (right != 0 && left > std::numeric_limits<std::size_t>::max() / right) {
        throw std::length_error("binary-proof dimensions overflow");
    }
    return left * right;
}

std::size_t checked_sum(std::size_t left, std::size_t right) {
    if (left > std::numeric_limits<std::size_t>::max() - right) {
        throw std::length_error("binary-proof vector dimension overflows");
    }
    return left + right;
}

bool same_ring(const PolynomialVector& values, std::size_t count,
               const commitment::Parameters& parameters) {
    if (values.size() != count) return false;
    return std::all_of(values.begin(), values.end(), [&](const auto& value) {
        return value.degree() == parameters.degree && value.modulus() == parameters.q;
    });
}

PolynomialVector from_lift(const std::vector<NTL::ZZ>& lift, std::size_t count,
                           const commitment::Parameters& parameters) {
    const std::size_t expected = checked_product(count, parameters.degree);
    if (lift.size() != expected) {
        throw std::invalid_argument("integer lift has an incompatible dimension");
    }
    PolynomialVector result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto first = lift.begin() + static_cast<std::ptrdiff_t>(i * parameters.degree);
        std::vector<NTL::ZZ> coefficients(first, first + parameters.degree);
        result.emplace_back(parameters.degree, parameters.q, coefficients);
    }
    return result;
}

std::vector<NTL::ZZ> centered_lift(const PolynomialVector& values) {
    std::size_t count = 0;
    for (const auto& value : values) {
        count = checked_sum(count, value.degree());
    }
    std::vector<NTL::ZZ> result;
    result.reserve(count);
    for (const auto& value : values) {
        for (std::size_t i = 0; i < value.degree(); ++i) {
            result.push_back(value.centered_coefficient(i));
        }
    }
    return result;
}

NTL::ZZ norm_squared(const std::vector<NTL::ZZ>& values) {
    NTL::ZZ result(0);
    for (const NTL::ZZ& value : values) result += value * value;
    return result;
}

NTL::ZZ norm_squared(const arithmetic::Polynomial& value) {
    NTL::ZZ result(0);
    for (std::size_t i = 0; i < value.degree(); ++i) {
        const NTL::ZZ coefficient = value.centered_coefficient(i);
        result += coefficient * coefficient;
    }
    return result;
}

bool within_squared_bound(const NTL::ZZ& value_squared,
                          const NTL::ZZ& bound_numerator,
                          const NTL::ZZ& bound_denominator) {
    return value_squared * bound_denominator <= bound_numerator;
}

struct Monomial {
    std::size_t degree;
    bool negative;
};

Monomial require_monomial(const arithmetic::Polynomial& challenge) {
    std::size_t nonzero_count = 0;
    std::size_t index = 0;
    bool negative = false;
    const NTL::ZZ& q = challenge.modulus();
    for (std::size_t i = 0; i < challenge.degree(); ++i) {
        const NTL::ZZ& coefficient = challenge.coefficient(i);
        if (coefficient == 0) continue;
        ++nonzero_count;
        index = i;
        if (coefficient == 1) {
            negative = false;
        } else if (coefficient == q - 1) {
            negative = true;
        } else {
            throw std::invalid_argument("binary-proof challenge is not a monomial");
        }
    }
    if (nonzero_count != 1) {
        throw std::invalid_argument("binary-proof challenge must be a signed monomial");
    }
    return {index, negative};
}

std::vector<NTL::ZZ> multiply_by_monomial(const std::vector<NTL::ZZ>& input,
                                         std::size_t polynomial_count,
                                         std::size_t degree,
                                         const Monomial& monomial) {
    if (input.size() != checked_product(polynomial_count, degree)) {
        throw std::invalid_argument("monomial multiplication input has wrong dimension");
    }
    std::vector<NTL::ZZ> result(input.size(), NTL::ZZ(0));
    for (std::size_t polynomial = 0; polynomial < polynomial_count; ++polynomial) {
        const std::size_t base = polynomial * degree;
        for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
            const std::size_t exponent = coefficient + monomial.degree;
            const std::size_t target = exponent % degree;
            const bool wrap_negative = (exponent >= degree) != monomial.negative;
            result[base + target] = wrap_negative ? -input[base + coefficient]
                                                  : input[base + coefficient];
        }
    }
    return result;
}

std::vector<NTL::ZZ> add_lifts(const std::vector<NTL::ZZ>& left,
                               const std::vector<NTL::ZZ>& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("integer vectors have incompatible dimensions");
    }
    std::vector<NTL::ZZ> result(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) result[i] = left[i] + right[i];
    return result;
}

std::vector<NTL::ZZ> concatenate(const std::vector<NTL::ZZ>& first,
                                 const std::vector<NTL::ZZ>& second) {
    std::vector<NTL::ZZ> result;
    result.reserve(checked_sum(first.size(), second.size()));
    result.insert(result.end(), first.begin(), first.end());
    result.insert(result.end(), second.begin(), second.end());
    return result;
}

bool q_bound_holds(const commitment::Parameters& p,
                   const BinaryProofParameters& proof) {
    // q > (10*phi1*d*sqrt(k*d*(beta-1)) + 2)^2, compared exactly
    // after multiplying by phi1.denominator^2 and squaring the remaining
    // nonnegative radical inequality.
    const NTL::ZZ a = 10 * proof.phi1.numerator * zz(p.degree);
    const NTL::ZZ t = proof.phi1.denominator;
    const NTL::ZZ radical_squared = zz(proof.k) * zz(p.degree) * zz(proof.beta - 1);
    const NTL::ZZ residual = p.q * t * t - a * a * radical_squared - 4 * t * t;
    return residual > 0 && residual * residual > 16 * a * a * t * t * radical_squared;
}

RationalBound commitment_binding_bound_squared(const commitment::Parameters& p,
                                               const BinaryProofParameters& proof) {
    // Protocol 1 / Theorem 1 (Esgin et al., Sec. 4):
    // T=(2d+2)*sqrt(54*phi1^4*d^3*k^3*beta*(beta-1)
    //                  +12*phi2^2*B^2*m^2*d^2).
    const NTL::ZZ p1 = proof.phi1.numerator;
    const NTL::ZZ d1 = proof.phi1.denominator;
    const NTL::ZZ p2 = proof.phi2.numerator;
    const NTL::ZZ d2 = proof.phi2.denominator;
    const NTL::ZZ d = zz(p.degree);
    const NTL::ZZ k = zz(proof.k);
    const NTL::ZZ beta = zz(proof.beta);
    const NTL::ZZ m = zz(p.m);
    const NTL::ZZ common_denominator = d1 * d1 * d1 * d1 * d2 * d2;
    const NTL::ZZ first = 54 * p1 * p1 * p1 * p1 * d * d * d * k * k * k *
                          beta * zz(proof.beta - 1) * d2 * d2;
    const NTL::ZZ second = 12 * p2 * p2 * p.B * p.B * m * m * d * d *
                           d1 * d1 * d1 * d1;
    const NTL::ZZ scale = 2 * d + 2;
    return {scale * scale * (first + second), common_denominator};
}

bool commitment_bound_is_sufficient(const commitment::Parameters& p,
                                    const BinaryProofParameters& proof) {
    const auto required = commitment_binding_bound_squared(p, proof);
    return p.T_com_squared.numerator * required.denominator >=
           required.numerator * p.T_com_squared.denominator;
}

void validate_proof_input(const commitment::CommitmentKey& key,
                          const BinaryProofParameters& proof,
                          const PolynomialVector& public_commitment,
                          const BinaryProofFirstMessage& first,
                          const arithmetic::Polynomial& challenge,
                          const BinaryProofResponse& response) {
    const auto& p = key.parameters();
    proof.validate(key);
    if (!same_ring(public_commitment, p.n, p) ||
        !same_ring(first.A, p.n, p) || !same_ring(first.C, p.n, p) ||
        !same_ring(first.D, p.n, p) ||
        !same_ring(response.f_nonzero, proof.k * (proof.beta - 1), p) ||
        !same_ring(response.z_b, p.m, p) || !same_ring(response.z_c, p.m, p) ||
        challenge.degree() != p.degree || challenge.modulus() != p.q) {
        throw std::invalid_argument("binary-proof transcript dimensions or rings are invalid");
    }
    (void)require_monomial(challenge);
}

std::vector<arithmetic::Polynomial> reconstruct_f(
    const BinaryProofParameters& proof, const arithmetic::Polynomial& challenge,
    const PolynomialVector& f_nonzero) {
    std::vector<arithmetic::Polynomial> f;
    f.reserve(checked_product(proof.k, proof.beta));
    for (std::size_t row = 0; row < proof.k; ++row) {
        arithmetic::Polynomial f_zero = challenge;
        for (std::size_t i = 1; i < proof.beta; ++i) {
            f_zero = f_zero - f_nonzero[row * (proof.beta - 1) + (i - 1)];
        }
        f.push_back(std::move(f_zero));
        for (std::size_t i = 1; i < proof.beta; ++i) {
            f.push_back(f_nonzero[row * (proof.beta - 1) + (i - 1)]);
        }
    }
    return f;
}

bool verify_norms(const commitment::Parameters& p,
                  const BinaryProofParameters& proof,
                  const std::vector<arithmetic::Polynomial>& f,
                  const BinaryProofResponse& response) {
    const NTL::ZZ phi1_bound_numerator = 25 * proof.phi1.numerator *
        proof.phi1.numerator * zz(p.degree) * zz(proof.k);
    const NTL::ZZ phi1_bound_denominator = proof.phi1.denominator * proof.phi1.denominator;
    const NTL::ZZ f_zero_bound = phi1_bound_numerator * zz(proof.beta - 1);
    for (std::size_t row = 0; row < proof.k; ++row) {
        if (!within_squared_bound(norm_squared(f[row * proof.beta]),
                                  f_zero_bound, phi1_bound_denominator)) {
            return false;
        }
        for (std::size_t i = 1; i < proof.beta; ++i) {
            if (!within_squared_bound(norm_squared(f[row * proof.beta + i]),
                                      phi1_bound_numerator, phi1_bound_denominator)) {
                return false;
            }
        }
    }

    const NTL::ZZ phi2_bound_numerator = 8 * proof.phi2.numerator *
        proof.phi2.numerator * p.B * p.B * zz(p.m) * zz(p.m) *
        zz(p.degree) * zz(p.degree);
    const NTL::ZZ phi2_bound_denominator = proof.phi2.denominator * proof.phi2.denominator;
    return within_squared_bound(norm_squared(centered_lift(response.z_b)),
                                phi2_bound_numerator, phi2_bound_denominator) &&
           within_squared_bound(norm_squared(centered_lift(response.z_c)),
                                phi2_bound_numerator, phi2_bound_denominator);
}

std::vector<NTL::ZZ> sample_gaussian_lift(std::size_t coefficient_count,
                                         const NTL::ZZ& sigma_squared_numerator,
                                         const NTL::ZZ& sigma_squared_denominator,
                                         sampling::RandomSource& random,
                                         DiscreteGaussianProvider& gaussian) {
    std::vector<NTL::ZZ> result;
    result.reserve(coefficient_count);
    for (std::size_t i = 0; i < coefficient_count; ++i) {
        result.push_back(gaussian.sample_coefficient(sigma_squared_numerator,
                                                     sigma_squared_denominator, random));
    }
    return result;
}

bool rej_accepts(const std::vector<NTL::ZZ>& z,
                 const std::vector<NTL::ZZ>& c,
                 const PositiveRational& phi,
                 const NTL::ZZ& K_squared,
                 sampling::RandomSource& random,
                 BernoulliExponentialProvider& exponential) {
    if (z.size() != c.size() || K_squared <= 0) {
        throw std::invalid_argument("rejection-sampling vectors or bound are invalid");
    }
    NTL::ZZ inner_product(0);
    NTL::ZZ c_norm_squared(0);
    for (std::size_t i = 0; i < z.size(); ++i) {
        inner_product += z[i] * c[i];
        c_norm_squared += c[i] * c[i];
    }

    const NTL::ZZ p = phi.numerator;
    const NTL::ZZ t = phi.denominator;
    const NTL::ZZ exponent_denominator = 2 * p * p * K_squared;
    const NTL::ZZ exponent_numerator =
        -(2 * p * t + t * t) * K_squared +
        t * t * (-2 * inner_product + c_norm_squared);
    if (exponent_numerator >= 0) {
        // Algorithm 1 compares a uniform u in [0,1) with exp(r). When r >= 0,
        // the threshold is at least one, so this branch accepts with certainty.
        return true;
    }
    return exponential.sample_exp(exponent_numerator, exponent_denominator, random);
}

}  // namespace

PositiveRational::PositiveRational(const NTL::ZZ& numerator_value,
                                   const NTL::ZZ& denominator_value)
    : numerator(numerator_value), denominator(denominator_value) {
    if (numerator <= 0 || denominator <= 0) {
        throw std::invalid_argument("binary-proof rational parameters must be positive");
    }
}

void BinaryProofParameters::validate(const commitment::CommitmentKey& key) const {
    const auto& p = key.parameters();
    p.validate();
    if (phi1.numerator <= 0 || phi1.denominator <= 0 ||
        phi2.numerator <= 0 || phi2.denominator <= 0) {
        throw std::invalid_argument("Protocol 1 rejection parameters must be positive rationals");
    }
    if (k == 0 || beta < 2 || k > std::numeric_limits<std::size_t>::max() / beta ||
        p.v != k * beta) {
        throw std::invalid_argument("binary-proof parameters require v=k*beta, k>0, beta>=2");
    }
    if (p.degree < 7 || checked_product(p.m, p.degree) < 86) {
        throw std::invalid_argument("Protocol 1 requires d>=7 and m*d>=86");
    }
    if (2 * p.B >= p.q) {
        throw std::invalid_argument("bounded coefficient interval must be injective modulo q");
    }
    if (!q_bound_holds(p, *this)) {
        throw std::invalid_argument("modulus q does not satisfy Esgin Protocol 1's lower bound");
    }
    if (!commitment_bound_is_sufficient(p, *this)) {
        throw std::invalid_argument("commitment norm bound is below Protocol 1's T-binding bound");
    }
}

BinaryProofBeginResult BeginBinaryProof(
    const commitment::CommitmentKey& key,
    const BinaryProofParameters& parameters,
    const PolynomialVector& public_commitment,
    const BinaryWitness& witness,
    sampling::RandomSource& random,
    DiscreteGaussianProvider& gaussian,
    AuxiliaryCommitmentProvider& auxiliary_commitment) {
    parameters.validate(key);
    const auto& p = key.parameters();
    if (!same_ring(public_commitment, p.n, p) ||
        !same_ring(witness.bits, p.v, p) ||
        !same_ring(witness.randomness, p.m, p)) {
        throw std::invalid_argument("binary witness or commitment has incompatible dimensions/ring");
    }

    std::vector<NTL::ZZ> bits_lift(checked_product(p.v, p.degree), NTL::ZZ(0));
    for (std::size_t row = 0; row < parameters.k; ++row) {
        std::size_t row_weight = 0;
        for (std::size_t digit = 0; digit < parameters.beta; ++digit) {
            const auto& bit = witness.bits[row * parameters.beta + digit];
            if (bit.coefficient(0) != 0 && bit.coefficient(0) != 1) {
                throw std::invalid_argument("binary witness entry is not 0 or 1");
            }
            for (std::size_t coefficient = 1; coefficient < p.degree; ++coefficient) {
                if (bit.coefficient(coefficient) != 0) {
                    throw std::invalid_argument("binary witness entries must be constant polynomials");
                }
            }
            if (bit.coefficient(0) == 1) ++row_weight;
            bits_lift[(row * parameters.beta + digit) * p.degree] = bit.coefficient(0);
        }
        if (row_weight != 1) {
            throw std::invalid_argument("each binary witness row must have Hamming weight one");
        }
    }

    std::vector<NTL::ZZ> witness_randomness_lift = centered_lift(witness.randomness);
    const NTL::ZZ randomness_bound_squared = p.B * p.B * zz(p.m) * zz(p.degree);
    for (const NTL::ZZ& coefficient : witness_randomness_lift) {
        if (coefficient < -p.B || coefficient > p.B) {
            throw std::invalid_argument("binary witness randomness is outside S_B");
        }
    }
    if (norm_squared(witness_randomness_lift) > randomness_bound_squared) {
        throw std::invalid_argument("binary witness randomness exceeds its Euclidean bound");
    }
    if (commitment::Com(key, witness.bits, witness.randomness) != public_commitment) {
        throw std::invalid_argument("binary witness does not open the public commitment");
    }

    std::vector<NTL::ZZ> a_lift(checked_product(p.v, p.degree), NTL::ZZ(0));
    const NTL::ZZ a_sigma_squared_numerator =
        parameters.phi1.numerator * parameters.phi1.numerator * zz(parameters.k);
    const NTL::ZZ a_sigma_squared_denominator =
        parameters.phi1.denominator * parameters.phi1.denominator;
    for (std::size_t row = 0; row < parameters.k; ++row) {
        for (std::size_t digit = 1; digit < parameters.beta; ++digit) {
            const std::size_t offset = (row * parameters.beta + digit) * p.degree;
            for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
                a_lift[offset + coefficient] = gaussian.sample_coefficient(
                    a_sigma_squared_numerator, a_sigma_squared_denominator, random);
            }
        }
        for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
            NTL::ZZ sum(0);
            for (std::size_t digit = 1; digit < parameters.beta; ++digit) {
                sum += a_lift[(row * parameters.beta + digit) * p.degree + coefficient];
            }
            a_lift[(row * parameters.beta) * p.degree + coefficient] = -sum;
        }
    }

    std::vector<NTL::ZZ> r_c_lift(checked_product(p.m, p.degree));
    for (NTL::ZZ& coefficient : r_c_lift) {
        coefficient = sampling::sample_bounded_coefficient(p.B, random);
    }
    const NTL::ZZ randomness_sigma_squared_numerator = parameters.phi2.numerator *
        parameters.phi2.numerator * p.B * p.B * 2 * zz(p.m) * zz(p.degree);
    const NTL::ZZ randomness_sigma_squared_denominator = parameters.phi2.denominator *
        parameters.phi2.denominator;
    std::vector<NTL::ZZ> r_a_lift = sample_gaussian_lift(
        checked_product(p.m, p.degree), randomness_sigma_squared_numerator,
        randomness_sigma_squared_denominator, random, gaussian);
    std::vector<NTL::ZZ> r_d_lift = sample_gaussian_lift(
        checked_product(p.m, p.degree), randomness_sigma_squared_numerator,
        randomness_sigma_squared_denominator, random, gaussian);

    const PolynomialVector a = from_lift(a_lift, p.v, p);
    const PolynomialVector r_c = from_lift(r_c_lift, p.m, p);
    const PolynomialVector r_a = from_lift(r_a_lift, p.m, p);
    const PolynomialVector r_d = from_lift(r_d_lift, p.m, p);
    PolynomialVector c_message;
    PolynomialVector d_message;
    c_message.reserve(p.v);
    d_message.reserve(p.v);
    for (std::size_t i = 0; i < p.v; ++i) {
        const NTL::ZZ bit = bits_lift[i * p.degree];
        std::vector<NTL::ZZ> signed_a(p.degree);
        for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
            const NTL::ZZ value = a_lift[i * p.degree + coefficient];
            signed_a[coefficient] = bit == 1 ? -value : value;
        }
        c_message.emplace_back(p.degree, p.q, signed_a);
        d_message.push_back(arithmetic::Polynomial(p.degree, p.q) - (a[i] * a[i]));
    }

    BinaryProofFirstMessage first;
    first.A = commitment::Com(key, a, r_a);
    first.C = commitment::Com(key, c_message, r_c);
    first.D = commitment::Com(key, d_message, r_d);
    AuxiliaryCommitmentOpening auxiliary = auxiliary_commitment.commit(
        first.A, first.C, first.D, random);
    first.auxiliary_commitment = std::move(auxiliary.commitment);

    BinaryProofProverState state;
    state.bits_ = witness.bits;
    state.witness_randomness_lift_ = std::move(witness_randomness_lift);
    state.a_lift_ = std::move(a_lift);
    state.r_c_lift_ = std::move(r_c_lift);
    state.r_a_lift_ = std::move(r_a_lift);
    state.r_d_lift_ = std::move(r_d_lift);
    state.auxiliary_opening_ = std::move(auxiliary.opening);
    return {std::move(first), std::move(state)};
}

std::optional<BinaryProofResponse> RespondBinaryProof(
    BinaryProofProverState& state,
    const commitment::CommitmentKey& key,
    const BinaryProofParameters& parameters,
    const arithmetic::Polynomial& challenge,
    sampling::RandomSource& random,
    BernoulliExponentialProvider& exponential) {
    if (state.consumed_) {
        throw std::logic_error("binary-proof prover state has already been consumed");
    }
    state.consumed_ = true;
    parameters.validate(key);
    const auto monomial = require_monomial(challenge);
    const auto& p = key.parameters();
    if (challenge.degree() != p.degree || challenge.modulus() != p.q) {
        throw std::invalid_argument("binary-proof challenge uses the wrong ring");
    }

    const std::vector<NTL::ZZ> x_bits = multiply_by_monomial(
        [&] {
            std::vector<NTL::ZZ> result;
            result.reserve(state.bits_.size() * p.degree);
            for (const auto& bit : state.bits_) {
                for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
                    result.push_back(coefficient == 0 ? bit.coefficient(0) : NTL::ZZ(0));
                }
            }
            return result;
        }(), p.v, p.degree, monomial);
    std::vector<NTL::ZZ> f_lift = add_lifts(state.a_lift_, x_bits);

    std::vector<NTL::ZZ> f_nonzero_lift;
    std::vector<NTL::ZZ> x_b_nonzero;
    f_nonzero_lift.reserve(parameters.k * (parameters.beta - 1) * p.degree);
    x_b_nonzero.reserve(f_nonzero_lift.capacity());
    for (std::size_t row = 0; row < parameters.k; ++row) {
        for (std::size_t digit = 1; digit < parameters.beta; ++digit) {
            const std::size_t offset = (row * parameters.beta + digit) * p.degree;
            for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
                f_nonzero_lift.push_back(f_lift[offset + coefficient]);
                x_b_nonzero.push_back(x_bits[offset + coefficient]);
            }
        }
    }
    if (!rej_accepts(f_nonzero_lift, x_b_nonzero, parameters.phi1,
                     zz(parameters.k), random, exponential)) {
        return std::nullopt;
    }

    const std::vector<NTL::ZZ> x_witness_randomness = multiply_by_monomial(
        state.witness_randomness_lift_, p.m, p.degree, monomial);
    const std::vector<NTL::ZZ> x_r_c = multiply_by_monomial(
        state.r_c_lift_, p.m, p.degree, monomial);
    const std::vector<NTL::ZZ> z_b_lift = add_lifts(x_witness_randomness, state.r_a_lift_);
    const std::vector<NTL::ZZ> z_c_lift = add_lifts(x_r_c, state.r_d_lift_);
    const std::vector<NTL::ZZ> second_z = concatenate(z_b_lift, z_c_lift);
    const std::vector<NTL::ZZ> second_c = concatenate(x_witness_randomness, x_r_c);
    const NTL::ZZ K_squared = p.B * p.B * 2 * zz(p.m) * zz(p.degree);
    if (!rej_accepts(second_z, second_c, parameters.phi2, K_squared,
                     random, exponential)) {
        return std::nullopt;
    }

    BinaryProofResponse response;
    response.f_nonzero = from_lift(f_nonzero_lift,
                                    parameters.k * (parameters.beta - 1), p);
    response.auxiliary_opening = state.auxiliary_opening_;
    response.z_b = from_lift(z_b_lift, p.m, p);
    response.z_c = from_lift(z_c_lift, p.m, p);
    return response;
}

arithmetic::Polynomial BinaryChallengeFromExponent(
    const commitment::Parameters& parameters, std::size_t exponent) {
    parameters.validate();
    if (exponent >= checked_product(2, parameters.degree)) {
        throw std::out_of_range("binary-proof challenge exponent must be in [0,2d)");
    }
    std::vector<NTL::ZZ> coefficients(parameters.degree, NTL::ZZ(0));
    const std::size_t index = exponent % parameters.degree;
    coefficients[index] = exponent < parameters.degree ? NTL::ZZ(1) : NTL::ZZ(-1);
    return arithmetic::Polynomial(parameters.degree, parameters.q, coefficients);
}

arithmetic::Polynomial SampleBinaryChallenge(
    const commitment::Parameters& parameters, sampling::RandomSource& random) {
    parameters.validate();
    const std::size_t challenge_count = checked_product(2, parameters.degree);
    const NTL::ZZ exponent = sampling::sample_uniform_coefficient(zz(challenge_count), random);
    return BinaryChallengeFromExponent(parameters,
        static_cast<std::size_t>(NTL::conv<long>(exponent)));
}

bool VerifyBinaryProof(const commitment::CommitmentKey& key,
                       const BinaryProofParameters& parameters,
                       const PolynomialVector& public_commitment,
                       const BinaryProofFirstMessage& first_message,
                       const arithmetic::Polynomial& challenge,
                       const BinaryProofResponse& response,
                       const AuxiliaryCommitmentProvider& auxiliary_commitment) {
    try {
        validate_proof_input(key, parameters, public_commitment, first_message,
                             challenge, response);
        const auto& p = key.parameters();
        if (!auxiliary_commitment.verify(first_message.A, first_message.C,
                                         first_message.D,
                                         first_message.auxiliary_commitment,
                                         response.auxiliary_opening)) {
            return false;
        }
        const auto f = reconstruct_f(parameters, challenge, response.f_nonzero);
        if (!verify_norms(p, parameters, f, response)) return false;

        PolynomialVector f_message;
        PolynomialVector g_message;
        f_message.reserve(f.size());
        g_message.reserve(f.size());
        for (const auto& value : f) {
            f_message.push_back(value);
            g_message.push_back(value * (challenge - value));
        }

        const PolynomialVector left_b = [&] {
            PolynomialVector result;
            result.reserve(p.n);
            for (std::size_t i = 0; i < p.n; ++i) {
                result.push_back(challenge * public_commitment[i] + first_message.A[i]);
            }
            return result;
        }();
        const PolynomialVector left_c = [&] {
            PolynomialVector result;
            result.reserve(p.n);
            for (std::size_t i = 0; i < p.n; ++i) {
                result.push_back(challenge * first_message.C[i] + first_message.D[i]);
            }
            return result;
        }();
        return left_b == commitment::Com(key, f_message, response.z_b) &&
               left_c == commitment::Com(key, g_message, response.z_c);
    } catch (...) {
        return false;
    }
}

}  // namespace lattice_lrs::proofs
