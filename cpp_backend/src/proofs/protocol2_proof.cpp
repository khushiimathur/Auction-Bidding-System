#include "lattice_lrs/proofs/protocol2_proof.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace lattice_lrs::proofs {
namespace {

using sampling::PolynomialVector;

struct SignedMonomial {
    std::size_t degree;
    bool negative;
};

NTL::ZZ zz(std::size_t value) {
    if (value > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        throw std::length_error("Protocol 2 dimensions exceed NTL's index range");
    }
    return NTL::to_ZZ(static_cast<long>(value));
}

std::size_t checked_product(std::size_t left, std::size_t right) {
    if (right != 0 && left > std::numeric_limits<std::size_t>::max() / right) {
        throw std::length_error("Protocol 2 dimensions overflow");
    }
    return left * right;
}

std::size_t list_size(std::size_t k, std::size_t beta) {
    std::size_t result = 1;
    for (std::size_t row = 0; row < k; ++row) {
        if (result > std::numeric_limits<std::size_t>::max() / beta) {
            throw std::length_error("Protocol 2 list size beta^k overflows");
        }
        result *= beta;
    }
    return result;
}

bool matches_ring(const arithmetic::Polynomial& polynomial,
                  const commitment::Parameters& parameters) {
    return polynomial.degree() == parameters.degree &&
           polynomial.modulus() == parameters.q;
}

bool matches_vector(const PolynomialVector& vector, std::size_t length,
                    const commitment::Parameters& parameters) {
    return vector.size() == length &&
           std::all_of(vector.begin(), vector.end(), [&](const auto& value) {
               return matches_ring(value, parameters);
           });
}

std::vector<NTL::ZZ> centered_lift(const PolynomialVector& values) {
    const std::size_t degree = values.empty() ? 0 : values.front().degree();
    const std::size_t count = checked_product(values.size(), degree);
    std::vector<NTL::ZZ> result;
    result.reserve(count);
    for (const auto& value : values) {
        for (std::size_t i = 0; i < degree; ++i) {
            result.push_back(value.centered_coefficient(i));
        }
    }
    return result;
}

PolynomialVector from_lift(const std::vector<NTL::ZZ>& lift,
                            std::size_t polynomial_count,
                            const commitment::Parameters& parameters) {
    const std::size_t expected =
        checked_product(polynomial_count, parameters.degree);
    if (lift.size() != expected) {
        throw std::invalid_argument("Protocol 2 integer lift has an incompatible dimension");
    }
    PolynomialVector result;
    result.reserve(polynomial_count);
    for (std::size_t i = 0; i < polynomial_count; ++i) {
        const std::size_t base = i * parameters.degree;
        std::vector<NTL::ZZ> coefficients(
            lift.begin() + static_cast<std::ptrdiff_t>(base),
            lift.begin() + static_cast<std::ptrdiff_t>(base + parameters.degree));
        result.emplace_back(parameters.degree, parameters.q, coefficients);
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

NTL::ZZ norm_squared(const PolynomialVector& values) {
    NTL::ZZ result(0);
    for (const auto& value : values) result += norm_squared(value);
    return result;
}

SignedMonomial require_monomial(const arithmetic::Polynomial& challenge) {
    if (challenge.modulus() <= 2 || !NTL::IsOdd(challenge.modulus())) {
        throw std::invalid_argument("Protocol 2 challenge ring modulus must be odd");
    }
    std::size_t nonzero_count = 0;
    SignedMonomial result{0, false};
    for (std::size_t i = 0; i < challenge.degree(); ++i) {
        const NTL::ZZ& coefficient = challenge.coefficient(i);
        if (coefficient == 0) continue;
        ++nonzero_count;
        if (coefficient == 1) {
            result = {i, false};
        } else if (coefficient == challenge.modulus() - 1) {
            result = {i, true};
        } else {
            throw std::invalid_argument("Protocol 2 challenge must be a signed monomial");
        }
    }
    if (nonzero_count != 1) {
        throw std::invalid_argument("Protocol 2 challenge must be a signed monomial");
    }
    return result;
}

SignedMonomial multiply_monomials(const SignedMonomial& left,
                                  const SignedMonomial& right,
                                  std::size_t degree) {
    const bool wraps = right.degree >= degree - left.degree;
    const std::size_t result_degree =
        wraps ? right.degree - (degree - left.degree)
              : left.degree + right.degree;
    return {result_degree, (left.negative != right.negative) != wraps};
}

std::vector<NTL::ZZ> multiply_by_monomial(
    const std::vector<NTL::ZZ>& input,
    const SignedMonomial& monomial,
    std::size_t polynomial_count,
    std::size_t degree) {
    if (input.size() != checked_product(polynomial_count, degree)) {
        throw std::invalid_argument("Protocol 2 monomial input has an incompatible dimension");
    }
    std::vector<NTL::ZZ> result(input.size(), NTL::ZZ(0));
    for (std::size_t polynomial = 0; polynomial < polynomial_count; ++polynomial) {
        const std::size_t base = polynomial * degree;
        for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
            const bool wraps = coefficient >= degree - monomial.degree;
            const std::size_t target =
                wraps ? coefficient - (degree - monomial.degree)
                      : coefficient + monomial.degree;
            result[base + target] =
                monomial.negative != wraps ? -input[base + coefficient]
                                           : input[base + coefficient];
        }
    }
    return result;
}

std::vector<NTL::ZZ> add_lifts(const std::vector<NTL::ZZ>& left,
                               const std::vector<NTL::ZZ>& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("Protocol 2 integer vectors have different dimensions");
    }
    std::vector<NTL::ZZ> result(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) result[i] = left[i] + right[i];
    return result;
}

std::vector<NTL::ZZ> concatenate(const std::vector<NTL::ZZ>& first,
                                 const std::vector<NTL::ZZ>& second) {
    if (first.size() > std::numeric_limits<std::size_t>::max() - second.size()) {
        throw std::length_error("Protocol 2 rejection vector size overflows");
    }
    std::vector<NTL::ZZ> result;
    result.reserve(first.size() + second.size());
    result.insert(result.end(), first.begin(), first.end());
    result.insert(result.end(), second.begin(), second.end());
    return result;
}

bool rejection_accepts(const std::vector<NTL::ZZ>& z_values,
                       const std::vector<NTL::ZZ>& center,
                       const PositiveRational& phi,
                       const NTL::ZZ& K_squared,
                       sampling::RandomSource& random,
                       BernoulliExponentialProvider& exponential) {
    if (z_values.size() != center.size() || K_squared <= 0 ||
        phi.numerator <= 0 || phi.denominator <= 0) {
        throw std::invalid_argument("Protocol 2 rejection inputs are invalid");
    }
    NTL::ZZ inner_product(0);
    NTL::ZZ center_norm_squared(0);
    for (std::size_t i = 0; i < z_values.size(); ++i) {
        inner_product += z_values[i] * center[i];
        center_norm_squared += center[i] * center[i];
    }
    const NTL::ZZ p = phi.numerator;
    const NTL::ZZ t = phi.denominator;
    const NTL::ZZ exponent_denominator = 2 * p * p * K_squared;
    const NTL::ZZ exponent_numerator =
        -(24 * p * t + t * t) * K_squared +
        t * t * (-2 * inner_product + center_norm_squared);
    if (exponent_numerator >= 0) return true;
    return exponential.sample_exp(exponent_numerator, exponent_denominator, random);
}

std::vector<std::size_t> index_digits(std::size_t index,
                                      std::size_t k,
                                      std::size_t beta) {
    std::vector<std::size_t> digits(k);
    for (std::size_t row = 0; row < k; ++row) {
        digits[row] = index % beta;
        index /= beta;
    }
    return digits;
}

std::vector<arithmetic::Polynomial> reconstruct_f(
    const Protocol2Parameters& parameters,
    const arithmetic::Polynomial& challenge,
    const PolynomialVector& f_nonzero) {
    std::vector<arithmetic::Polynomial> f;
    f.reserve(checked_product(parameters.k, parameters.beta));
    std::size_t nonzero_offset = 0;
    for (std::size_t row = 0; row < parameters.k; ++row) {
        arithmetic::Polynomial f_zero = challenge;
        std::vector<arithmetic::Polynomial> row_nonzero;
        row_nonzero.reserve(parameters.beta - 1);
        for (std::size_t digit = 1; digit < parameters.beta; ++digit) {
            row_nonzero.push_back(f_nonzero[nonzero_offset++]);
            f_zero = f_zero - row_nonzero.back();
        }
        f.push_back(std::move(f_zero));
        f.insert(f.end(), row_nonzero.begin(), row_nonzero.end());
    }
    return f;
}

bool verify_norms(const commitment::Parameters& p,
                  const Protocol2Parameters& proof,
                  const std::vector<arithmetic::Polynomial>& f,
                  const Protocol2Response& response) {
    const NTL::ZZ phi1_bound_numerator =
        25 * proof.phi1.numerator * proof.phi1.numerator *
        zz(p.degree) * zz(proof.k);
    const NTL::ZZ phi1_bound_denominator =
        proof.phi1.denominator * proof.phi1.denominator;
    const NTL::ZZ beta_minus_one = zz(proof.beta - 1);
    const NTL::ZZ f_zero_bound =
        phi1_bound_numerator * beta_minus_one * beta_minus_one;
    for (std::size_t row = 0; row < proof.k; ++row) {
        if (!within_squared_bound(norm_squared(f[row * proof.beta]),
                                  f_zero_bound, phi1_bound_denominator)) {
            return false;
        }
        for (std::size_t digit = 1; digit < proof.beta; ++digit) {
            if (!within_squared_bound(
                    norm_squared(f[row * proof.beta + digit]),
                    phi1_bound_numerator, phi1_bound_denominator)) {
                return false;
            }
        }
    }

    const NTL::ZZ p2_bound_numerator =
        12 * proof.phi2.numerator * proof.phi2.numerator *
        p.B * p.B * zz(p.m) * zz(p.m) * zz(p.degree) * zz(p.degree);
    const NTL::ZZ p2_bound_denominator =
        proof.phi2.denominator * proof.phi2.denominator;
    return within_squared_bound(norm_squared(response.z), p2_bound_numerator,
                                p2_bound_denominator) &&
           within_squared_bound(norm_squared(response.z_b), p2_bound_numerator,
                                p2_bound_denominator) &&
           within_squared_bound(norm_squared(response.z_c), p2_bound_numerator,
                                p2_bound_denominator);
}

}  // namespace

class Protocol2ProofBuilder {
public:
    template <typename SampleGaussian>
    static Protocol2ProofBeginResult begin(
        const commitment::CommitmentKey& key,
        const Protocol2Parameters& proof,
        const Protocol2PublicList& public_list,
        const Protocol2Witness& witness,
        sampling::RandomSource& random,
        SampleGaussian&& sample_gaussian,
        Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    proof.validate(key);
    const commitment::Parameters& p = key.parameters();
    const std::size_t expected_list_size = list_size(proof.k, proof.beta);
    if (public_list.size() != expected_list_size ||
        witness.index >= expected_list_size) {
        throw std::invalid_argument("Protocol 2 list size or witness index is invalid");
    }
    for (const PolynomialVector& entry : public_list) {
        if (!matches_vector(entry, p.n, p)) {
            throw std::invalid_argument("Protocol 2 list entry has an incompatible ring or length");
        }
    }
    if (!matches_vector(witness.opening_randomness, p.m, p)) {
        throw std::invalid_argument("Protocol 2 witness opening has an incompatible ring or length");
    }

    const std::size_t md = checked_product(p.m, p.degree);
    std::vector<NTL::ZZ> witness_randomness_lift =
        centered_lift(witness.opening_randomness);
    for (const NTL::ZZ& value : witness_randomness_lift) {
        if (value < -p.B || value > p.B) {
            throw std::invalid_argument("Protocol 2 witness opening is outside S_B");
        }
    }
    if (norm_squared(witness_randomness_lift) > p.B * p.B * zz(p.m) * zz(p.degree)) {
        throw std::invalid_argument("Protocol 2 witness opening exceeds its norm bound");
    }
    const PolynomialVector zero_message(
        p.v, arithmetic::Polynomial(p.degree, p.q));
    if (commitment::Com(key, zero_message, witness.opening_randomness) !=
        public_list[witness.index]) {
        throw std::invalid_argument("Selected Protocol 2 list entry is not opened by the witness");
    }

    const std::vector<std::size_t> selected_digits =
        index_digits(witness.index, proof.k, proof.beta);
    std::vector<NTL::ZZ> bits_lift(checked_product(p.v, p.degree), NTL::ZZ(0));
    for (std::size_t row = 0; row < proof.k; ++row) {
        bits_lift[(row * proof.beta + selected_digits[row]) * p.degree] = 1;
    }
    const PolynomialVector bits = from_lift(bits_lift, p.v, p);

    std::vector<NTL::ZZ> a_lift(checked_product(p.v, p.degree), NTL::ZZ(0));
    for (std::size_t row = 0; row < proof.k; ++row) {
        for (std::size_t digit = 1; digit < proof.beta; ++digit) {
            const std::size_t offset =
                (row * proof.beta + digit) * p.degree;
            for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
                a_lift[offset + coefficient] =
                    sample_gaussian(Protocol2GaussianSampleKind::binary_mask);
            }
        }
        for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
            NTL::ZZ sum(0);
            for (std::size_t digit = 1; digit < proof.beta; ++digit) {
                sum += a_lift[(row * proof.beta + digit) * p.degree + coefficient];
            }
            a_lift[(row * proof.beta) * p.degree + coefficient] = -sum;
        }
    }

    std::vector<NTL::ZZ> r_b_lift(md);
    std::vector<NTL::ZZ> r_c_lift(md);
    for (std::size_t i = 0; i < md; ++i) {
        r_b_lift[i] = sampling::sample_bounded_coefficient(p.B, random);
        r_c_lift[i] = sampling::sample_bounded_coefficient(p.B, random);
    }

    std::vector<NTL::ZZ> r_a_lift(md);
    std::vector<NTL::ZZ> r_d_lift(md);
    for (std::size_t i = 0; i < md; ++i) {
        r_a_lift[i] =
            sample_gaussian(Protocol2GaussianSampleKind::response_mask);
    }
    for (std::size_t i = 0; i < md; ++i) {
        r_d_lift[i] =
            sample_gaussian(Protocol2GaussianSampleKind::response_mask);
    }

    const PolynomialVector a = from_lift(a_lift, p.v, p);
    const PolynomialVector r_b = from_lift(r_b_lift, p.m, p);
    const PolynomialVector r_c = from_lift(r_c_lift, p.m, p);
    const PolynomialVector r_a = from_lift(r_a_lift, p.m, p);
    const PolynomialVector r_d = from_lift(r_d_lift, p.m, p);
    PolynomialVector c_message;
    PolynomialVector d_message;
    c_message.reserve(p.v);
    d_message.reserve(p.v);
    for (std::size_t i = 0; i < p.v; ++i) {
        const bool bit = bits_lift[i * p.degree] == 1;
        std::vector<NTL::ZZ> signed_a(p.degree);
        for (std::size_t coefficient = 0; coefficient < p.degree; ++coefficient) {
            const NTL::ZZ& value = a_lift[i * p.degree + coefficient];
            signed_a[coefficient] = bit ? -value : value;
        }
        c_message.emplace_back(p.degree, p.q, signed_a);
        d_message.push_back(
            arithmetic::Polynomial(p.degree, p.q) - a[i] * a[i]);
    }

    Protocol2FirstMessage first;
    first.A = commitment::Com(key, a, r_a);
    first.B = commitment::Com(key, bits, r_b);
    first.C = commitment::Com(key, c_message, r_c);
    first.D = commitment::Com(key, d_message, r_d);

    std::vector<std::vector<NTL::ZZ>> rho_lifts(
        proof.k, std::vector<NTL::ZZ>(md));
    std::vector<PolynomialVector> rho_vectors;
    rho_vectors.reserve(proof.k);
    for (std::size_t j = 0; j < proof.k; ++j) {
        for (NTL::ZZ& coefficient : rho_lifts[j]) {
            coefficient = sample_gaussian(Protocol2GaussianSampleKind::rho);
        }
        rho_vectors.push_back(from_lift(rho_lifts[j], p.m, p));
    }

    std::vector<Protocol2PolynomialExpansion> expansions;
    expansions.reserve(expected_list_size);
    for (std::size_t index = 0; index < expected_list_size; ++index) {
        expansions.push_back(ExpandProtocol2Polynomial(
            a, proof.k, proof.beta, selected_digits,
            index_digits(index, proof.k, proof.beta)));
    }
    first.E.reserve(proof.k);
    for (std::size_t j = 0; j < proof.k; ++j) {
        first.E.push_back(BuildProtocol2E(
            key, public_list, expansions, proof.k, proof.beta, j, rho_vectors[j]));
    }

    AuxiliaryCommitmentOpening auxiliary = auxiliary_commitment.commit(
        first.A, first.B, first.C, first.D, first.E, random);
    first.auxiliary_commitment = std::move(auxiliary.commitment);

    Protocol2ProverState state;
    state.bits_lift_ = bits_lift;
    state.witness_randomness_lift_ = std::move(witness_randomness_lift);
    state.a_lift_ = std::move(a_lift);
    state.r_b_lift_ = std::move(r_b_lift);
    state.r_c_lift_ = std::move(r_c_lift);
    state.r_a_lift_ = std::move(r_a_lift);
    state.r_d_lift_ = std::move(r_d_lift);
    state.rho_lifts_ = std::move(rho_lifts);
    state.auxiliary_opening_ = std::move(auxiliary.opening);
    return {std::move(first), std::move(state)};
    }

    static Protocol2FirstStageLiftResponse first_stage(
        const Protocol2ProverState& state,
        const commitment::CommitmentKey& key,
        const Protocol2Parameters& proof,
        const arithmetic::Polynomial& challenge) {
        proof.validate(key);
        const commitment::Parameters& p = key.parameters();
        if (challenge.degree() != p.degree || challenge.modulus() != p.q) {
            throw std::invalid_argument("Protocol 2 challenge uses the wrong ring");
        }
        const SignedMonomial monomial = require_monomial(challenge);
        const std::vector<NTL::ZZ> x_bits = multiply_by_monomial(
            state.bits_lift_, monomial, p.v, p.degree);
        const std::vector<NTL::ZZ> f_lift = add_lifts(state.a_lift_, x_bits);

        Protocol2FirstStageLiftResponse result;
        const std::size_t count =
            checked_product(checked_product(proof.k, proof.beta - 1), p.degree);
        result.f_nonzero_lift.reserve(count);
        result.center_f_lift.reserve(count);
        for (std::size_t row = 0; row < proof.k; ++row) {
            for (std::size_t digit = 1; digit < proof.beta; ++digit) {
                const std::size_t offset =
                    (row * proof.beta + digit) * p.degree;
                for (std::size_t coefficient = 0; coefficient < p.degree;
                     ++coefficient) {
                    result.f_nonzero_lift.push_back(
                        f_lift[offset + coefficient]);
                    result.center_f_lift.push_back(
                        x_bits[offset + coefficient]);
                }
            }
        }
        return result;
    }

    static Protocol2ResponseLiftData response_lifts(
        const Protocol2ProverState& state,
        const commitment::CommitmentKey& key,
        const Protocol2Parameters& proof,
        const arithmetic::Polynomial& challenge) {
        proof.validate(key);
        const commitment::Parameters& p = key.parameters();
        if (challenge.degree() != p.degree || challenge.modulus() != p.q) {
            throw std::invalid_argument("Protocol 2 challenge uses the wrong ring");
        }
        const SignedMonomial monomial = require_monomial(challenge);
        Protocol2ResponseLiftData result;
        result.responses = ComputeProtocol2IntegerLiftResponses(
            challenge, proof.k, state.witness_randomness_lift_,
            state.rho_lifts_, state.r_b_lift_, state.r_a_lift_,
            state.r_c_lift_, state.r_d_lift_);

        SignedMonomial challenge_power{0, false};
        for (std::size_t i = 0; i < proof.k; ++i) {
            challenge_power =
                multiply_monomials(challenge_power, monomial, p.degree);
        }
        result.center_z_lift = multiply_by_monomial(
            state.witness_randomness_lift_, challenge_power, p.m, p.degree);
        result.center_z_b_lift = multiply_by_monomial(
            state.r_b_lift_, monomial, p.m, p.degree);
        result.center_z_c_lift = multiply_by_monomial(
            state.r_c_lift_, monomial, p.m, p.degree);
        result.auxiliary_opening = state.auxiliary_opening_;
        return result;
    }
};

void Protocol2Parameters::validate(const commitment::CommitmentKey& key) const {
    const commitment::Parameters& p = key.parameters();
    p.validate();
    if (p.B <= 0) {
        throw std::invalid_argument("Protocol 2 requires positive B");
    }
    BinaryProofParameters{k, beta, phi1, phi2}.validate(key);
    (void)list_size(k, beta);
}

DsProtocol2RSignGaussianProvider::DsProtocol2RSignGaussianProvider(
    DiscreteGaussianSProvider& sampler,
    const Protocol2RSignGaussianScaleProfile& scale_profile)
    : sampler_(sampler), scale_profile_(scale_profile) {}

bool DsProtocol2RSignGaussianProvider::supports_section6_distributions()
    const noexcept {
    return scale_profile_.supports_section6_distributions();
}

NTL::ZZ DsProtocol2RSignGaussianProvider::sample_coefficient(
    Protocol2GaussianSampleKind kind,
    std::size_t run_index,
    std::size_t repetitions,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    sampling::RandomSource& random) {
    if (repetitions == 0 || run_index >= repetitions) {
        throw std::invalid_argument("RSign Gaussian run index is invalid");
    }
    if (!supports_section6_distributions()) {
        throw std::runtime_error(
            "RSign Gaussian scale profile does not support Section 6");
    }
    const Protocol2GaussianScaleSquared scale =
        scale_profile_.scale_squared(
            kind, run_index, repetitions, key, parameters);
    if (scale.numerator <= 0 || scale.denominator <= 0) {
        throw std::invalid_argument(
            "RSign Gaussian scale profile returned a non-positive rational");
    }
    return sampler_.sample_coefficient_from_scale_squared(
        scale.numerator, scale.denominator, random);
}

Protocol2ProofBeginResult BeginProtocol2Proof(
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof,
    const Protocol2PublicList& public_list,
    const Protocol2Witness& witness,
    sampling::RandomSource& random,
    DiscreteGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    proof.validate(key);
    const commitment::Parameters& p = key.parameters();
    const NTL::ZZ phi1_num = proof.phi1.numerator * proof.phi1.numerator *
                             zz(proof.k);
    const NTL::ZZ phi1_den =
        proof.phi1.denominator * proof.phi1.denominator;
    const NTL::ZZ phi2_num =
        proof.phi2.numerator * proof.phi2.numerator * p.B * p.B *
        3 * zz(p.m) * zz(p.degree);
    const NTL::ZZ phi2_den =
        proof.phi2.denominator * proof.phi2.denominator;
    return Protocol2ProofBuilder::begin(
        key, proof, public_list, witness, random,
        [&](Protocol2GaussianSampleKind kind) {
            if (kind == Protocol2GaussianSampleKind::binary_mask) {
                return gaussian.sample_coefficient(phi1_num, phi1_den, random);
            }
            if (kind == Protocol2GaussianSampleKind::rho) {
                return gaussian.sample_coefficient(
                    phi2_num, phi2_den * zz(proof.k), random);
            }
            return gaussian.sample_coefficient(phi2_num, phi2_den, random);
        },
        auxiliary_commitment);
}

Protocol2ProofBeginResult BeginProtocol2ProofForRSign(
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof,
    const Protocol2PublicList& public_list,
    const Protocol2Witness& witness,
    std::size_t run_index,
    std::size_t repetitions,
    sampling::RandomSource& random,
    Protocol2RSignGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    if (repetitions == 0 || run_index >= repetitions) {
        throw std::invalid_argument("RSign run index or repetition count is invalid");
    }
    if (!gaussian.supports_section6_distributions()) {
        throw std::runtime_error(
            "RSign Gaussian provider does not support the Section 6 distributions");
    }
    return Protocol2ProofBuilder::begin(
        key, proof, public_list, witness, random,
        [&](Protocol2GaussianSampleKind kind) {
            return gaussian.sample_coefficient(
                kind, run_index, repetitions, key, proof, random);
        },
        auxiliary_commitment);
}

Protocol2FirstStageLiftResponse ComputeProtocol2FirstStageLiftResponse(
    const Protocol2ProverState& state,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof,
    const arithmetic::Polynomial& challenge) {
    if (state.consumed_) {
        throw std::logic_error("Protocol 2 prover state has already been consumed");
    }
    return Protocol2ProofBuilder::first_stage(state, key, proof, challenge);
}

Protocol2ResponseLiftData ComputeProtocol2ResponseLiftData(
    Protocol2ProverState& state,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof,
    const arithmetic::Polynomial& challenge) {
    if (state.consumed_) {
        throw std::logic_error("Protocol 2 prover state has already been consumed");
    }
    state.consumed_ = true;
    return Protocol2ProofBuilder::response_lifts(state, key, proof, challenge);
}

Protocol2Response EncodeProtocol2Response(
    const Protocol2FirstStageLiftResponse& first_stage,
    Protocol2ResponseLiftData&& response_lifts,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof) {
    proof.validate(key);
    const commitment::Parameters& p = key.parameters();
    const std::size_t f_count = checked_product(proof.k, proof.beta - 1);
    const std::size_t f_dimension = checked_product(f_count, p.degree);
    const std::size_t response_dimension = checked_product(p.m, p.degree);
    if (first_stage.f_nonzero_lift.size() != f_dimension ||
        response_lifts.responses.z_lift.size() != response_dimension ||
        response_lifts.responses.z_b_lift.size() != response_dimension ||
        response_lifts.responses.z_c_lift.size() != response_dimension) {
        throw std::invalid_argument("Protocol 2 response lifts have incompatible dimensions");
    }

    Protocol2Response response;
    response.f_nonzero = from_lift(first_stage.f_nonzero_lift, f_count, p);
    response.auxiliary_opening = std::move(response_lifts.auxiliary_opening);
    response.z = from_lift(response_lifts.responses.z_lift, p.m, p);
    response.z_b = from_lift(response_lifts.responses.z_b_lift, p.m, p);
    response.z_c = from_lift(response_lifts.responses.z_c_lift, p.m, p);
    return response;
}

std::optional<Protocol2Response> RespondProtocol2Proof(
    Protocol2ProverState& state,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof,
    const arithmetic::Polynomial& challenge,
    sampling::RandomSource& random,
    BernoulliExponentialProvider& exponential) {
    if (state.consumed_) {
        throw std::logic_error("Protocol 2 prover state has already been consumed");
    }
    state.consumed_ = true;
    proof.validate(key);
    const commitment::Parameters& p = key.parameters();
    const Protocol2FirstStageLiftResponse first_stage =
            Protocol2ProofBuilder::first_stage(state, key, proof, challenge);
    if (!rejection_accepts(first_stage.f_nonzero_lift,
                              first_stage.center_f_lift, proof.phi1,
                          zz(proof.k), random, exponential)) {
        return std::nullopt;
    }

    Protocol2ResponseLiftData response_lifts =
            Protocol2ProofBuilder::response_lifts(state, key, proof, challenge);
    const Protocol2JointRejectionInput rejection_input{
            response_lifts.responses.z_lift,
            response_lifts.responses.z_b_lift,
            response_lifts.responses.z_c_lift,
            response_lifts.center_z_lift,
            response_lifts.center_z_b_lift,
            response_lifts.center_z_c_lift};
    if (!AcceptProtocol2JointResponse(
            key, proof.phi2, rejection_input, random, exponential)) {
        return std::nullopt;
    }
    return EncodeProtocol2Response(first_stage, std::move(response_lifts),
                                       key, proof);
}

bool VerifyProtocol2Proof(
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& proof,
    const Protocol2PublicList& public_list,
    const Protocol2FirstMessage& first,
    const arithmetic::Polynomial& challenge,
    const Protocol2Response& response,
    const Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    try {
        proof.validate(key);
    } catch (const std::exception&) {
        return false;
    }
    const commitment::Parameters& p = key.parameters();
    std::size_t expected_list_size = 0;
    try {
        expected_list_size = list_size(proof.k, proof.beta);
    } catch (const std::exception&) {
        return false;
    }
    const std::size_t f_nonzero_count = checked_product(proof.k, proof.beta - 1);
    if (public_list.size() != expected_list_size ||
        !matches_vector(first.A, p.n, p) ||
        !matches_vector(first.B, p.n, p) ||
        !matches_vector(first.C, p.n, p) ||
        !matches_vector(first.D, p.n, p) ||
        first.E.size() != proof.k ||
        !matches_vector(response.f_nonzero, f_nonzero_count, p) ||
        !matches_vector(response.z, p.m, p) ||
        !matches_vector(response.z_b, p.m, p) ||
        !matches_vector(response.z_c, p.m, p) ||
        challenge.degree() != p.degree || challenge.modulus() != p.q) {
        return false;
    }
    for (const PolynomialVector& entry : public_list) {
        if (!matches_vector(entry, p.n, p)) return false;
    }
    for (const PolynomialVector& e : first.E) {
        if (!matches_vector(e, p.n, p)) return false;
    }
    SignedMonomial monomial;
    try {
        monomial = require_monomial(challenge);
    } catch (const std::invalid_argument&) {
        return false;
    }
    (void)monomial;
    if (!auxiliary_commitment.verify(
            first.A, first.B, first.C, first.D, first.E,
            first.auxiliary_commitment, response.auxiliary_opening)) {
        return false;
    }

    const std::vector<arithmetic::Polynomial> f =
        reconstruct_f(proof, challenge, response.f_nonzero);
    if (!verify_norms(p, proof, f, response)) return false;

    PolynomialVector f_message;
    PolynomialVector g_message;
    f_message.reserve(f.size());
    g_message.reserve(f.size());
    for (const arithmetic::Polynomial& value : f) {
        f_message.push_back(value);
        g_message.push_back(value * (challenge - value));
    }
    PolynomialVector left_b;
    PolynomialVector left_c;
    left_b.reserve(p.n);
    left_c.reserve(p.n);
    for (std::size_t i = 0; i < p.n; ++i) {
        left_b.push_back(challenge * first.B[i] + first.A[i]);
        left_c.push_back(challenge * first.C[i] + first.D[i]);
    }
    if (left_b != commitment::Com(key, f_message, response.z_b) ||
        left_c != commitment::Com(key, g_message, response.z_c)) {
        return false;
    }

    PolynomialVector left(
        p.n, arithmetic::Polynomial(p.degree, p.q));
    for (std::size_t index = 0; index < expected_list_size; ++index) {
        const std::vector<std::size_t> digits =
            index_digits(index, proof.k, proof.beta);
        arithmetic::Polynomial product(p.degree, p.q, {NTL::ZZ(1)});
        for (std::size_t row = 0; row < proof.k; ++row) {
            product = product * f[row * proof.beta + digits[row]];
        }
        for (std::size_t row = 0; row < p.n; ++row) {
            left[row] = left[row] + public_list[index][row] * product;
        }
    }
    const arithmetic::Polynomial one(p.degree, p.q, {NTL::ZZ(1)});
    arithmetic::Polynomial power = one;
    for (std::size_t j = 0; j < proof.k; ++j) {
        for (std::size_t row = 0; row < p.n; ++row) {
            left[row] = left[row] - first.E[j][row] * power;
        }
        power = power * challenge;
    }
    const PolynomialVector zero_message(
        p.v, arithmetic::Polynomial(p.degree, p.q));
    return left == commitment::Com(key, zero_message, response.z);
}

}  // namespace lattice_lrs::proofs
