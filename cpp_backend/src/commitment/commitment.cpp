#include "lattice_lrs/commitment/commitment.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace lattice_lrs::commitment {
namespace {

arithmetic::Matrix as_column(const sampling::PolynomialVector& vector,
                             const Parameters& parameters) {
    arithmetic::Matrix column(vector.size(), 1, parameters.degree, parameters.q);
    for (std::size_t i = 0; i < vector.size(); ++i) {
        column.at(i, 0) = vector[i];
    }
    return column;
}

sampling::PolynomialVector from_column(const arithmetic::Matrix& column) {
    sampling::PolynomialVector vector;
    vector.reserve(column.rows());
    for (std::size_t row = 0; row < column.rows(); ++row) {
        vector.push_back(column.at(row, 0));
    }
    return vector;
}

bool vector_matches(const sampling::PolynomialVector& vector, std::size_t expected_length,
                    const Parameters& parameters) {
    if (vector.size() != expected_length) {
        return false;
    }
    for (const arithmetic::Polynomial& polynomial : vector) {
        if (polynomial.degree() != parameters.degree || polynomial.modulus() != parameters.q) {
            return false;
        }
    }
    return true;
}

void require_vector(const sampling::PolynomialVector& vector, std::size_t expected_length,
                    const Parameters& parameters, const char* name) {
    if (!vector_matches(vector, expected_length, parameters)) {
        throw std::invalid_argument(std::string(name) + " has an incompatible length or ring");
    }
}

NTL::ZZ squared_norm(const sampling::PolynomialVector& randomness,
                     const sampling::PolynomialVector& message) {
    NTL::ZZ result(0);
    const auto add_vector_norm = [&result](const sampling::PolynomialVector& vector) {
        for (const arithmetic::Polynomial& polynomial : vector) {
            for (std::size_t i = 0; i < polynomial.degree(); ++i) {
                const NTL::ZZ coefficient = polynomial.centered_coefficient(i);
                result += coefficient * coefficient;
            }
        }
    };
    add_vector_norm(randomness);
    add_vector_norm(message);
    return result;
}

}  // namespace

SquaredNormBound::SquaredNormBound(const NTL::ZZ& numerator_value,
                                   const NTL::ZZ& denominator_value)
    : numerator(numerator_value), denominator(denominator_value) {
    if (numerator <= 0 || denominator <= 0) {
        throw std::invalid_argument("T_com squared bound must be a positive rational");
    }
}

void Parameters::validate() const {
    if (n == 0 || m < n || v == 0 || degree == 0) {
        throw std::invalid_argument("commitment dimensions must satisfy n>0, m>=n, v>0, d>0");
    }
    if (q <= 1 || !NTL::IsOdd(q)) {
        throw std::invalid_argument("Esgin commitment modulus q must be an odd integer greater than 1");
    }
    if (B < 0) {
        throw std::invalid_argument("commitment coefficient bound B must be nonnegative");
    }
    if (T_com_squared.numerator <= 0 || T_com_squared.denominator <= 0) {
        throw std::invalid_argument("T_com squared bound must be positive");
    }
}

CommitmentKey::CommitmentKey(const Parameters& parameters, arithmetic::Matrix G_r,
                             arithmetic::Matrix G_m)
    : parameters_(parameters), G_r_(std::move(G_r)), G_m_(std::move(G_m)),
      G_(parameters.n, parameters.m + parameters.v, parameters.degree, parameters.q) {
    parameters_.validate();
    if (G_r_.rows() != parameters_.n || G_r_.columns() != parameters_.m ||
        G_r_.degree() != parameters_.degree || G_r_.modulus() != parameters_.q ||
        G_m_.rows() != parameters_.n || G_m_.columns() != parameters_.v ||
        G_m_.degree() != parameters_.degree || G_m_.modulus() != parameters_.q) {
        throw std::invalid_argument("commitment-key matrices do not match parameter dimensions");
    }
    for (std::size_t row = 0; row < parameters_.n; ++row) {
        for (std::size_t column = 0; column < parameters_.m; ++column) {
            G_.at(row, column) = G_r_.at(row, column);
        }
        for (std::size_t column = 0; column < parameters_.v; ++column) {
            G_.at(row, parameters_.m + column) = G_m_.at(row, column);
        }
    }
}

CommitmentKey CKeygen(const Parameters& parameters, sampling::RandomSource& random) {
    parameters.validate();

    const arithmetic::Matrix G_r_prime = sampling::sample_uniform_matrix(
        parameters.n, parameters.m - parameters.n, parameters.degree, parameters.q, random);
    const arithmetic::Matrix G_m = sampling::sample_uniform_matrix(
        parameters.n, parameters.v, parameters.degree, parameters.q, random);

    arithmetic::Matrix G_r(parameters.n, parameters.m, parameters.degree, parameters.q);
    for (std::size_t row = 0; row < parameters.n; ++row) {
        G_r.at(row, row) = arithmetic::Polynomial(
            parameters.degree, parameters.q, {NTL::ZZ(1)});
        for (std::size_t column = 0; column < parameters.m - parameters.n; ++column) {
            G_r.at(row, parameters.n + column) = G_r_prime.at(row, column);
        }
    }
    return CommitmentKey(parameters, std::move(G_r), G_m);
}

CommitmentKey CKeygen(const Parameters& parameters) {
    sampling::SystemRandomSource random;
    return CKeygen(parameters, random);
}

sampling::PolynomialVector Com(const CommitmentKey& key,
                               const sampling::PolynomialVector& message,
                               const sampling::PolynomialVector& randomness) {
    const Parameters& parameters = key.parameters();
    require_vector(message, parameters.v, parameters, "message");
    require_vector(randomness, parameters.m, parameters, "randomness");
    const arithmetic::Matrix randomness_column = as_column(randomness, parameters);
    const arithmetic::Matrix message_column = as_column(message, parameters);
    return from_column(key.G_r() * randomness_column + key.G_m() * message_column);
}

CommitmentOpening Commit(const CommitmentKey& key,
                         const sampling::PolynomialVector& message,
                         sampling::RandomSource& random) {
    const Parameters& parameters = key.parameters();
    require_vector(message, parameters.v, parameters, "message");
    sampling::PolynomialVector randomness = sampling::sample_bounded_vector(
        parameters.m, parameters.degree, parameters.q, parameters.B, random);
    sampling::PolynomialVector commitment = Com(key, message, randomness);
    return CommitmentOpening{std::move(commitment), std::move(randomness)};
}

CommitmentOpening Commit(const CommitmentKey& key,
                         const sampling::PolynomialVector& message) {
    sampling::SystemRandomSource random;
    return Commit(key, message, random);
}

bool Open(const CommitmentKey& key,
          const sampling::PolynomialVector& commitment,
          const arithmetic::Polynomial& relaxation_factor,
          const sampling::PolynomialVector& message,
          const sampling::PolynomialVector& randomness) {
    const Parameters& parameters = key.parameters();
    if (!vector_matches(commitment, parameters.n, parameters) ||
        !vector_matches(message, parameters.v, parameters) ||
        !vector_matches(randomness, parameters.m, parameters) ||
        relaxation_factor.degree() != parameters.degree ||
        relaxation_factor.modulus() != parameters.q) {
        return false;
    }

    const NTL::ZZ norm_squared = squared_norm(randomness, message);
    if (norm_squared * parameters.T_com_squared.denominator >
        parameters.T_com_squared.numerator) {
        return false;
    }

    const sampling::PolynomialVector opened = Com(key, message, randomness);
    for (std::size_t i = 0; i < parameters.n; ++i) {
        if (opened[i] != relaxation_factor * commitment[i]) {
            return false;
        }
    }
    return true;
}

}  // namespace lattice_lrs::commitment
