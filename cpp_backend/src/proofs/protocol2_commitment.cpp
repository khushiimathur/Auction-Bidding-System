#include "lattice_lrs/proofs/protocol2_commitment.hpp"

#include <limits>
#include <stdexcept>

namespace lattice_lrs::proofs {
namespace {

std::size_t protocol2_list_size(std::size_t k, std::size_t beta) {
    if (k == 0 || beta == 0) {
        throw std::invalid_argument("Protocol 2 dimensions must be positive");
    }

    if (beta == 1) {
        return 1;
    }

    const std::size_t max_size = std::numeric_limits<std::size_t>::max();
    std::size_t list_size = 1;
    for (std::size_t digit = 0; digit < k; ++digit) {
        if (list_size > max_size / beta) {
            throw std::length_error("Protocol 2 list size beta^k overflows");
        }
        list_size *= beta;
    }
    return list_size;
}

bool matches_ring(const arithmetic::Polynomial& polynomial,
                  const commitment::Parameters& parameters) {
    return polynomial.degree() == parameters.degree &&
           polynomial.modulus() == parameters.q;
}

bool matches_vector(const sampling::PolynomialVector& vector,
                    std::size_t length,
                    const commitment::Parameters& parameters) {
    if (vector.size() != length) {
        return false;
    }
    for (const arithmetic::Polynomial& polynomial : vector) {
        if (!matches_ring(polynomial, parameters)) {
            return false;
        }
    }
    return true;
}

}  // namespace

sampling::PolynomialVector BuildProtocol2E(
    const commitment::CommitmentKey& key,
    const std::vector<sampling::PolynomialVector>& commitments,
    const std::vector<Protocol2PolynomialExpansion>& expansions,
    std::size_t k,
    std::size_t beta,
    std::size_t j,
    const sampling::PolynomialVector& rho_j) {
    const commitment::Parameters& parameters = key.parameters();
    parameters.validate();

    const std::size_t expected_list_size = protocol2_list_size(k, beta);
    if (j >= k) {
        throw std::invalid_argument("Protocol 2 coefficient index j is out of range");
    }
    if (commitments.size() != expected_list_size ||
        expansions.size() != expected_list_size) {
        throw std::invalid_argument("Protocol 2 list and expansion sizes must equal beta^k");
    }
    if (!matches_vector(rho_j, parameters.m, parameters)) {
        throw std::invalid_argument("rho_j has an incompatible length or ring");
    }

    for (std::size_t index = 0; index < expected_list_size; ++index) {
        if (!matches_vector(commitments[index], parameters.n, parameters)) {
            throw std::invalid_argument("list commitment has an incompatible length or ring");
        }
        const Protocol2PolynomialExpansion& expansion = expansions[index];
        if (expansion.coefficients.size() != k ||
            !matches_ring(expansion.leading_coefficient, parameters)) {
            throw std::invalid_argument("polynomial expansion has an incompatible coefficient count or ring");
        }
        for (const arithmetic::Polynomial& coefficient : expansion.coefficients) {
            if (!matches_ring(coefficient, parameters)) {
                throw std::invalid_argument("polynomial expansion coefficient uses an incompatible ring");
            }
        }
    }

    sampling::PolynomialVector zero_message(
        parameters.v, arithmetic::Polynomial(parameters.degree, parameters.q));
    sampling::PolynomialVector result = commitment::Com(key, zero_message, rho_j);

    for (std::size_t index = 0; index < expected_list_size; ++index) {
        const arithmetic::Polynomial& coefficient =
            expansions[index].coefficients[j];
        for (std::size_t row = 0; row < parameters.n; ++row) {
            result[row] = result[row] + coefficient * commitments[index][row];
        }
    }
    return result;
}

}  // namespace lattice_lrs::proofs
