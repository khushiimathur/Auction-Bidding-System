#include "lattice_lrs/proofs/protocol2_polynomial.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace lattice_lrs::proofs {

Protocol2PolynomialExpansion ExpandProtocol2Polynomial(
    const sampling::PolynomialVector& a_values,
    std::size_t k,
    std::size_t beta,
    const std::vector<std::size_t>& selected_digits,
    const std::vector<std::size_t>& index_digits) {
    if (k == 0 || beta == 0) {
        throw std::invalid_argument("Protocol 2 expansion dimensions must be positive");
    }

    const std::size_t max_size = std::numeric_limits<std::size_t>::max();
    if (beta > max_size / k || k == max_size) {
        throw std::length_error("Protocol 2 expansion dimensions overflow");
    }
    const std::size_t expected_a_values = k * beta;
    const std::size_t coefficient_count = k + 1;
    if (coefficient_count > std::vector<arithmetic::Polynomial>().max_size()) {
        throw std::length_error("Protocol 2 expansion has too many coefficients");
    }

    if (a_values.size() != expected_a_values ||
        selected_digits.size() != k || index_digits.size() != k) {
        throw std::invalid_argument("Protocol 2 expansion inputs have incompatible dimensions");
    }

    const arithmetic::Polynomial& ring_example = a_values.front();
    for (const arithmetic::Polynomial& value : a_values) {
        if (value.degree() != ring_example.degree() ||
            value.modulus() != ring_example.modulus()) {
            throw std::invalid_argument("Protocol 2 expansion values use different rings");
        }
    }
    for (std::size_t row = 0; row < k; ++row) {
        if (selected_digits[row] >= beta || index_digits[row] >= beta) {
            throw std::invalid_argument("Protocol 2 expansion digit is out of range");
        }
    }

    const arithmetic::Polynomial zero(ring_example.degree(), ring_example.modulus());
    const arithmetic::Polynomial one(ring_example.degree(), ring_example.modulus(),
                                     {NTL::ZZ(1)});
    std::vector<arithmetic::Polynomial> expanded{one};

    for (std::size_t row = 0; row < k; ++row) {
        const arithmetic::Polynomial& constant =
            a_values[row * beta + index_digits[row]];
        const bool has_linear_term = selected_digits[row] == index_digits[row];
        std::vector<arithmetic::Polynomial> next(expanded.size() + 1, zero);

        for (std::size_t degree = 0; degree < expanded.size(); ++degree) {
            next[degree] = next[degree] + expanded[degree] * constant;
            if (has_linear_term) {
                next[degree + 1] = next[degree + 1] + expanded[degree];
            }
        }
        expanded = std::move(next);
    }

    std::vector<arithmetic::Polynomial> coefficients;
    coefficients.reserve(k);
    for (std::size_t degree = 0; degree < k; ++degree) {
        coefficients.push_back(std::move(expanded[degree]));
    }
    return {std::move(coefficients), std::move(expanded[k])};
}

}  // namespace lattice_lrs::proofs
