#pragma once

#include "lattice_lrs/sampling/sampler.hpp"

#include <cstddef>
#include <vector>

namespace lattice_lrs::proofs {

struct Protocol2PolynomialExpansion {
    // Coefficients p_{i,0}, ..., p_{i,k-1}, in ascending order.
    std::vector<arithmetic::Polynomial> coefficients;
    arithmetic::Polynomial leading_coefficient;
};

// Expands product_j (t * [selected_digits[j] == index_digits[j]]
//                      + a_values[j * beta + index_digits[j]])
// as a formal polynomial in t with coefficients in the common ring of a_values.
Protocol2PolynomialExpansion ExpandProtocol2Polynomial(
    const sampling::PolynomialVector& a_values,
    std::size_t k,
    std::size_t beta,
    const std::vector<std::size_t>& selected_digits,
    const std::vector<std::size_t>& index_digits);

}  // namespace lattice_lrs::proofs
