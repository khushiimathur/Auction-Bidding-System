#pragma once

#include "lattice_lrs/sampling/sampler.hpp"

#include <cstddef>
#include <vector>

namespace lattice_lrs::proofs {

// Computes z in R_q^m by modular ring arithmetic. The returned residues do
// not preserve the integer lifts required by Protocol 2 joint rejection.
sampling::PolynomialVector ComputeProtocol2Z(
    const arithmetic::Polynomial& x,
    std::size_t k,
    const sampling::PolynomialVector& r,
    const std::vector<sampling::PolynomialVector>& rho);

}  // namespace lattice_lrs::proofs
