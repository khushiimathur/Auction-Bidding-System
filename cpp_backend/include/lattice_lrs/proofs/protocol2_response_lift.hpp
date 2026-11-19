#pragma once

#include "lattice_lrs/arithmetic/polynomial.hpp"

#include <NTL/ZZ.h>

#include <cstddef>
#include <vector>

namespace lattice_lrs::proofs {

struct Protocol2IntegerLiftResponses {
    std::vector<NTL::ZZ> z_lift;
    std::vector<NTL::ZZ> z_b_lift;
    std::vector<NTL::ZZ> z_c_lift;
};

// Computes the Protocol 2 response blocks over integer lifts. Each vector is
// flattened vector-major, coefficient-minor; x must be a signed monomial.
// No coefficient is reduced modulo q.
Protocol2IntegerLiftResponses ComputeProtocol2IntegerLiftResponses(
    const arithmetic::Polynomial& x,
    std::size_t k,
    const std::vector<NTL::ZZ>& r_lift,
    const std::vector<std::vector<NTL::ZZ>>& rho_lifts,
    const std::vector<NTL::ZZ>& r_b_lift,
    const std::vector<NTL::ZZ>& r_a_lift,
    const std::vector<NTL::ZZ>& r_c_lift,
    const std::vector<NTL::ZZ>& r_d_lift);

}  // namespace lattice_lrs::proofs
