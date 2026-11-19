#pragma once

#include "lattice_lrs/commitment/commitment.hpp"
#include "lattice_lrs/proofs/protocol2_polynomial.hpp"

#include <cstddef>
#include <vector>

namespace lattice_lrs::proofs {

// Computes E_j for list entries and expansions supplied in matching,
// increasing list-index order. rho_j is caller-provided.
sampling::PolynomialVector BuildProtocol2E(
    const commitment::CommitmentKey& key,
    const std::vector<sampling::PolynomialVector>& commitments,
    const std::vector<Protocol2PolynomialExpansion>& expansions,
    std::size_t k,
    std::size_t beta,
    std::size_t j,
    const sampling::PolynomialVector& rho_j);

}  // namespace lattice_lrs::proofs
