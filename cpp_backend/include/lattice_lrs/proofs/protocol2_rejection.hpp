#pragma once

#include "lattice_lrs/proofs/binary_proof.hpp"

#include <NTL/ZZ.h>

#include <vector>

namespace lattice_lrs::proofs {

struct Protocol2JointRejectionInput {
    // Each block is an integer lift flattened in vector-major, coefficient-
    // minor order. Values must not be reduced modulo q before rejection.
    std::vector<NTL::ZZ> z_lift;
    std::vector<NTL::ZZ> z_b_lift;
    std::vector<NTL::ZZ> z_c_lift;
    std::vector<NTL::ZZ> center_z_lift;
    std::vector<NTL::ZZ> center_z_b_lift;
    std::vector<NTL::ZZ> center_z_c_lift;
};

// Applies Protocol 2's single joint rejection to (z,z_b,z_c), using
// K^2 = 3*B^2*m*d from the commitment parameters. Each input block must have
// exactly m*d integer coefficients. Provider and RandomSource failures
// propagate to the caller.
bool AcceptProtocol2JointResponse(
    const commitment::CommitmentKey& key,
    const PositiveRational& phi2,
    const Protocol2JointRejectionInput& input,
    sampling::RandomSource& random,
    BernoulliExponentialProvider& exponential);

}  // namespace lattice_lrs::proofs
