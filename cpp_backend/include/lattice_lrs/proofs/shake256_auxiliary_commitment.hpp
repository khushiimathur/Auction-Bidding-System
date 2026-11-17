#pragma once

#include "lattice_lrs/proofs/binary_proof.hpp"
#include "lattice_lrs/proofs/protocol2_proof.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lattice_lrs::proofs {

class Shake256AuxiliaryCommitmentProvider final
    : public AuxiliaryCommitmentProvider,
      public Protocol2AuxiliaryCommitmentProvider {
public:
    static constexpr std::size_t kOpeningSize = 32;
    static constexpr std::size_t kDigestSize = 32;

    AuxiliaryCommitmentOpening commit(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        sampling::RandomSource& random) override;

    bool verify(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        const AuxiliaryCommitmentValue& commitment,
        const std::vector<std::uint8_t>& opening) const override;

    AuxiliaryCommitmentOpening commit(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& B,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        const std::vector<sampling::PolynomialVector>& E,
        sampling::RandomSource& random) override;

    bool verify(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& B,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        const std::vector<sampling::PolynomialVector>& E,
        const AuxiliaryCommitmentValue& commitment,
        const std::vector<std::uint8_t>& opening) const override;
};

}  // namespace lattice_lrs::proofs
