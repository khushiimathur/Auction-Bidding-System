#pragma once

#include "lattice_lrs/proofs/protocol2_commitment.hpp"
#include "lattice_lrs/proofs/protocol2_rejection.hpp"
#include "lattice_lrs/proofs/protocol2_response_lift.hpp"

#include <optional>
#include <vector>

namespace lattice_lrs::proofs {

struct Protocol2Parameters {
    std::size_t k;
    std::size_t beta;
    PositiveRational phi1;
    PositiveRational phi2;

    // Checks the embedded Protocol 1 requirements and Protocol 2 dimensions.
    // This is not a validation of every Theorem 2 security parameter bound.
    void validate(const commitment::CommitmentKey& key) const;
};

struct Protocol2Witness {
    std::size_t index;
    sampling::PolynomialVector opening_randomness;
};

using Protocol2PublicList = std::vector<sampling::PolynomialVector>;

class Protocol2AuxiliaryCommitmentProvider {
public:
    virtual ~Protocol2AuxiliaryCommitmentProvider() = default;
    virtual AuxiliaryCommitmentOpening commit(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& B,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        const std::vector<sampling::PolynomialVector>& E,
        sampling::RandomSource& random) = 0;
    virtual bool verify(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& B,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        const std::vector<sampling::PolynomialVector>& E,
        const AuxiliaryCommitmentValue& auxiliary_commitment,
        const std::vector<std::uint8_t>& opening) const = 0;
};

struct Protocol2FirstMessage {
    sampling::PolynomialVector A;
    sampling::PolynomialVector B;
    sampling::PolynomialVector C;
    sampling::PolynomialVector D;
    std::vector<sampling::PolynomialVector> E;
    AuxiliaryCommitmentValue auxiliary_commitment;
};

struct Protocol2Response {
    // Entries f_{j,i} for i=1,...,beta-1, in row-major order.
    sampling::PolynomialVector f_nonzero;
    std::vector<std::uint8_t> auxiliary_opening;
    sampling::PolynomialVector z;
    sampling::PolynomialVector z_b;
    sampling::PolynomialVector z_c;
};

struct Protocol2ProofBeginResult;

class Protocol2ProverState {
public:
    Protocol2ProverState(Protocol2ProverState&&) noexcept = default;
    Protocol2ProverState& operator=(Protocol2ProverState&&) noexcept = default;
    Protocol2ProverState(const Protocol2ProverState&) = delete;
    Protocol2ProverState& operator=(const Protocol2ProverState&) = delete;

private:
    Protocol2ProverState() = default;

    friend struct Protocol2ProofBeginResult;
    friend Protocol2ProofBeginResult BeginProtocol2Proof(
        const commitment::CommitmentKey&, const Protocol2Parameters&,
        const Protocol2PublicList&, const Protocol2Witness&,
        sampling::RandomSource&, DiscreteGaussianProvider&,
        Protocol2AuxiliaryCommitmentProvider&);
    friend std::optional<Protocol2Response> RespondProtocol2Proof(
        Protocol2ProverState&, const commitment::CommitmentKey&,
        const Protocol2Parameters&, const arithmetic::Polynomial&,
        sampling::RandomSource&, BernoulliExponentialProvider&);

    std::vector<NTL::ZZ> bits_lift_;
    std::vector<NTL::ZZ> witness_randomness_lift_;
    std::vector<NTL::ZZ> a_lift_;
    std::vector<NTL::ZZ> r_b_lift_;
    std::vector<NTL::ZZ> r_c_lift_;
    std::vector<NTL::ZZ> r_a_lift_;
    std::vector<NTL::ZZ> r_d_lift_;
    std::vector<std::vector<NTL::ZZ>> rho_lifts_;
    std::vector<std::uint8_t> auxiliary_opening_;
    bool consumed_ = false;
};

struct Protocol2ProofBeginResult {
    Protocol2FirstMessage first_message;
    Protocol2ProverState state;
};

Protocol2ProofBeginResult BeginProtocol2Proof(
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    const Protocol2PublicList& public_list,
    const Protocol2Witness& witness,
    sampling::RandomSource& random,
    DiscreteGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

// Returns nullopt on either protocol rejection. The state is consumed on every
// call; the caller must restart BeginProtocol2Proof after an abort.
std::optional<Protocol2Response> RespondProtocol2Proof(
    Protocol2ProverState& state,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    const arithmetic::Polynomial& challenge,
    sampling::RandomSource& random,
    BernoulliExponentialProvider& exponential);

bool VerifyProtocol2Proof(
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    const Protocol2PublicList& public_list,
    const Protocol2FirstMessage& first_message,
    const arithmetic::Polynomial& challenge,
    const Protocol2Response& response,
    const Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

}  // namespace lattice_lrs::proofs
