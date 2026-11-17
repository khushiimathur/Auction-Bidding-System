#pragma once

#include "lattice_lrs/proofs/protocol2_commitment.hpp"
#include "lattice_lrs/proofs/discrete_gaussian_s.hpp"
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

enum class Protocol2GaussianSampleKind {
    binary_mask,
    response_mask,
    rho,
};

// Section 6's raw Gaussian widths are not fully resolved by the available
// specification. Implementations must opt in only when they implement the
// required repeated-run D_s law; tests may use explicitly non-cryptographic
// deterministic providers.
class Protocol2RSignGaussianProvider {
public:
    virtual ~Protocol2RSignGaussianProvider() = default;
    virtual bool supports_section6_distributions() const noexcept = 0;
    virtual NTL::ZZ sample_coefficient(
        Protocol2GaussianSampleKind kind,
        std::size_t run_index,
        std::size_t repetitions,
        const commitment::CommitmentKey& key,
        const Protocol2Parameters& parameters,
        sampling::RandomSource& random) = 0;
};

struct Protocol2GaussianScaleSquared {
    NTL::ZZ numerator;
    NTL::ZZ denominator;
};

class Protocol2RSignGaussianScaleProfile {
public:
    virtual ~Protocol2RSignGaussianScaleProfile() = default;
    virtual bool supports_section6_distributions() const noexcept = 0;
    virtual Protocol2GaussianScaleSquared scale_squared(
        Protocol2GaussianSampleKind kind,
        std::size_t run_index,
        std::size_t repetitions,
        const commitment::CommitmentKey& key,
        const Protocol2Parameters& parameters) const = 0;
};

// Bridges a resolved rational D_s scale profile to the existing exact D_s
// sampler. No profile is supplied because the Section 6 raw scale mapping
// remains unresolved.
class DsProtocol2RSignGaussianProvider final
    : public Protocol2RSignGaussianProvider {
public:
    DsProtocol2RSignGaussianProvider(
        DiscreteGaussianSProvider& sampler,
        const Protocol2RSignGaussianScaleProfile& scale_profile);

    bool supports_section6_distributions() const noexcept override;
    NTL::ZZ sample_coefficient(
        Protocol2GaussianSampleKind kind,
        std::size_t run_index,
        std::size_t repetitions,
        const commitment::CommitmentKey& key,
        const Protocol2Parameters& parameters,
        sampling::RandomSource& random) override;

private:
    DiscreteGaussianSProvider& sampler_;
    const Protocol2RSignGaussianScaleProfile& scale_profile_;
};

struct Protocol2FirstStageLiftResponse {
    // Both vectors are flattened (j,i)-major, coefficient-minor.
    std::vector<NTL::ZZ> f_nonzero_lift;
    std::vector<NTL::ZZ> center_f_lift;
};

struct Protocol2ResponseLiftData {
    Protocol2IntegerLiftResponses responses;
    std::vector<NTL::ZZ> center_z_lift;
    std::vector<NTL::ZZ> center_z_b_lift;
    std::vector<NTL::ZZ> center_z_c_lift;
    std::vector<std::uint8_t> auxiliary_opening;
};

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
class Protocol2ProofBuilder;

class Protocol2ProverState {
public:
    Protocol2ProverState(Protocol2ProverState&&) noexcept = default;
    Protocol2ProverState& operator=(Protocol2ProverState&&) noexcept = default;
    Protocol2ProverState(const Protocol2ProverState&) = delete;
    Protocol2ProverState& operator=(const Protocol2ProverState&) = delete;

private:
    Protocol2ProverState() = default;

    friend class Protocol2ProofBuilder;
    friend struct Protocol2ProofBeginResult;
    friend Protocol2ProofBeginResult BeginProtocol2Proof(
        const commitment::CommitmentKey&, const Protocol2Parameters&,
        const Protocol2PublicList&, const Protocol2Witness&,
        sampling::RandomSource&, DiscreteGaussianProvider&,
        Protocol2AuxiliaryCommitmentProvider&);
    friend Protocol2ProofBeginResult BeginProtocol2ProofForRSign(
        const commitment::CommitmentKey&, const Protocol2Parameters&,
        const Protocol2PublicList&, const Protocol2Witness&,
        std::size_t, std::size_t, sampling::RandomSource&,
        Protocol2RSignGaussianProvider&,
        Protocol2AuxiliaryCommitmentProvider&);
    friend Protocol2FirstStageLiftResponse
    ComputeProtocol2FirstStageLiftResponse(
        const Protocol2ProverState&, const commitment::CommitmentKey&,
        const Protocol2Parameters&, const arithmetic::Polynomial&);
    friend Protocol2ResponseLiftData ComputeProtocol2ResponseLiftData(
        Protocol2ProverState&, const commitment::CommitmentKey&,
        const Protocol2Parameters&, const arithmetic::Polynomial&);
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

// Section 6 per-run first-message generation. The injected Gaussian provider
// receives the run index and total repetition count so unresolved raw laws
// cannot be silently replaced by Protocol 2's single-run widths.
Protocol2ProofBeginResult BeginProtocol2ProofForRSign(
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    const Protocol2PublicList& public_list,
    const Protocol2Witness& witness,
    std::size_t run_index,
    std::size_t repetitions,
    sampling::RandomSource& random,
    Protocol2RSignGaussianProvider& gaussian,
    Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment);

// Computes challenge-dependent f lifts without applying rejection.
Protocol2FirstStageLiftResponse ComputeProtocol2FirstStageLiftResponse(
    const Protocol2ProverState& state,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    const arithmetic::Polynomial& challenge);

// Consumes the prover state and computes unreduced response and center lifts.
Protocol2ResponseLiftData ComputeProtocol2ResponseLiftData(
    Protocol2ProverState& state,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters,
    const arithmetic::Polynomial& challenge);

// Converts accepted integer lifts to ring responses. Call only after the
// relevant global rejection decision has accepted.
Protocol2Response EncodeProtocol2Response(
    const Protocol2FirstStageLiftResponse& first_stage,
    Protocol2ResponseLiftData&& response_lifts,
    const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters);

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
