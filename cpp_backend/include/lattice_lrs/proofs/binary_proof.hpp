#pragma once

#include "lattice_lrs/commitment/commitment.hpp"

#include <NTL/ZZ.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace lattice_lrs::proofs {

struct PositiveRational {
    NTL::ZZ numerator;
    NTL::ZZ denominator;

    PositiveRational(const NTL::ZZ& numerator, const NTL::ZZ& denominator);
};

struct BinaryProofParameters {
    std::size_t k;
    std::size_t beta;
    PositiveRational phi1;
    PositiveRational phi2;

    // Validates Protocol 1's dimensional, q, and commitment-bound requirements.
    void validate(const commitment::CommitmentKey& key) const;
};

struct BinaryWitness {
    // k rows, beta constant-ring entries per row; each row must be one-hot.
    sampling::PolynomialVector bits;
    sampling::PolynomialVector randomness;
};

struct AuxiliaryCommitmentValue {
    std::vector<std::uint8_t> bytes;
};

struct AuxiliaryCommitmentOpening {
    AuxiliaryCommitmentValue commitment;
    std::vector<std::uint8_t> opening;
};

// Section 4 treats aCom as an assumed hiding/binding auxiliary commitment
// (or a random oracle). This interface keeps that separate from Com_ck.
class AuxiliaryCommitmentProvider {
public:
    virtual ~AuxiliaryCommitmentProvider() = default;
    virtual AuxiliaryCommitmentOpening commit(
        const sampling::PolynomialVector& A,
        const sampling::PolynomialVector& C,
        const sampling::PolynomialVector& D,
        sampling::RandomSource& random) = 0;
    virtual bool verify(const sampling::PolynomialVector& A,
                        const sampling::PolynomialVector& C,
                        const sampling::PolynomialVector& D,
                        const AuxiliaryCommitmentValue& commitment,
                        const std::vector<std::uint8_t>& opening) const = 0;
};

// Samples x in Z from Esgin's D_sigma law:
// P[X=x] is proportional to exp(-x^2/(2*sigma_squared)), where
// sigma_squared = sigma_squared_numerator / sigma_squared_denominator > 0.
// The rational is exact; implementations must use the supplied OS-backed
// RandomSource in production.
class DiscreteGaussianProvider {
public:
    virtual ~DiscreteGaussianProvider() = default;
    virtual NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                                      const NTL::ZZ& sigma_squared_denominator,
                                      sampling::RandomSource& random) = 0;
};

// Samples a Bernoulli variable with exact probability exp(log_numerator /
// log_denominator), for strictly negative rational log values. The rejection
// helper handles nonnegative logs as certain acceptance and calls this provider
// only for negative logs. This is the exact exponential comparison needed by
// Algorithm 1's rejection sampler.
class BernoulliExponentialProvider {
public:
    virtual ~BernoulliExponentialProvider() = default;
    virtual bool sample_exp(const NTL::ZZ& log_numerator,
                            const NTL::ZZ& log_denominator,
                            sampling::RandomSource& random) = 0;
};

struct BinaryProofFirstMessage {
    sampling::PolynomialVector A;
    sampling::PolynomialVector C;
    sampling::PolynomialVector D;
    AuxiliaryCommitmentValue auxiliary_commitment;
};

struct BinaryProofResponse {
    // Entries f_{j,i} for i=1,...,beta-1, in row-major order.
    sampling::PolynomialVector f_nonzero;
    std::vector<std::uint8_t> auxiliary_opening;
    sampling::PolynomialVector z_b;
    sampling::PolynomialVector z_c;
};

struct BinaryProofBeginResult;

class BinaryProofProverState {
public:
    BinaryProofProverState(BinaryProofProverState&&) noexcept = default;
    BinaryProofProverState& operator=(BinaryProofProverState&&) noexcept = default;
    BinaryProofProverState(const BinaryProofProverState&) = delete;
    BinaryProofProverState& operator=(const BinaryProofProverState&) = delete;

private:
    BinaryProofProverState() = default;

    friend struct BinaryProofBeginResult;
    friend BinaryProofBeginResult BeginBinaryProof(
        const commitment::CommitmentKey&, const BinaryProofParameters&,
        const sampling::PolynomialVector&, const BinaryWitness&,
        sampling::RandomSource&, DiscreteGaussianProvider&,
        AuxiliaryCommitmentProvider&);
    friend std::optional<BinaryProofResponse> RespondBinaryProof(
        BinaryProofProverState&, const commitment::CommitmentKey&,
        const BinaryProofParameters&, const arithmetic::Polynomial&,
        sampling::RandomSource&, BernoulliExponentialProvider&);

    sampling::PolynomialVector bits_;
    // Integer lifts are retained for the rejection-sampling inner products.
    // Reducing Gaussian samples modulo q before Rej would change its law.
    std::vector<NTL::ZZ> witness_randomness_lift_;
    std::vector<NTL::ZZ> a_lift_;
    std::vector<NTL::ZZ> r_c_lift_;
    std::vector<NTL::ZZ> r_a_lift_;
    std::vector<NTL::ZZ> r_d_lift_;
    std::vector<std::uint8_t> auxiliary_opening_;
    bool consumed_ = false;
};

struct BinaryProofBeginResult {
    BinaryProofFirstMessage first_message;
    BinaryProofProverState state;
};

BinaryProofBeginResult BeginBinaryProof(
    const commitment::CommitmentKey& key,
    const BinaryProofParameters& parameters,
    const sampling::PolynomialVector& public_commitment,
    const BinaryWitness& witness,
    sampling::RandomSource& random,
    DiscreteGaussianProvider& gaussian,
    AuxiliaryCommitmentProvider& auxiliary_commitment);

// Returns nullopt if either protocol rejection step aborts. The state is
// consumed on every call; callers restart BeginBinaryProof after an abort.
std::optional<BinaryProofResponse> RespondBinaryProof(
    BinaryProofProverState& state,
    const commitment::CommitmentKey& key,
    const BinaryProofParameters& parameters,
    const arithmetic::Polynomial& challenge,
    sampling::RandomSource& random,
    BernoulliExponentialProvider& exponential);

arithmetic::Polynomial BinaryChallengeFromExponent(const commitment::Parameters& parameters,
                                                   std::size_t exponent);
arithmetic::Polynomial SampleBinaryChallenge(const commitment::Parameters& parameters,
                                             sampling::RandomSource& random);

bool VerifyBinaryProof(const commitment::CommitmentKey& key,
                       const BinaryProofParameters& parameters,
                       const sampling::PolynomialVector& public_commitment,
                       const BinaryProofFirstMessage& first_message,
                       const arithmetic::Polynomial& challenge,
                       const BinaryProofResponse& response,
                       const AuxiliaryCommitmentProvider& auxiliary_commitment);

}  // namespace lattice_lrs::proofs
