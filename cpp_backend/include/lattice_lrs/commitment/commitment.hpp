#pragma once

#include "lattice_lrs/arithmetic/matrix.hpp"
#include "lattice_lrs/sampling/random_source.hpp"
#include "lattice_lrs/sampling/sampler.hpp"

#include <NTL/ZZ.h>

#include <cstddef>

namespace lattice_lrs::commitment {

// Stores the exact rational value T_com^2 = numerator / denominator. This
// allows the paper's Euclidean norm check without floating-point rounding.
struct SquaredNormBound {
    NTL::ZZ numerator;
    NTL::ZZ denominator;

    SquaredNormBound(const NTL::ZZ& numerator, const NTL::ZZ& denominator);
};

struct Parameters {
    std::size_t n;
    std::size_t m;
    std::size_t v;
    std::size_t degree;
    NTL::ZZ q;
    NTL::ZZ B;
    SquaredNormBound T_com_squared;

    void validate() const;
};

class CommitmentKey {
public:
    CommitmentKey(const Parameters& parameters, arithmetic::Matrix G_r,
                  arithmetic::Matrix G_m);

    const Parameters& parameters() const noexcept { return parameters_; }
    const arithmetic::Matrix& G_r() const noexcept { return G_r_; }
    const arithmetic::Matrix& G_m() const noexcept { return G_m_; }
    const arithmetic::Matrix& G() const noexcept { return G_; }

private:
    Parameters parameters_;
    arithmetic::Matrix G_r_;
    arithmetic::Matrix G_m_;
    arithmetic::Matrix G_;
};

struct CommitmentOpening {
    sampling::PolynomialVector commitment;
    sampling::PolynomialVector opening_randomness;
};

CommitmentKey CKeygen(const Parameters& parameters, sampling::RandomSource& random);
CommitmentKey CKeygen(const Parameters& parameters);
// Deterministic commitment map from Section 2.2; randomness is supplied by the
// caller because internal protocols also use non-S_B opening distributions.
sampling::PolynomialVector Com(const CommitmentKey& key,
                               const sampling::PolynomialVector& message,
                               const sampling::PolynomialVector& randomness);
CommitmentOpening Commit(const CommitmentKey& key,
                         const sampling::PolynomialVector& message,
                         sampling::RandomSource& random);
CommitmentOpening Commit(const CommitmentKey& key,
                         const sampling::PolynomialVector& message);

// Implements the relaxed relation exactly: Com_ck(message; randomness) = y*C.
// The caller supplies the relaxation factor y; it is never implicitly set to 1.
bool Open(const CommitmentKey& key,
          const sampling::PolynomialVector& commitment,
          const arithmetic::Polynomial& relaxation_factor,
          const sampling::PolynomialVector& message,
          const sampling::PolynomialVector& randomness);

}  // namespace lattice_lrs::commitment
