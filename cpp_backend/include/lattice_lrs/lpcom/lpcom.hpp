#pragma once

// LPCom: the lattice-based commitment scheme of Cabarcas, Demirel,
// Goepfert, Lancrenon and Wunderer, "An Unconditionally Hiding and
// Long-Term Binding Post-Quantum Commitment Scheme" (ePrint 2015/628),
// Section 3, Figure 1 ("GenCom/Com/Unv").
//
// --- Why this exists as a SEPARATE module from lattice_lrs::commitment ---
// lattice_lrs::commitment::Com (commitment/commitment.hpp) is Esgin et
// al.'s INTERNAL ring-signature commitment: it operates over the ring
// R_q = Z_q[X]/(X^d+1) (arithmetic::Polynomial/PolynomialVector/Matrix),
// and is used only to build a ring member's own public key
// (pk = Com(0; sk_randomness)); it has nothing to do with hiding a bid
// amount. LPCom is the AUCTION-LEVEL commitment to the bid amount
// itself. To keep that distinction unambiguous rather than relying on
// callers to remember it, LPCom is implemented over PLAIN Z_q vectors
// and matrices (std::vector<NTL::ZZ>, not ring elements) -- a visibly
// different mathematical structure, in its own namespace, with its own
// parameter type. Nothing here reuses or modifies
// lattice_lrs::commitment's types or algorithm.
//
// --- Construction (paper's Figure 1) ---
//   pk  = (A1, A2) with A1 in Z_q^(m x n), A2 in Z_q^(m x k), sampled so
//         that A = [A1 | A2] has TRIVIAL KERNEL mod q (the only x with
//         Ax = 0 mod q is x = 0).
//   Com(pk, v):  r <- Z_q^k uniform; e <- D^m_sigma (discrete Gaussian,
//                paper's pi-convention density rho_sigma(x) =
//                exp(-pi x^2 / sigma^2) / sigma, i.e. exactly the "D_s"
//                law lattice_lrs::proofs::ExactDiscreteGaussianSProvider
//                already implements with s = sigma);
//                c = A1 v + A2 r + e (mod q). Output (c, r); v itself is
//                part of the opening the committer must remember too.
//   Unv(pk, c, v, r):  recompute e' = c - A1 v - A2 r (mod q), take its
//                centered representative in (-q/2, q/2], accept iff
//                ||e'|| <= B.
//
// --- Paper-faithful vs. experimental: read before changing B/sigma/q ---
// Theorem 1 (correctness), Theorem 2 (statistical hiding, requires sigma
// above a smoothing-parameter bound of Lambda_q(A2)), and Theorem 3
// (computational binding, reduces to alpha-SVP with alpha = 2B /
// lambda_1(Lambda_q(A))) are PROVEN in the paper for suitable parameter
// choices. This file implements the ALGORITHMS exactly; it does NOT
// independently re-derive or verify Theorem 2/3's bounds for any
// concrete (n, k, m, q, sigma, B) below, and makes NO claim of any
// specific bit-level post-quantum security. ExperimentalDemoParameters()
// below is explicitly an experimental, demo-scale instantiation loosely
// following the asymptotic shape of the paper's own Figure 2 (which the
// paper itself describes as "not at all optimized for concrete
// instantiations"), chosen only so GenCom/Com/Unv run quickly in a demo;
// it is not, and must not be presented as, a validated security
// parameter set. See docs/LPCOM_INTEGRATION.md for the full discussion.

#include "lattice_lrs/proofs/discrete_gaussian_s.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

#include <cstddef>
#include <vector>

namespace lattice_lrs::lpcom {

using Vector = std::vector<NTL::ZZ>;
using Matrix = std::vector<Vector>;  // row-major, Matrix[row][col]

// GenCom's public output: pk = (A1, A2), plus the parameters needed to
// run Com/Unv against it. q is required to be prime (checked in
// GenCom): this makes the trivial-kernel validation below an exact rank
// computation over the field Z_q, not an approximation. The paper does
// not require q prime; this is a deliberate, documented implementation
// choice to make the validation exact and tractable.
struct Parameters {
    std::size_t n = 0;  // message-vector rank (v in Z_q^n)
    std::size_t k = 0;  // randomness-vector rank (r in Z_q^k)
    std::size_t m = 0;  // lattice dimension / number of rows of A
    NTL::ZZ q;          // modulus, prime, entries of A1/A2/c live in [0, q)

    // sigma^2, the discrete Gaussian's scale-squared, as an exact
    // positive rational (numerator/denominator), in the paper's
    // pi-convention (rho_sigma(x) = exp(-pi x^2 / sigma^2) / sigma).
    NTL::ZZ sigma_squared_numerator;
    NTL::ZZ sigma_squared_denominator;

    // Euclidean-norm acceptance bound B for Unv (paper: accept iff
    // ||e|| <= B; Theorem 1 requires B > sigma*sqrt(m/(2*pi)) for
    // correctness to hold with overwhelming probability).
    NTL::ZZ B;

    Matrix A1;  // m x n, entries in [0, q)
    Matrix A2;  // m x k, entries in [0, q)
};

// A commitment: c in Z_q^m (what the committer publishes).
struct Commitment {
    Vector c;
};

// The opening a committer must keep to later reveal: the message v
// itself and the randomness r (NOT the error e -- Unv recomputes e from
// c, v, r, so there is no need to store it separately, matching the
// paper's own (c, r) output of Com; v is carried alongside r here
// purely so callers have one self-contained struct to keep private
// until settlement).
struct Opening {
    Vector v;
    Vector r;
};

struct ComResult {
    Commitment commitment;
    Opening opening;
};

// GenCom(1^kappa, 1^k): samples A1, A2 uniformly over Z_q, mod-q entries,
// and RETRIES (up to max_attempts) until [A1 | A2] has full column rank
// mod q (equivalently: trivial kernel, since q is prime and this
// requires m >= n + k). Throws std::invalid_argument for inconsistent
// dimensions/modulus (q not prime, m < n + k, non-positive sigma^2 or B)
// and std::runtime_error if no full-rank sample is found within
// max_attempts (a real, reportable failure -- never silently accepted
// with an unvalidated A).
Parameters GenCom(std::size_t n, std::size_t k, std::size_t m,
                   const NTL::ZZ& q,
                   const NTL::ZZ& sigma_squared_numerator,
                   const NTL::ZZ& sigma_squared_denominator,
                   const NTL::ZZ& B, sampling::RandomSource& random,
                   std::size_t max_attempts = 64);

// Com(pk, v): validates v has length n with every coordinate in
// [0, q), samples r uniformly in Z_q^k (sampling::sample_uniform_coefficient,
// a CSPRNG-backed uniform sampler already used throughout this
// codebase) and e coordinate-wise from the exact D_s discrete Gaussian
// (`gaussian`, e.g. lattice_lrs::proofs::ExactDiscreteGaussianSProvider --
// NOT a rounded continuous sampler), then computes c = A1 v + A2 r + e
// (mod q). Returns both the commitment and the opening (v, r) the
// caller must keep private until it chooses to reveal it.
ComResult Com(const Parameters& params, const Vector& v,
               proofs::DiscreteGaussianSProvider& gaussian,
               sampling::RandomSource& random);

// Unv(pk, c, v, r): recomputes e' = c - A1 v - A2 r (mod q), centers it
// to (-q/2, q/2], and accepts iff its Euclidean norm is <= B. Returns
// false (never throws) for a norm violation; throws std::invalid_argument
// only for a structurally malformed input (wrong vector lengths, c/v/r
// coordinates outside [0, q)), since that indicates caller error, not a
// legitimate failed opening.
bool Unv(const Parameters& params, const Commitment& commitment,
          const Vector& v, const Vector& r);

// An explicitly experimental, demo-scale parameter profile, loosely
// following the asymptotic SHAPE of the paper's Figure 2 (kappa
// constant, n = k, m = 3k, q on the order of k^2, sigma on the order of
// k^1.25) with k chosen small (16) and as a perfect fourth power so that
// sigma^2 = k^2.5 is an EXACT integer (16^1.25 = 32 exactly), since the
// exact discrete Gaussian sampler used here requires an exact rational
// scale-squared, not a floating-point approximation. q is the nearest
// prime to k^2 = 256 (257). B is sqrt(m)*sigma rounded up to the nearest
// integer (B itself is only a norm threshold, not fed into the exact
// sampler, so rounding it is not a fidelity problem the way rounding
// sigma^2 would be).
//
// This is NOT the paper's own suggested k=128 instantiation (used there
// only for the separate Sigma*-protocol parameter set in Figure 4, and
// explicitly NOT claimed by the paper to be concretely optimized
// either), and this file makes NO bit-security claim for it. It exists
// solely so GenCom/Com/Unv complete quickly in the demo. See
// docs/LPCOM_INTEGRATION.md.
Parameters ExperimentalDemoParameters(sampling::RandomSource& random);

// A second experimental, demo-scale profile with n = 1: for committing
// to a SINGLE scalar message (e.g. one bid amount), as opposed to
// ExperimentalDemoParameters()'s n = k general message vector shape.
// Same sigma^2 = 1024 (exact) and q = 257 (prime) as
// ExperimentalDemoParameters(); k = 16, m = 24 (>= n + k = 17). B =
// ceil(sqrt(24) * 32) = 157. Same "no bit-security claim" caveat
// applies -- see the header comment above.
Parameters ScalarMessageDemoParameters(sampling::RandomSource& random);

}  // namespace lattice_lrs::lpcom
