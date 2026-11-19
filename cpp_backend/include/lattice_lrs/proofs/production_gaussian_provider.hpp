#pragma once

// Phase E: production wiring for Protocol2RSignGaussianProvider.
//
// --- RESOLVED (this supersedes the "blocking ambiguity" this file
// originally reported) ---
// A later audit, backed by inspecting the actual PDF page images and text
// layer of Esgin et al. (2018/773) rather than OCR alone, established the
// verified Section 6 repeated-round variances:
//   sigma_f^2 = phi1^2 * k * r
//   sigma_z^2 = 3 * phi2^2 * B^2 * m * d * r
// confirmed by direct comparison against the already-shipping, already-
// correct r=1 formulas in BeginProtocol2Proof (protocol2_proof.cpp:578-597,
// unmodified by this change), which reduce to exactly these at r=1.
//
// Crucially, these are SIGMA-convention (no pi) variances, and
// DiscreteGaussianProvider / ExactDiscreteGaussianProvider (discrete_
// gaussian.hpp/.cpp) already sample that exact law (P[X=x] proportional to
// exp(-x^2/(2*sigma^2))) directly from a rational sigma^2, with no pi
// anywhere in their own mathematics. There is therefore no 2*pi conversion
// to perform, and no irrationality problem: SigmaProtocol2RSignGaussianProvider
// (below) feeds these sigma^2 values straight into the existing, unmodified
// ExactDiscreteGaussianProvider. This is the production provider.
//
// --- What the D_s-based machinery below (DiagnosticOnlyGaussianScaleProfile,
// Section6GaussianProviderBundle) now is: EXPERIMENTAL, SUPERSEDED for this
// purpose ---
// The D_s (with-pi) route was this file's first attempt, before the above
// was resolved. It remains in the repository (not removed, since removal
// was not demonstrated necessary) but MUST NOT be used as the production
// Gaussian provider for RSign: feeding a sigma-convention variance into a
// sampler documented to expect an s^2 (with-pi) parameter, with no
// conversion applied, samples from the wrong distribution (effective width
// smaller by a factor of sqrt(2*pi) ~= 2.5066). This was confirmed by audit,
// not merely suspected. See DiagnosticOnlyGaussianScaleProfile's own updated
// comment below.
//
// --- What already exists and is already production-grade (reused here,
// not reimplemented) ---
// - ExactBernoulliPiExponentialProvider: exact Bernoulli(exp(-pi*t))
//   sampler for rational t >= 0 (bernoulli_pi_exponential.cpp), used
//   correctly by the Karney/Agrawal-style D_s exact sampler.
// - ExactDiscreteGaussianSProvider: exact sampler for Esgin's D_s law,
//   mass proportional to exp(-pi*x^2/s_squared) (discrete_gaussian_s.cpp).
//   Verified against its own stated law by inspection; it is a correct
//   implementation of a well-defined distribution GIVEN a correct
//   s_squared input.
// - DsProtocol2RSignGaussianProvider (protocol2_proof.hpp/.cpp): the
//   existing bridge from a Protocol2RSignGaussianScaleProfile to the exact
//   D_s sampler, already satisfying the Protocol2RSignGaussianProvider
//   interface RSign requires.
//
// --- The blocking ambiguity (reported, not guessed past) ---
// Protocol2RSignGaussianProvider's own header comment already states:
// "Section 6's raw Gaussian widths are not fully resolved by the available
// specification." This file's author independently attempted to resolve
// that gap for Phase E and reached the same conclusion, for the following
// reason:
//
// Esgin et al. (2018/773) Section 2.3 defines TWO related but distinct
// Gaussian conventions:
//   (1) the "D_s" family: density proportional to exp(-pi*x^2/s^2)
//       (the ellipsoid/spherical discrete Gaussian with parameter s), and
//   (2) the "D_sigma" ("discrete normal") family, EXPLICITLY DEFINED as
//       D_s with s = sigma*sqrt(2*pi) -- i.e. D_sigma's density has no pi
//       in its own exponent (proportional to exp(-x^2/(2*sigma^2))) only
//       because the pi has already been absorbed into the s<->sigma
//       conversion.
// This repository's own two existing samplers mirror that split exactly:
// DiscreteGaussianProvider::sample_coefficient takes "sigma_squared" and
// is documented as exp(-x^2/(2*sigma_squared)) -- no pi -- while
// DiscreteGaussianSProvider::sample_coefficient_from_scale_squared takes
// "s_squared" and is documented as exp(-pi*x^2/s_squared) -- with pi. Both
// exist, deliberately, because Protocol 1/2's ORIGINAL (non-repeated)
// per-run masking already uses the sigma (no-pi) convention (confirmed by
// symbolically re-deriving proofs::AcceptProtocol2JointResponse's exact
// exponent formula against Lemma 6's Rej(z,c,phi,K)/mu(phi) equations and
// finding an exact match using phi2 directly as a sigma-convention width,
// with no stray factor of pi anywhere), while
// Protocol2RSignGaussianProvider -- used ONLY for RSign's r-repeated batch
// sampling -- is typed to feed the D_s (WITH pi) sampler instead.
//
// Converting a sigma-convention width (e.g. the paper's own
// "D^d_{phi1*sqrt(k)}"-style per-run notation, extended by sqrt(r) for the
// repeated case) into the s^2 the D_s sampler needs would require
// s^2 = 2*pi*sigma^2 -- but pi is irrational, and this codebase's entire
// sampling/rejection infrastructure is built on EXACT rational (NTL::ZZ
// numerator/denominator) arithmetic with no floating point anywhere. There
// is no way to represent that conversion exactly, which strongly suggests
// either (a) the paper's own r-repeated-case notation is ALREADY meant in
// the s (with-pi) convention directly (so no conversion is needed, and the
// width IS s, not sigma) or (b) some other relationship holds that this
// implementation could not establish from the available OCR'd text with
// confidence (the specific digits "12" appearing in the tweaks paragraph's
// "D^d_{12*sqrt(k*r)}"/"D^{md}_{12*B*sqrt(3*m*d*r)}" notation are
// ambiguous: they could be the literal constant 12 reused from Lemma 4's
// unrelated "Pr[|z|>12*sigma]<2^-100" tail-safety bound, or OCR corruption
// of "phi_1"/"phi_2" subscript glyphs -- this repository's rendering of
// nearby formulas, e.g. Theorem 1's "5^4*phi_1^4" rendering as "54phi41" in
// the same extraction, demonstrates that phi-subscript corruption into
// adjacent digit strings DOES happen in this exact source).
//
// Per the Phase E instructions, this ambiguity is reported rather than
// silently resolved. No Protocol2RSignGaussianScaleProfile claiming to be
// "the Section 6 production scale profile" is implemented in this file.
//
// --- What this file DOES provide ---
// A convenience bundle (Section6GaussianProviderBundle) that wires the
// EXISTING exact D_s machinery to an OS-backed RandomSource and to ANY
// caller-supplied Protocol2RSignGaussianScaleProfile, so the PLUMBING
// (exact sampling, RNG/exception propagation, interface conformance) can
// be exercised and tested end-to-end without that plumbing itself being
// the blocked part. DiagnosticOnlyGaussianScaleProfile, included here, is
// explicitly NOT a claim about Section 6's true widths -- see its own
// doc comment -- and must never be described as "production" or
// "paper-validated" by any caller.

#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/bernoulli_pi_exponential.hpp"
#include "lattice_lrs/proofs/discrete_gaussian.hpp"
#include "lattice_lrs/proofs/discrete_gaussian_s.hpp"
#include "lattice_lrs/proofs/protocol2_proof.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

namespace lattice_lrs::proofs {

// EXPERIMENTAL / SUPERSEDED for production RSign use -- see the file-level
// comment above. NOT a Section 6 scale profile: it returns a sigma-
// convention variance (no pi) but is consumed by DsProtocol2RSignGaussianProvider
// as if it were an s^2 (with-pi) parameter, with no 2*pi conversion applied.
// Confirmed by audit to sample a narrower-than-intended distribution
// (effective width off by a factor of sqrt(2*pi)); retained only as a
// plumbing/RNG-propagation exercise for the D_s sampler chain, never as a
// production Gaussian provider. Use SigmaProtocol2RSignGaussianProvider
// instead for RSign.
class DiagnosticOnlyGaussianScaleProfile final
    : public Protocol2RSignGaussianScaleProfile {
public:
    bool supports_section6_distributions() const noexcept override {
        return true;
    }

    Protocol2GaussianScaleSquared scale_squared(
        Protocol2GaussianSampleKind kind, std::size_t run_index,
        std::size_t repetitions, const commitment::CommitmentKey& key,
        const Protocol2Parameters& parameters) const override;
};

// Owns the exact-sampler chain (Bernoulli-pi -> D_s -> RSign bridge) so
// callers get a single object implementing Protocol2RSignGaussianProvider,
// backed by whatever RandomSource/scale profile they supply (production
// callers should use sampling::SystemRandomSource; the scale profile
// determines whether the result is anything more than a plumbing check --
// see the file-level comment).
class Section6GaussianProviderBundle final {
public:
    // IMPORTANT (discovered during Phase E testing, not stated in either
    // sampler's own doc comment): ExactDiscreteGaussianSProvider's exact
    // Karney/Agrawal-style algorithm proposes from a discrete Laplace
    // mixture stepped by `proposal_center`, then rejects down to the true
    // D_s law. Its RUNNING TIME degrades sharply -- tens of thousands of
    // expensive exact Bernoulli(exp(-pi*t)) calls per sampled coefficient,
    // each itself an unbounded interval-refinement loop -- when
    // `proposal_center` is small relative to sqrt(s_squared). A default of
    // 1/1 (this constructor's previous default) was observed to make a
    // single sample_coefficient call take tens of seconds for an
    // s_squared on the order of 10^4-10^5; choosing proposal_center
    // approximately sqrt(s_squared) for the scales actually in use made
    // the identical call return in well under a millisecond. There is no
    // default that is efficient across arbitrarily different scales, so
    // this constructor requires the caller to choose one appropriate to
    // the scale(s) it intends to sample -- it is a required parameter with
    // no default, not an optional tuning knob.
    Section6GaussianProviderBundle(
        const Protocol2RSignGaussianScaleProfile& scale_profile,
        const NTL::ZZ& proposal_center_numerator,
        const NTL::ZZ& proposal_center_denominator);

    Protocol2RSignGaussianProvider& provider() noexcept { return bridge_; }

private:
    ExactBernoulliPiExponentialProvider exponential_;
    ExactDiscreteGaussianSProvider d_s_sampler_;
    DsProtocol2RSignGaussianProvider bridge_;
};

// --- Production Gaussian provider for RSign (Section 6, r-repeated). ---
//
// Computes the verified sigma-convention variances directly and samples
// them with the existing, unmodified ExactDiscreteGaussianProvider --
// no D_s, no pi, no approximation. Exact formulas (phi1, phi2 are the
// PositiveRational fields of Protocol2Parameters; k from parameters.k;
// m, degree, B from key.parameters(); r = repetitions):
//
//   binary_mask   (f_{j,i}):      sigma^2 = phi1^2 * k * r
//   response_mask (z, z_b, z_c):  sigma^2 = 3 * phi2^2 * B^2 * m * d * r
//   rho           (rho_j):        sigma^2 = 3 * phi2^2 * B^2 * m * d * r / k
//
// The response_mask and rho formulas are the non-repeated
// BeginProtocol2Proof formulas (protocol2_proof.cpp:582-595) generalized
// by the factor r; at r=1 they reduce to exactly those already-shipping
// lines (verified below in tests/test_production_rsign_providers.cpp).
//
// This fixes the PARAMETERIZATION of RSign's repeated-round Gaussian
// sampling (the masks are now drawn from the width the paper's Table 4
// states, via an exact, already-verified sampler). It does NOT, by
// itself, establish that RSign is production-secure: the Section 6
// completeness/soundness analysis as a whole (q-sizing, the global
// rejection's own still-separately-reviewed exponent, the commitment
// scheme's binding parameters, etc.) has not been re-audited end-to-end
// as a consequence of this specific fix, and no end-to-end production
// RSign/LRSign run has been attempted using it.
class SigmaProtocol2RSignGaussianProvider final
    : public Protocol2RSignGaussianProvider {
public:
    // sigma_sampler must outlive this object. Not copied/reimplemented --
    // this class only computes sigma^2 and delegates sampling to it.
    explicit SigmaProtocol2RSignGaussianProvider(
        DiscreteGaussianProvider& sigma_sampler) noexcept;

    bool supports_section6_distributions() const noexcept override {
        return true;
    }

    // Throws std::invalid_argument for repetitions==0, run_index>=repetitions,
    // or (for the rho kind only) parameters.k==0. Propagates whatever
    // sigma_sampler/random throw (e.g. an RNG failure).
    NTL::ZZ sample_coefficient(Protocol2GaussianSampleKind kind,
                               std::size_t run_index, std::size_t repetitions,
                               const commitment::CommitmentKey& key,
                               const Protocol2Parameters& parameters,
                               sampling::RandomSource& random) override;

private:
    DiscreteGaussianProvider& sigma_sampler_;
};

// Owns the exact sigma-sampler chain (Bernoulli-exponential -> D_sigma ->
// RSign bridge) so callers get a single object implementing
// Protocol2RSignGaussianProvider, backed by whatever RandomSource the
// caller supplies when sampling (production callers should use
// sampling::SystemRandomSource). This is the recommended production
// wiring for RSign's Gaussian provider.
class SigmaSection6GaussianProviderBundle final {
public:
    SigmaSection6GaussianProviderBundle() noexcept;

    Protocol2RSignGaussianProvider& provider() noexcept { return bridge_; }

private:
    ExactBernoulliExponentialProvider exponential_;
    ExactDiscreteGaussianProvider sigma_sampler_;
    SigmaProtocol2RSignGaussianProvider bridge_;
};

}  // namespace lattice_lrs::proofs
