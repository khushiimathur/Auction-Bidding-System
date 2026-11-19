#pragma once

// Phase E correction: a production RSignBatchRejectionProvider for Esgin et
// al. (2018/773) Section 6, "Tweaks for r-repeated protocol".
//
// --- History of this file (kept so the correction is legible) ---
// The first version of this file (NormBoundRSignBatchRejectionProvider)
// implemented a deterministic squared-norm threshold, justified by the
// observation that RSignBatchRejectionParameters carried no phi field. An
// independent review correctly rejected that justification: the absence
// of a field in this repository's own interface is evidence about this
// repository's interface, not about Esgin et al.'s mathematics. The paper
// states explicitly (Section 6, "Tweaks for r-repeated protocol"): "we
// apply THE rejection sampling to r-concatenated vectors at once" -- a
// direct reference back to Algorithm 1's Rej(z,c,phi,K) (the SAME
// mechanism already used, unchanged, by Protocol 1/2's per-run rejections
// and by the already-verified proofs::AcceptProtocol2JointResponse), with
// only K rescaled for the r-fold concatenation. This file now implements
// that corrected reading.
//
// --- Exact equation implemented (re-derived and verified twice: once
// independently from Algorithm 1 + Lemma 6, and once by symbolic
// comparison against AcceptProtocol2JointResponse's already-correct
// per-run code) ---
// Algorithm 1 (Rej(z,c,phi,K)): sigma = phi*K;
//   mu(phi) = e^{12/phi + 1/(2*phi^2)}  (Lemma 6);
//   accept with probability p = min(1, (1/mu(phi)) *
//       exp((||c||^2 - 2*<z,c>) / (2*sigma^2))).
// For phi = p/t (PositiveRational) and K_squared = K^2, substituting
// sigma^2 = (p/t)^2 * K_squared and taking logs, multiplying through by
// 2*p^2*K_squared to clear denominators, gives:
//   exponent_numerator   = -(24*p*t + t*t) * K_squared
//                         + t*t * (||center||^2 - 2*<values,center>)
//   exponent_denominator = 2 * p * p * K_squared
// accept deterministically if exponent_numerator >= 0 (p >= 1 in that
// case); otherwise accept with the EXACT probability
// exp(exponent_numerator / exponent_denominator), via the existing exact
// BernoulliExponentialProvider (which requires a strictly negative
// rational log -- exactly what exponent_numerator/exponent_denominator is
// in this branch, since exponent_denominator > 0 always).
//
// `values`/`center` are `z`/`c` in Algorithm 1's notation: `values` is the
// complete r-concatenated response lift (f, or z/z_b/z_c together), and
// `center` is the corresponding complete r-concatenated challenge-
// dependent deterministic part -- exactly the vectors r_sign_impl already
// builds in run-major order before calling accept() once per stage, per
// batch (not per run). This file does not change that orchestration.
//
// --- phi and K_squared: what is used, and why ---
// `parameters.phi` is now required (see ring_signature.hpp's
// RSignBatchRejectionParameters): phi1 for the f-vector stage, phi2 for
// the response stage, populated by r_sign_impl from the SAME
// Protocol2Parameters already used for every other per-run rejection in
// this scheme -- the paper gives no indication that a different phi
// applies to the repeated-batch case.
//
// `parameters.K_squared` (k*r for f; 3*B^2*m*d*r for the response) is used
// as-is: K scales as K_single*sqrt(r) for r independent runs each
// individually bounded by K_single (center-norm-squared additivity across
// independent runs), which was verified in the prior review and is
// unrelated to the separate, still-unresolved Gaussian-sampling-WIDTH
// ambiguity (see production_gaussian_provider.hpp). This file does not
// touch, rely on, or validate `parameters.target_s_squared_numerator/
// denominator` ("144" constants) at all -- those fields are retained on
// the shared struct only because existing tests (e.g.
// tests/test_rsign_batch.cpp's ScriptedRejection) read them, not because
// this provider needs them.
//
// --- What remains unresolved (unchanged from the prior review) ---
// The Gaussian SAMPLING width used to actually draw the f/z/z_b/z_c masks
// (Protocol2RSignGaussianScaleProfile) is a separate, still-open question.
// This file's correction concerns only the ACCEPT/REJECT decision given
// whatever values/center a Gaussian provider produces; it does not supply
// or validate those values.

#include "lattice_lrs/proofs/binary_proof.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"

namespace lattice_lrs::ring_signature {

// Production implementation of Section 6's global/batch rejection,
// delegating the exact Bernoulli(exp(...)) decision to the caller-supplied
// exact BernoulliExponentialProvider (the same interface
// AcceptProtocol2JointResponse already uses for the per-run case). The
// provider reference must outlive this object.
class Section6BatchRejectionProvider final
    : public RSignBatchRejectionProvider {
public:
    explicit Section6BatchRejectionProvider(
        proofs::BernoulliExponentialProvider& exponential) noexcept;

    bool supports_section6_rejection() const noexcept override {
        return true;
    }

    // Throws std::invalid_argument if `values`/`center` have mismatched or
    // zero length, if parameters.phi is not a positive rational, or if
    // parameters.K_squared is negative (a malformed batch). Otherwise
    // implements the exact equation documented above.
    bool accept(const std::vector<NTL::ZZ>& values,
               const std::vector<NTL::ZZ>& center,
               const RSignBatchRejectionParameters& parameters,
               sampling::RandomSource& random) override;

private:
    proofs::BernoulliExponentialProvider& exponential_;
};

}  // namespace lattice_lrs::ring_signature
