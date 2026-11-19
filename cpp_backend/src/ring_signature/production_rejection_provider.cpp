#include "lattice_lrs/ring_signature/production_rejection_provider.hpp"

#include <stdexcept>

namespace lattice_lrs::ring_signature {

Section6BatchRejectionProvider::Section6BatchRejectionProvider(
    proofs::BernoulliExponentialProvider& exponential) noexcept
    : exponential_(exponential) {}

bool Section6BatchRejectionProvider::accept(
    const std::vector<NTL::ZZ>& values, const std::vector<NTL::ZZ>& center,
    const RSignBatchRejectionParameters& parameters,
    sampling::RandomSource& random) {
    if (values.empty() || values.size() != center.size()) {
        throw std::invalid_argument(
            "Section6BatchRejectionProvider requires nonempty, "
            "equal-length values/center vectors");
    }
    if (parameters.phi.numerator <= 0 || parameters.phi.denominator <= 0) {
        throw std::invalid_argument(
            "Section6BatchRejectionProvider requires a positive rational "
            "phi (phi1 for the f stage, phi2 for the response stage)");
    }
    if (parameters.K_squared < 0) {
        throw std::invalid_argument("K^2 must be nonnegative");
    }

    const NTL::ZZ& p = parameters.phi.numerator;
    const NTL::ZZ& t = parameters.phi.denominator;
    const NTL::ZZ& K_squared = parameters.K_squared;

    NTL::ZZ inner_product(0);
    NTL::ZZ center_norm_squared(0);
    for (std::size_t i = 0; i < values.size(); ++i) {
        inner_product += values[i] * center[i];
        center_norm_squared += center[i] * center[i];
    }

    if (center_norm_squared > K_squared) {
        throw std::invalid_argument(
            "Section6BatchRejectionProvider: center exceeds K^2 -- the "
            "caller constructed an inconsistent batch (this mirrors "
            "AcceptProtocol2JointResponse's own center-bound check)");
    }

    // Exact re-derivation of Algorithm 1's Rej(z,c,phi,K) acceptance test
    // for phi = p/t: see the header comment for the full derivation. This
    // is algebraically identical in form to
    // proofs::AcceptProtocol2JointResponse's exponent_numerator/
    // exponent_denominator, generalized from the single-run K_squared to
    // the r-concatenated batch K_squared already computed by
    // ring_signature.cpp's r_sign_impl.
    const NTL::ZZ exponent_denominator = 2 * p * p * K_squared;
    const NTL::ZZ exponent_numerator =
        -(24 * p * t + t * t) * K_squared +
        t * t * (center_norm_squared - 2 * inner_product);

    if (exponent_numerator >= 0) {
        return true;
    }
    return exponential_.sample_exp(exponent_numerator, exponent_denominator,
                                   random);
}

}  // namespace lattice_lrs::ring_signature
