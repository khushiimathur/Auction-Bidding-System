#include "lattice_lrs/proofs/production_gaussian_provider.hpp"

#include <stdexcept>

namespace lattice_lrs::proofs {

Protocol2GaussianScaleSquared DiagnosticOnlyGaussianScaleProfile::scale_squared(
    Protocol2GaussianSampleKind kind, std::size_t run_index,
    std::size_t repetitions, const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters) const {
    (void)run_index;
    if (repetitions == 0) {
        throw std::invalid_argument(
            "DiagnosticOnlyGaussianScaleProfile requires repetitions > 0");
    }
    const commitment::Parameters& p = key.parameters();
    const NTL::ZZ r = NTL::to_ZZ(static_cast<long>(repetitions));
    const NTL::ZZ k = NTL::to_ZZ(static_cast<long>(parameters.k));
    const NTL::ZZ m = NTL::to_ZZ(static_cast<long>(p.m));
    const NTL::ZZ degree = NTL::to_ZZ(static_cast<long>(p.degree));

    switch (kind) {
        case Protocol2GaussianSampleKind::binary_mask: {
            // Diagnostic-only width: phi1^2 * k * r (dimensional analogue
            // of the per-run D^d_{phi1*sqrt(k)} scaled by sqrt(r) for r
            // independent repetitions). NOT a verified Section 6 value.
            const NTL::ZZ numerator =
                parameters.phi1.numerator * parameters.phi1.numerator * k * r;
            const NTL::ZZ denominator =
                parameters.phi1.denominator * parameters.phi1.denominator;
            return {numerator, denominator};
        }
        case Protocol2GaussianSampleKind::response_mask: {
            // Diagnostic-only width: (phi2*B)^2 * m * d * r.
            const NTL::ZZ numerator = parameters.phi2.numerator *
                                      parameters.phi2.numerator * p.B * p.B *
                                      m * degree * r;
            const NTL::ZZ denominator =
                parameters.phi2.denominator * parameters.phi2.denominator;
            return {numerator, denominator};
        }
        case Protocol2GaussianSampleKind::rho: {
            // Diagnostic-only width: (phi2*B)^2 * m * d * r / k.
            if (parameters.k == 0) {
                throw std::invalid_argument(
                    "DiagnosticOnlyGaussianScaleProfile requires k > 0 for "
                    "the rho kind");
            }
            const NTL::ZZ numerator = parameters.phi2.numerator *
                                      parameters.phi2.numerator * p.B * p.B *
                                      m * degree * r;
            const NTL::ZZ denominator =
                parameters.phi2.denominator * parameters.phi2.denominator * k;
            return {numerator, denominator};
        }
    }
    throw std::invalid_argument(
        "DiagnosticOnlyGaussianScaleProfile received an unknown "
        "Protocol2GaussianSampleKind");
}

Section6GaussianProviderBundle::Section6GaussianProviderBundle(
    const Protocol2RSignGaussianScaleProfile& scale_profile,
    const NTL::ZZ& proposal_center_numerator,
    const NTL::ZZ& proposal_center_denominator)
    : exponential_(),
      d_s_sampler_(exponential_, proposal_center_numerator,
                  proposal_center_denominator),
      bridge_(d_s_sampler_, scale_profile) {}

namespace {

// sigma^2 = phi1^2 * k * r  (binary_mask)
// sigma^2 = 3 * phi2^2 * B^2 * m * d * r  (response_mask)
// sigma^2 = 3 * phi2^2 * B^2 * m * d * r / k  (rho)
// See production_gaussian_provider.hpp for the derivation and the
// BeginProtocol2Proof (r=1) cross-check.
struct SigmaSquared {
    NTL::ZZ numerator;
    NTL::ZZ denominator;
};

SigmaSquared compute_sigma_squared(Protocol2GaussianSampleKind kind,
                                   std::size_t repetitions,
                                   const commitment::CommitmentKey& key,
                                   const Protocol2Parameters& parameters) {
    const commitment::Parameters& p = key.parameters();
    const NTL::ZZ r = NTL::to_ZZ(static_cast<long>(repetitions));
    const NTL::ZZ k = NTL::to_ZZ(static_cast<long>(parameters.k));
    const NTL::ZZ m = NTL::to_ZZ(static_cast<long>(p.m));
    const NTL::ZZ degree = NTL::to_ZZ(static_cast<long>(p.degree));

    switch (kind) {
        case Protocol2GaussianSampleKind::binary_mask: {
            const NTL::ZZ numerator =
                parameters.phi1.numerator * parameters.phi1.numerator * k * r;
            const NTL::ZZ denominator =
                parameters.phi1.denominator * parameters.phi1.denominator;
            return {numerator, denominator};
        }
        case Protocol2GaussianSampleKind::response_mask: {
            const NTL::ZZ numerator = 3 * parameters.phi2.numerator *
                                      parameters.phi2.numerator * p.B * p.B *
                                      m * degree * r;
            const NTL::ZZ denominator =
                parameters.phi2.denominator * parameters.phi2.denominator;
            return {numerator, denominator};
        }
        case Protocol2GaussianSampleKind::rho: {
            if (parameters.k == 0) {
                throw std::invalid_argument(
                    "SigmaProtocol2RSignGaussianProvider requires k > 0 for "
                    "the rho kind");
            }
            const NTL::ZZ numerator = 3 * parameters.phi2.numerator *
                                      parameters.phi2.numerator * p.B * p.B *
                                      m * degree * r;
            const NTL::ZZ denominator =
                parameters.phi2.denominator * parameters.phi2.denominator * k;
            return {numerator, denominator};
        }
    }
    throw std::invalid_argument(
        "SigmaProtocol2RSignGaussianProvider received an unknown "
        "Protocol2GaussianSampleKind");
}

}  // namespace

SigmaProtocol2RSignGaussianProvider::SigmaProtocol2RSignGaussianProvider(
    DiscreteGaussianProvider& sigma_sampler) noexcept
    : sigma_sampler_(sigma_sampler) {}

NTL::ZZ SigmaProtocol2RSignGaussianProvider::sample_coefficient(
    Protocol2GaussianSampleKind kind, std::size_t run_index,
    std::size_t repetitions, const commitment::CommitmentKey& key,
    const Protocol2Parameters& parameters, sampling::RandomSource& random) {
    if (repetitions == 0 || run_index >= repetitions) {
        throw std::invalid_argument(
            "SigmaProtocol2RSignGaussianProvider: run index or repetition "
            "count is invalid");
    }
    const SigmaSquared sigma_squared =
        compute_sigma_squared(kind, repetitions, key, parameters);
    return sigma_sampler_.sample_coefficient(sigma_squared.numerator,
                                             sigma_squared.denominator,
                                             random);
}

SigmaSection6GaussianProviderBundle::SigmaSection6GaussianProviderBundle() noexcept
    : exponential_(), sigma_sampler_(exponential_), bridge_(sigma_sampler_) {}

}  // namespace lattice_lrs::proofs
