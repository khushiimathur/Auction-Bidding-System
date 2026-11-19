// Phase E correction tests: Section6BatchRejectionProvider (the corrected
// Algorithm-1-based global/batch rejection) and the production Gaussian
// plumbing (Section6GaussianProviderBundle /
// DiagnosticOnlyGaussianScaleProfile, unchanged by this correction). See
// ring_signature/production_rejection_provider.hpp for the exact
// derivation of the corrected accept() equation (re-verified twice: once
// from Algorithm 1 + Lemma 6 directly, once by symbolic comparison against
// proofs::AcceptProtocol2JointResponse) and
// proofs/production_gaussian_provider.hpp for what remains unresolved
// about the Gaussian sampling widths.
//
// These are functional/diagnostic tests. They establish that
// Section6BatchRejectionProvider computes the documented equation exactly
// and delegates correctly to the exact Bernoulli-exponential provider.
// They do not, by themselves, establish that any RSign run using these
// providers is cryptographically sound or matches Esgin et al.'s exact
// security parameters (the Gaussian-width question remains open).

#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/production_gaussian_provider.hpp"
#include "lattice_lrs/ring_signature/production_rejection_provider.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lattice_lrs::arithmetic;
using namespace lattice_lrs::commitment;
using namespace lattice_lrs::proofs;
using namespace lattice_lrs::ring_signature;
using namespace lattice_lrs::sampling;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

class ZeroByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        std::fill(output, output + length, std::uint8_t(0));
    }
};

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("simulated entropy failure");
    }
};

// Records the exact (log_numerator, log_denominator) BernoulliExponential
// is asked to evaluate, so a test can independently hand-compute the
// expected rational and assert exact equality -- not just "some
// plausible-looking call happened".
class RecordingBernoulliExponentialProvider final
    : public BernoulliExponentialProvider {
public:
    explicit RecordingBernoulliExponentialProvider(bool result_to_return)
        : result_(result_to_return) {}

    bool sample_exp(const NTL::ZZ& log_numerator,
                    const NTL::ZZ& log_denominator,
                    RandomSource&) override {
        ++call_count;
        last_numerator = log_numerator;
        last_denominator = log_denominator;
        return result_;
    }

    std::size_t call_count = 0;
    NTL::ZZ last_numerator;
    NTL::ZZ last_denominator;

private:
    bool result_;
};

CommitmentKey make_key(RandomSource& random) {
    Parameters parameters{1, 1, 4, 86, z(1000000007), z(1),
                         SquaredNormBound(z(1) << 256, z(1))};
    return CKeygen(parameters, random);
}

Protocol2Parameters make_proof_parameters() {
    return Protocol2Parameters{2, 2, PositiveRational(z(22), z(1)),
                               PositiveRational(z(22), z(1))};
}

RSignBatchRejectionParameters make_rejection_parameters(
    RSignRejectionStage stage, const PositiveRational& phi,
    const NTL::ZZ& K_squared) {
    // The retained target_s_squared_numerator/denominator fields are not
    // used by Section6BatchRejectionProvider (see its header comment);
    // they are filled with a placeholder here purely because the struct
    // still carries them for other callers/tests.
    return RSignBatchRejectionParameters{
        stage, 2, 2, 2, 1, 86, z(1), phi, K_squared, z(0), z(1)};
}

// --- Section6BatchRejectionProvider ---

void test_rejection_advertises_section6_support() {
    RecordingBernoulliExponentialProvider exponential(true);
    Section6BatchRejectionProvider provider(exponential);
    require(provider.supports_section6_rejection() == true,
            "production rejection provider must advertise Section 6 support");
}

void test_rejection_positive_exponent_accepts_deterministically() {
    // phi=22/1, K_squared=10. values=center=0 -> inner_product=0,
    // center_norm_squared=0. exponent_numerator = -(24*22*1+1)*10 + 0
    //   = -5290 < 0 is WRONG for "positive" -- choose values/center so
    // that center_norm_squared - 2*inner_product is large and positive
    // enough to overcome the inherent -(24pt+t^2)*K^2 term.
    // With phi=1/1 (t=1,p=1), K_squared=1: baseline term =
    // -(24*1*1+1)*1 = -25. Need t^2*(||c||^2-2<v,c>) > 25 i.e.
    // The -(24pt+t^2) term is multiplied by K_squared, not a flat
    // constant, and ||center||^2 <= K_squared always (enforced by the
    // provider's own guard), so making the exponent positive with a
    // nonnegative inner product is impossible; instead use a large
    // negative inner product (values and center pointing in opposite
    // directions) to drive -2*<values,center> strongly positive.
    // center=(-6) -> ||c||^2=36 (<= K_squared=36); values=100 ->
    // <v,c>=-600 -> -2<v,c>=1200. exponent_numerator =
    // -(24*1*1+1)*36 + 1*(36+1200) = -900 + 1236 = 336 > 0.
    RecordingBernoulliExponentialProvider exponential(false);
    ZeroByteSource random;
    Section6BatchRejectionProvider provider(exponential);

    const PositiveRational phi(z(1), z(1));
    const std::vector<NTL::ZZ> values{z(100)};
    const std::vector<NTL::ZZ> center{z(-6)};
    const auto parameters = make_rejection_parameters(
        RSignRejectionStage::f_vector, phi, z(36));  // K^2 >= ||center||^2

    require(provider.accept(values, center, parameters, random),
            "a nonnegative exponent must accept deterministically");
    require(exponential.call_count == 0,
            "a deterministic accept (exponent >= 0) must never consult the "
            "Bernoulli-exponential provider");
}

void test_rejection_zero_exponent_accepts_deterministically() {
    // phi=1/1 (p=1,t=1), K_squared=36: threshold term = 25*K_squared=900.
    // center=(-6) -> ||c||^2=36 (<= K_squared); values=72 ->
    // <v,c>=-432 -> -2<v,c>=864. bracket = 36+864=900 = 25*36 exactly ->
    // exponent_numerator = -900 + 900 = 0 exactly.
    RecordingBernoulliExponentialProvider exponential(false);
    ZeroByteSource random;
    Section6BatchRejectionProvider provider(exponential);

    const PositiveRational phi(z(1), z(1));
    const std::vector<NTL::ZZ> values{z(72)};
    const std::vector<NTL::ZZ> center{z(-6)};
    const auto parameters =
        make_rejection_parameters(RSignRejectionStage::f_vector, phi, z(36));

    require(provider.accept(values, center, parameters, random),
            "an exactly-zero exponent must accept deterministically "
            "(p = 1 exactly)");
    require(exponential.call_count == 0,
            "a zero exponent must not consult the Bernoulli-exponential "
            "provider either");
}

void test_rejection_negative_exponent_uses_exact_probability() {
    // phi=22/1 (p=22,t=1), K_squared=4 (e.g. k*r=2*2 for the f stage).
    // values=center=0: inner_product=0, center_norm_squared=0.
    // exponent_numerator = -(24*22*1+1^2)*4 + 1*(0-0) = -(529)*4 = -2116.
    // exponent_denominator = 2*22^2*4 = 3872.
    RecordingBernoulliExponentialProvider exponential(true);
    ZeroByteSource random;
    Section6BatchRejectionProvider provider(exponential);

    const PositiveRational phi(z(22), z(1));
    const std::vector<NTL::ZZ> values{z(0), z(0)};
    const std::vector<NTL::ZZ> center{z(0), z(0)};
    const auto parameters =
        make_rejection_parameters(RSignRejectionStage::f_vector, phi, z(4));

    const bool result = provider.accept(values, center, parameters, random);
    require(result == true,
            "the provider must return exactly what the Bernoulli-exponential "
            "provider decided for a negative exponent");
    require(exponential.call_count == 1,
            "a negative exponent must consult the Bernoulli-exponential "
            "provider exactly once");
    require(exponential.last_numerator == z(-2116),
            "the exact log-numerator handed to the Bernoulli-exponential "
            "provider must match the hand-derived value");
    require(exponential.last_denominator == z(3872),
            "the exact log-denominator handed to the Bernoulli-exponential "
            "provider must match the hand-derived value");
}

void test_rejection_response_stage_uses_phi2_and_matching_k_squared() {
    // Same hand-derivation as the negative-exponent test above, but for
    // RSignRejectionStage::response_vector with a different phi (phi2)
    // and a K_squared matching the response stage's 3*B^2*m*d*r shape
    // (here just a representative value, 12, to keep the arithmetic
    // checkable by hand): phi=phi2=22/1, K_squared=12.
    // exponent_numerator = -(24*22+1)*12 + 0 = -529*12 = -6348.
    // exponent_denominator = 2*22^2*12 = 11616.
    RecordingBernoulliExponentialProvider exponential(false);
    ZeroByteSource random;
    Section6BatchRejectionProvider provider(exponential);

    const PositiveRational phi2(z(22), z(1));
    const std::vector<NTL::ZZ> values{z(0), z(0), z(0)};
    const std::vector<NTL::ZZ> center{z(0), z(0), z(0)};
    const auto parameters = make_rejection_parameters(
        RSignRejectionStage::response_vector, phi2, z(12));

    const bool result = provider.accept(values, center, parameters, random);
    require(result == false,
            "the response stage must also return exactly what the "
            "Bernoulli-exponential provider decided");
    require(exponential.last_numerator == z(-6348),
            "the response stage's exponent numerator must match the "
            "hand-derived value (using phi2, not phi1)");
    require(exponential.last_denominator == z(11616),
            "the response stage's exponent denominator must match the "
            "hand-derived value");
}

void test_rejection_rejects_mismatched_lengths() {
    RecordingBernoulliExponentialProvider exponential(true);
    Section6BatchRejectionProvider provider(exponential);
    ZeroByteSource random;
    const std::vector<NTL::ZZ> values{z(1), z(1)};
    const std::vector<NTL::ZZ> center{z(1)};
    const auto parameters = make_rejection_parameters(
        RSignRejectionStage::f_vector, PositiveRational(z(22), z(1)), z(10));

    bool threw = false;
    try {
        (void)provider.accept(values, center, parameters, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "mismatched values/center lengths must be rejected safely");
    require(exponential.call_count == 0,
            "an invalid batch must be rejected before ever consulting the "
            "Bernoulli-exponential provider");
}

void test_rejection_rejects_center_exceeding_k_squared() {
    RecordingBernoulliExponentialProvider exponential(true);
    Section6BatchRejectionProvider provider(exponential);
    ZeroByteSource random;
    const std::vector<NTL::ZZ> values{z(1)};
    const std::vector<NTL::ZZ> center{z(100)};  // ||center||^2 = 10000
    const auto parameters = make_rejection_parameters(
        RSignRejectionStage::f_vector, PositiveRational(z(22), z(1)),
        z(1));  // K^2 = 1

    bool threw = false;
    try {
        (void)provider.accept(values, center, parameters, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw,
            "a center exceeding its own K^2 bound must be rejected as an "
            "invalid (inconsistent) batch, not silently accepted/rejected");
}

void test_rejection_rejects_negative_k_squared() {
    // PositiveRational's own constructor already forbids a non-positive
    // phi, so the only remaining malformed-input case reachable through
    // accept() itself is a negative K_squared.
    RecordingBernoulliExponentialProvider exponential(true);
    Section6BatchRejectionProvider provider(exponential);
    ZeroByteSource random;
    const std::vector<NTL::ZZ> values{z(0)};
    const std::vector<NTL::ZZ> center{z(0)};
    const auto parameters = make_rejection_parameters(
        RSignRejectionStage::f_vector, PositiveRational(z(1), z(1)), z(-1));

    bool threw = false;
    try {
        (void)provider.accept(values, center, parameters, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "a negative K^2 must be rejected as invalid");
}

void test_rejection_propagates_rng_failure() {
    ExactBernoulliExponentialProvider exponential;
    FailingRandomSource failing_random;
    Section6BatchRejectionProvider provider(exponential);

    const PositiveRational phi(z(22), z(1));
    const std::vector<NTL::ZZ> values{z(0), z(0)};
    const std::vector<NTL::ZZ> center{z(0), z(0)};
    const auto parameters =
        make_rejection_parameters(RSignRejectionStage::f_vector, phi, z(4));

    bool propagated = false;
    try {
        (void)provider.accept(values, center, parameters, failing_random);
    } catch (const std::runtime_error& error) {
        propagated = std::string(error.what()) == "simulated entropy failure";
    }
    require(propagated,
            "an entropy-source failure inside the exact "
            "Bernoulli-exponential provider must propagate to the caller "
            "unmodified when the decision is randomized (negative "
            "exponent)");
}

// --- DiagnosticOnlyGaussianScaleProfile / Section6GaussianProviderBundle ---

void test_scale_profile_dimensions_and_growth_with_repetitions() {
    ZeroByteSource random;
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters = make_proof_parameters();
    DiagnosticOnlyGaussianScaleProfile profile;

    const auto scale_r2 = profile.scale_squared(
        Protocol2GaussianSampleKind::binary_mask, 0, 2, key, proof_parameters);
    const auto scale_r4 = profile.scale_squared(
        Protocol2GaussianSampleKind::binary_mask, 0, 4, key, proof_parameters);

    // phi1=22, k=2: numerator = 22^2*2*r = 968*r, denominator = 1.
    require(scale_r2.numerator == z(968 * 2) && scale_r2.denominator == z(1),
            "binary_mask scale must match phi1^2*k*r exactly at r=2");
    require(scale_r4.numerator == z(968 * 4) && scale_r4.denominator == z(1),
            "binary_mask scale must match phi1^2*k*r exactly at r=4");
    require(scale_r4.numerator == 2 * scale_r2.numerator,
            "the scale must grow linearly with repetitions, as expected for "
            "r independent repeated draws");
}

void test_scale_profile_rejects_zero_repetitions() {
    ZeroByteSource random;
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters = make_proof_parameters();
    DiagnosticOnlyGaussianScaleProfile profile;

    bool threw = false;
    try {
        (void)profile.scale_squared(Protocol2GaussianSampleKind::rho, 0, 0,
                                   key, proof_parameters);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "zero repetitions must be rejected as invalid");
}

void test_gaussian_bundle_samples_successfully() {
    // ExactBernoulliPiExponentialProvider's interval-refinement algorithm
    // needs genuinely random bits to terminate promptly; the deterministic
    // ZeroByteSource used elsewhere in this file (fine for the rejection
    // provider's pure-arithmetic tests, and for CKeygen's simple uniform
    // sampling) is pathological input for it and was observed to hang
    // during Phase E development. Use a real OS-backed RandomSource for
    // any call that actually exercises the exact D_s/Bernoulli-pi chain.
    SystemRandomSource setup_random;
    CommitmentKey key = make_key(setup_random);
    Protocol2Parameters proof_parameters = make_proof_parameters();
    DiagnosticOnlyGaussianScaleProfile profile;
    // proposal_center chosen ~= sqrt(s_squared) for this specific
    // (response_mask, k=2, r=2) query (s_squared = 83248, sqrt ~= 288.5);
    // see Section6GaussianProviderBundle's constructor comment for why
    // this is required, not optional, for acceptable performance.
    Section6GaussianProviderBundle bundle(profile, z(289), z(1));

    require(bundle.provider().supports_section6_distributions() == true,
            "the bundled provider must advertise Section 6 support");

    SystemRandomSource sampling_random;
    const NTL::ZZ sample = bundle.provider().sample_coefficient(
        Protocol2GaussianSampleKind::response_mask, 0, 2, key,
        proof_parameters, sampling_random);
    // No assertion on the sampled value itself (it is drawn from a
    // diagnostic, not paper-validated, distribution); this test only
    // establishes that the exact D_s sampler chain runs to completion and
    // returns an integer without throwing.
    (void)sample;
}

void test_gaussian_bundle_propagates_rng_failure() {
    FailingRandomSource failing_random;
    ZeroByteSource setup_random;
    CommitmentKey key = make_key(setup_random);
    Protocol2Parameters proof_parameters = make_proof_parameters();
    DiagnosticOnlyGaussianScaleProfile profile;
    // FailingRandomSource throws on its very first fill_bytes call, before
    // any proposal/rejection loop can run even once, so the proposal
    // center's efficiency does not matter for this particular test -- any
    // positive rational is fine here.
    Section6GaussianProviderBundle bundle(profile, z(1), z(1));

    bool propagated = false;
    try {
        (void)bundle.provider().sample_coefficient(
            Protocol2GaussianSampleKind::binary_mask, 0, 2, key,
            proof_parameters, failing_random);
    } catch (const std::runtime_error& error) {
        propagated = std::string(error.what()) == "simulated entropy failure";
    }
    require(propagated,
            "an entropy-source failure deep inside the exact D_s sampler "
            "chain must propagate to the caller unmodified, not be "
            "swallowed or silently retried forever");
}

// --- SigmaProtocol2RSignGaussianProvider (production) ---
//
// Verified formulas (see production_gaussian_provider.hpp):
//   binary_mask:   sigma^2 = phi1^2 * k * r
//   response_mask: sigma^2 = 3 * phi2^2 * B^2 * m * d * r
//   rho:           sigma^2 = 3 * phi2^2 * B^2 * m * d * r / k
// cross-checked against BeginProtocol2Proof's own r=1 formulas
// (protocol2_proof.cpp:578-597): phi1_num=phi1^2*k, phi2_num=
// phi2^2*B^2*3*m*d, rho denominator additionally multiplied by k.

class RecordingDiscreteGaussianProvider final : public DiscreteGaussianProvider {
public:
    NTL::ZZ sample_coefficient(const NTL::ZZ& sigma_squared_numerator,
                              const NTL::ZZ& sigma_squared_denominator,
                              RandomSource&) override {
        ++call_count;
        last_numerator = sigma_squared_numerator;
        last_denominator = sigma_squared_denominator;
        return z(0);
    }

    std::size_t call_count = 0;
    NTL::ZZ last_numerator;
    NTL::ZZ last_denominator;
};

void test_sigma_provider_advertises_section6_support() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    require(provider.supports_section6_distributions() == true,
            "the sigma-based production provider must advertise Section 6 "
            "support");
}

void test_sigma_provider_binary_mask_exact_variance() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    // phi1=22/1, k=2, r=2 -> sigma^2 = 22^2*2*2 = 1936, denominator 1.
    Protocol2Parameters proof_parameters = make_proof_parameters();

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::binary_mask,
                                      0, 2, key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(1936) &&
                sigma_sampler.last_denominator == z(1),
            "binary_mask sigma^2 must equal phi1^2*k*r exactly");
}

void test_sigma_provider_response_mask_exact_variance_includes_factor_of_3() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);  // m=1, degree=86, B=1
    // phi2=22/1, B=1, m=1, d=86, r=2 ->
    // sigma^2 = 3*22^2*1*1*86*2 = 3*484*172 = 249744, denominator 1.
    Protocol2Parameters proof_parameters = make_proof_parameters();

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::response_mask,
                                      0, 2, key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(249744) &&
                sigma_sampler.last_denominator == z(1),
            "response_mask sigma^2 must equal 3*phi2^2*B^2*m*d*r exactly, "
            "including the factor of 3 the diagnostic profile omitted");
}

void test_sigma_provider_rho_exact_variance() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    // Same numerator as response_mask (249744), denominator additionally
    // multiplied by k=2 -> denominator 2.
    Protocol2Parameters proof_parameters = make_proof_parameters();

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::rho, 0, 2,
                                      key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(249744) &&
                sigma_sampler.last_denominator == z(2),
            "rho sigma^2 must equal 3*phi2^2*B^2*m*d*r/k exactly");
}

void test_sigma_provider_dispatches_distinct_formula_per_kind() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters = make_proof_parameters();

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::binary_mask,
                                      0, 2, key, proof_parameters, random);
    const NTL::ZZ binary_numerator = sigma_sampler.last_numerator;
    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::response_mask,
                                      0, 2, key, proof_parameters, random);
    const NTL::ZZ response_numerator = sigma_sampler.last_numerator;
    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::rho, 0, 2,
                                      key, proof_parameters, random);
    const NTL::ZZ rho_numerator = sigma_sampler.last_numerator;
    const NTL::ZZ rho_denominator = sigma_sampler.last_denominator;

    require(sigma_sampler.call_count == 3,
            "each distinct kind must reach the sampler exactly once per call");
    require(binary_numerator != response_numerator,
            "binary_mask and response_mask must use different formulas");
    require(response_numerator == rho_numerator && rho_denominator == z(2),
            "response_mask and rho share the same numerator but rho divides "
            "by k in the denominator, not the numerator");
}

void test_sigma_provider_r_equals_1_matches_nonrepeated_formulas() {
    // Cross-check against BeginProtocol2Proof's own already-shipping r=1
    // lines (protocol2_proof.cpp:578-586):
    //   phi1_num = phi1^2*k, phi1_den = phi1^2 denominator
    //   phi2_num = phi2^2*B^2*3*m*d, phi2_den = phi2^2 denominator
    //   rho: phi2_num / (phi2_den*k)
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);  // m=1, degree=86, B=1
    Protocol2Parameters proof_parameters = make_proof_parameters();  // phi1=phi2=22/1, k=2

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::binary_mask,
                                      0, 1, key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(22 * 22 * 2) &&
                sigma_sampler.last_denominator == z(1),
            "at r=1, binary_mask must match BeginProtocol2Proof's phi1_num="
            "phi1^2*k exactly");

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::response_mask,
                                      0, 1, key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(22 * 22 * 1 * 1 * 3 * 1 * 86) &&
                sigma_sampler.last_denominator == z(1),
            "at r=1, response_mask must match BeginProtocol2Proof's "
            "phi2_num=phi2^2*B^2*3*m*d exactly");

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::rho, 0, 1,
                                      key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(22 * 22 * 1 * 1 * 3 * 1 * 86) &&
                sigma_sampler.last_denominator == z(2),
            "at r=1, rho must match BeginProtocol2Proof's phi2_num/"
            "(phi2_den*k) exactly");
}

void test_sigma_provider_multiple_repetitions_scale_linearly() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters = make_proof_parameters();

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::binary_mask,
                                      0, 3, key, proof_parameters, random);
    const NTL::ZZ r3 = sigma_sampler.last_numerator;
    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::binary_mask,
                                      0, 7, key, proof_parameters, random);
    const NTL::ZZ r7 = sigma_sampler.last_numerator;

    require(r3 == z(22 * 22 * 2 * 3), "r=3 must give phi1^2*k*3 exactly");
    require(r7 == z(22 * 22 * 2 * 7), "r=7 must give phi1^2*k*7 exactly");
    require(7 * r3 == 3 * r7,
            "sigma^2 must scale exactly linearly with repetitions");
}

void test_sigma_provider_non_integral_phi_is_exact() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    // phi1 = 7/2 (non-integral rational), k=2, r=2 ->
    // sigma^2 = (7/2)^2 * 2 * 2 = 49/4 * 4 = 49/1, but the provider must
    // not reduce the fraction itself -- it should pass numerator=7*7*2*2=196,
    // denominator=2*2=4 (reduction, if any, is the sampler's business).
    Protocol2Parameters proof_parameters{
        2, 2, PositiveRational(z(7), z(2)), PositiveRational(z(22), z(1))};

    (void)provider.sample_coefficient(Protocol2GaussianSampleKind::binary_mask,
                                      0, 2, key, proof_parameters, random);
    require(sigma_sampler.last_numerator == z(7 * 7 * 2 * 2) &&
                sigma_sampler.last_denominator == z(2 * 2),
            "a non-integral rational phi1 must be carried through exactly "
            "as numerator/denominator, not rounded or reduced by this "
            "provider");
}

void test_sigma_provider_rejects_zero_repetitions() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters = make_proof_parameters();

    bool threw = false;
    try {
        (void)provider.sample_coefficient(
            Protocol2GaussianSampleKind::binary_mask, 0, 0, key,
            proof_parameters, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "zero repetitions must be rejected");
    require(sigma_sampler.call_count == 0,
            "an invalid call must never reach the sampler");
}

void test_sigma_provider_rejects_run_index_out_of_range() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters = make_proof_parameters();

    bool threw = false;
    try {
        (void)provider.sample_coefficient(
            Protocol2GaussianSampleKind::binary_mask, 2, 2, key,
            proof_parameters, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "run_index >= repetitions must be rejected");
}

void test_sigma_provider_rejects_zero_k_for_rho() {
    RecordingDiscreteGaussianProvider sigma_sampler;
    ZeroByteSource random;
    SigmaProtocol2RSignGaussianProvider provider(sigma_sampler);
    CommitmentKey key = make_key(random);
    Protocol2Parameters proof_parameters{
        0, 2, PositiveRational(z(22), z(1)), PositiveRational(z(22), z(1))};

    bool threw = false;
    try {
        (void)provider.sample_coefficient(Protocol2GaussianSampleKind::rho, 0,
                                         2, key, proof_parameters, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "k=0 must be rejected for the rho kind");
}

void test_sigma_bundle_samples_successfully() {
    SigmaSection6GaussianProviderBundle bundle;
    require(bundle.provider().supports_section6_distributions() == true,
            "the sigma production bundle must advertise Section 6 support");

    SystemRandomSource random;
    ZeroByteSource setup_random;
    CommitmentKey key = make_key(setup_random);
    Protocol2Parameters proof_parameters = make_proof_parameters();

    const NTL::ZZ sample = bundle.provider().sample_coefficient(
        Protocol2GaussianSampleKind::binary_mask, 0, 2, key, proof_parameters,
        random);
    // No assertion on the value itself; this establishes the exact
    // ExactDiscreteGaussianProvider sampling chain runs to completion
    // (no pi, no irrational-conversion issue, since this path never
    // touches D_s at all).
    (void)sample;
}

void test_sigma_bundle_propagates_rng_failure() {
    SigmaSection6GaussianProviderBundle bundle;
    FailingRandomSource failing_random;
    ZeroByteSource setup_random;
    CommitmentKey key = make_key(setup_random);
    Protocol2Parameters proof_parameters = make_proof_parameters();

    bool propagated = false;
    try {
        (void)bundle.provider().sample_coefficient(
            Protocol2GaussianSampleKind::response_mask, 0, 2, key,
            proof_parameters, failing_random);
    } catch (const std::runtime_error& error) {
        propagated = std::string(error.what()) == "simulated entropy failure";
    }
    require(propagated,
            "an entropy-source failure inside the exact sigma sampler chain "
            "must propagate to the caller unmodified");
}

}  // namespace

int main() {
    const std::pair<const char*, void (*)()> cases[] = {
        {"rejection_advertises_section6_support",
         test_rejection_advertises_section6_support},
        {"rejection_positive_exponent_accepts_deterministically",
         test_rejection_positive_exponent_accepts_deterministically},
        {"rejection_zero_exponent_accepts_deterministically",
         test_rejection_zero_exponent_accepts_deterministically},
        {"rejection_negative_exponent_uses_exact_probability",
         test_rejection_negative_exponent_uses_exact_probability},
        {"rejection_response_stage_uses_phi2_and_matching_k_squared",
         test_rejection_response_stage_uses_phi2_and_matching_k_squared},
        {"rejection_rejects_mismatched_lengths",
         test_rejection_rejects_mismatched_lengths},
        {"rejection_rejects_center_exceeding_k_squared",
         test_rejection_rejects_center_exceeding_k_squared},
        {"rejection_rejects_negative_k_squared",
         test_rejection_rejects_negative_k_squared},
        {"rejection_propagates_rng_failure",
         test_rejection_propagates_rng_failure},
        {"scale_profile_dimensions_and_growth_with_repetitions",
         test_scale_profile_dimensions_and_growth_with_repetitions},
        {"scale_profile_rejects_zero_repetitions",
         test_scale_profile_rejects_zero_repetitions},
        {"gaussian_bundle_samples_successfully",
         test_gaussian_bundle_samples_successfully},
        {"gaussian_bundle_propagates_rng_failure",
         test_gaussian_bundle_propagates_rng_failure},
        {"sigma_provider_advertises_section6_support",
         test_sigma_provider_advertises_section6_support},
        {"sigma_provider_binary_mask_exact_variance",
         test_sigma_provider_binary_mask_exact_variance},
        {"sigma_provider_response_mask_exact_variance_includes_factor_of_3",
         test_sigma_provider_response_mask_exact_variance_includes_factor_of_3},
        {"sigma_provider_rho_exact_variance",
         test_sigma_provider_rho_exact_variance},
        {"sigma_provider_dispatches_distinct_formula_per_kind",
         test_sigma_provider_dispatches_distinct_formula_per_kind},
        {"sigma_provider_r_equals_1_matches_nonrepeated_formulas",
         test_sigma_provider_r_equals_1_matches_nonrepeated_formulas},
        {"sigma_provider_multiple_repetitions_scale_linearly",
         test_sigma_provider_multiple_repetitions_scale_linearly},
        {"sigma_provider_non_integral_phi_is_exact",
         test_sigma_provider_non_integral_phi_is_exact},
        {"sigma_provider_rejects_zero_repetitions",
         test_sigma_provider_rejects_zero_repetitions},
        {"sigma_provider_rejects_run_index_out_of_range",
         test_sigma_provider_rejects_run_index_out_of_range},
        {"sigma_provider_rejects_zero_k_for_rho",
         test_sigma_provider_rejects_zero_k_for_rho},
        {"sigma_bundle_samples_successfully",
         test_sigma_bundle_samples_successfully},
        {"sigma_bundle_propagates_rng_failure",
         test_sigma_bundle_propagates_rng_failure},
    };

    int failures = 0;
    for (const auto& [name, fn] : cases) {
        try {
            fn();
            std::cout << "PASS: " << name << "\n";
        } catch (const std::exception& error) {
            std::cout << "FAIL: " << name << " (" << error.what() << ")\n";
            ++failures;
        }
    }
    return failures == 0 ? 0 : 1;
}
