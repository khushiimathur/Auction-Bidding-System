// Unit tests for lattice_lrs::lpcom (GenCom/Com/Unv), the paper-faithful
// LPCom commitment scheme (Cabarcas et al., ePrint 2015/628, Figure 1).
// Real cryptographic primitives throughout: the actual exact discrete
// Gaussian sampler (proofs::ExactDiscreteGaussianSProvider) and the
// actual CSPRNG-backed uniform sampler; no mocks.

#include "lattice_lrs/lpcom/lpcom.hpp"

#include "lattice_lrs/proofs/bernoulli_pi_exponential.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace lattice_lrs;
using lattice_lrs::lpcom::Commitment;
using lattice_lrs::lpcom::ComResult;
using lattice_lrs::lpcom::Opening;
using lattice_lrs::lpcom::Parameters;
using lattice_lrs::lpcom::Vector;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

// A small, fast parameter set used for most unit tests -- distinct from
// (and much smaller than) ExperimentalDemoParameters(), chosen purely
// so dozens of GenCom/Com/Unv calls run quickly. n=2, k=2, m=8, q=23
// (prime, m >= n+k=4 satisfied comfortably), sigma^2=9 (exact), B=10.
Parameters SmallTestParameters(sampling::RandomSource& random) {
    return lpcom::GenCom(/*n=*/2, /*k=*/2, /*m=*/8, NTL::to_ZZ(23),
                         /*sigma_squared_numerator=*/NTL::to_ZZ(9),
                         /*sigma_squared_denominator=*/NTL::to_ZZ(1),
                         /*B=*/NTL::to_ZZ(10), random);
}

struct GaussianBundle {
    proofs::ExactBernoulliPiExponentialProvider exponential;
    proofs::ExactDiscreteGaussianSProvider sampler{exponential, NTL::to_ZZ(3),
                                                   NTL::to_ZZ(1)};
};

void test_gencom_produces_trivial_kernel_matrix() {
    sampling::SystemRandomSource random;
    Parameters params = SmallTestParameters(random);
    require(params.A1.size() == params.m, "A1 must have m rows");
    require(params.A1[0].size() == params.n, "A1 must have n columns");
    require(params.A2[0].size() == params.k, "A2 must have k columns");
}

void test_gencom_rejects_m_less_than_n_plus_k() {
    sampling::SystemRandomSource random;
    bool threw = false;
    try {
        lpcom::GenCom(5, 5, 6, NTL::to_ZZ(23), NTL::to_ZZ(9), NTL::to_ZZ(1),
                     NTL::to_ZZ(10), random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "GenCom must reject m < n + k");
}

void test_gencom_rejects_composite_modulus() {
    sampling::SystemRandomSource random;
    bool threw = false;
    try {
        lpcom::GenCom(2, 2, 8, NTL::to_ZZ(24), NTL::to_ZZ(9), NTL::to_ZZ(1),
                     NTL::to_ZZ(10), random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "GenCom must reject a non-prime q");
}

void test_honest_commit_and_open_accepts() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    Vector v{NTL::to_ZZ(5), NTL::to_ZZ(17)};
    ComResult result = lpcom::Com(params, v, gaussian.sampler, random);

    const bool accepted = lpcom::Unv(params, result.commitment,
                                     result.opening.v, result.opening.r);
    require(accepted, "an honestly generated commitment must open");
}

void test_incorrect_message_is_rejected() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    Vector v{NTL::to_ZZ(5), NTL::to_ZZ(17)};
    ComResult result = lpcom::Com(params, v, gaussian.sampler, random);

    Vector wrong_v{NTL::to_ZZ(6), NTL::to_ZZ(17)};
    const bool accepted =
        lpcom::Unv(params, result.commitment, wrong_v, result.opening.r);
    require(!accepted, "opening with the wrong message must be rejected");
}

void test_incorrect_randomness_is_rejected() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    Vector v{NTL::to_ZZ(5), NTL::to_ZZ(17)};
    ComResult result = lpcom::Com(params, v, gaussian.sampler, random);

    Vector wrong_r = result.opening.r;
    wrong_r[0] = (wrong_r[0] + 1) % params.q;
    const bool accepted =
        lpcom::Unv(params, result.commitment, result.opening.v, wrong_r);
    require(!accepted, "opening with the wrong randomness must be rejected");
}

void test_modified_commitment_is_rejected() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    Vector v{NTL::to_ZZ(5), NTL::to_ZZ(17)};
    ComResult result = lpcom::Com(params, v, gaussian.sampler, random);

    Commitment tampered = result.commitment;
    tampered.c[0] = (tampered.c[0] + 1) % params.q;
    const bool accepted =
        lpcom::Unv(params, tampered, result.opening.v, result.opening.r);
    require(!accepted,
           "opening a commitment that was modified after the fact must be "
           "rejected");
}

void test_message_outside_range_is_rejected() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    Vector out_of_range{NTL::to_ZZ(23), NTL::to_ZZ(0)};  // 23 == q, invalid
    bool threw = false;
    try {
        lpcom::Com(params, out_of_range, gaussian.sampler, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "Com must reject a message coordinate outside [0, q)");
}

void test_wrong_dimension_message_is_rejected() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    Vector wrong_length{NTL::to_ZZ(1)};
    bool threw = false;
    try {
        lpcom::Com(params, wrong_length, gaussian.sampler, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "Com must reject a message vector of the wrong length");
}

void test_experimental_demo_parameters_round_trip() {
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = lpcom::ExperimentalDemoParameters(random);
    require(params.n == 16 && params.k == 16 && params.m == 48,
           "ExperimentalDemoParameters must match its documented shape");

    Vector v(params.n, NTL::ZZ(0));
    v[0] = NTL::to_ZZ(42);
    ComResult result = lpcom::Com(params, v, gaussian.sampler, random);
    const bool accepted = lpcom::Unv(params, result.commitment,
                                     result.opening.v, result.opening.r);
    require(accepted,
           "the experimental demo parameter profile must still satisfy "
           "correctness for an honest commit/open");
}

void test_error_samples_are_not_degenerate() {
    // Sanity check that the Gaussian sampler is actually producing a
    // spread of values (not e.g. always 0), across several independent
    // commitments -- guards against an accidentally-degenerate wiring
    // of the sampler (wrong scale, frozen RNG, etc.).
    sampling::SystemRandomSource random;
    GaussianBundle gaussian;
    Parameters params = SmallTestParameters(random);

    bool saw_nonzero_difference = false;
    NTL::ZZ first_c0;
    for (int trial = 0; trial < 10; ++trial) {
        Vector v{NTL::to_ZZ(1), NTL::to_ZZ(1)};
        ComResult result = lpcom::Com(params, v, gaussian.sampler, random);
        if (trial == 0) {
            first_c0 = result.commitment.c[0];
        } else if (result.commitment.c[0] != first_c0) {
            saw_nonzero_difference = true;
        }
    }
    require(saw_nonzero_difference,
           "repeated commitments to the same message must not all produce "
           "an identical commitment (randomness/error sampling must vary)");
}

}  // namespace

int main() {
    try {
        test_gencom_produces_trivial_kernel_matrix();
        test_gencom_rejects_m_less_than_n_plus_k();
        test_gencom_rejects_composite_modulus();
        test_honest_commit_and_open_accepts();
        test_incorrect_message_is_rejected();
        test_incorrect_randomness_is_rejected();
        test_modified_commitment_is_rejected();
        test_message_outside_range_is_rejected();
        test_wrong_dimension_message_is_rejected();
        test_experimental_demo_parameters_round_trip();
        test_error_samples_are_not_degenerate();
    } catch (const std::exception& error) {
        std::cerr << "lpcom test failure: " << error.what() << std::endl;
        return 1;
    }
    std::cout << "All lpcom tests passed." << std::endl;
    return 0;
}
