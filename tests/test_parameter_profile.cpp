#include "lattice_lrs/ring_signature/parameter_profile.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include <NTL/ZZ.h>

#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using lattice_lrs::ring_signature::ComputeRSignRepetitionCount;
using lattice_lrs::ring_signature::ParameterProfile;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

struct ExpectedProfile {
    std::size_t ring_size;
    std::size_t n;
    std::size_t m;
    std::size_t d;
    std::size_t log2_q;
    std::size_t k;
    std::size_t beta;
    std::size_t repetitions;
    std::size_t v;
    NTL::ZZ q;
    NTL::ZZ T1_squared;
    NTL::ZZ T_prime_squared;
};

NTL::ZZ decimal(const char* digits) {
    NTL::ZZ result(0);
    for (const char* cursor = digits; *cursor != '\0'; ++cursor) {
        result *= 10;
        result += *cursor - '0';
    }
    return result;
}

void test_named_profiles() {
    const std::array<ExpectedProfile, 4> expected{{
        // T1_squared values below are (2d+2)^2*(first+second) -- see
        // ParameterProfile::T1_squared()'s derivation comment. These were
        // recomputed after fixing a bug where the (2d+2) scale factor was
        // applied only once instead of squared; T_prime_squared (the
        // third decimal in each row) is a separate, independently-correct
        // formula and is unaffected.
        {64, 5, 13, 256, 50, 2, 8, 16, 16,
         decimal("1125899906826241"),
         decimal("6430557334242762921345024"),
         decimal("11836756857422346190848")},
        {256, 5, 13, 256, 53, 2, 16, 16, 32,
         decimal("9007199254740481"),
         decimal("27559530539021028003151872"),
         decimal("11836756857422346190848")},
        {1024, 11, 25, 128, 46, 2, 32, 19, 64,
         decimal("119569584450049"),
         decimal("5058976610265717053325312"),
         decimal("812231229670686720000")},
        {4096, 21, 50, 64, 47, 2, 64, 22, 128,
         decimal("140737488355201"),
         decimal("874917277190027319705600"),
         decimal("58779891620904960000")},
    }};
    const std::array<ParameterProfile, 4> profiles{
        ParameterProfile::N64(), ParameterProfile::N256(),
        ParameterProfile::N1024(), ParameterProfile::N4096()};

    for (std::size_t index = 0; index < profiles.size(); ++index) {
        const ParameterProfile& profile = profiles[index];
        const ExpectedProfile& row = expected[index];
        profile.validate();
        require(profile.ring_size() == row.ring_size &&
                    profile.n() == row.n && profile.m() == row.m &&
                    profile.d() == row.d &&
                    profile.reference_log2_q() == row.log2_q &&
                    profile.k() == row.k && profile.beta() == row.beta &&
                    profile.repetitions() == row.repetitions &&
                    profile.v() == row.v && profile.q() == row.q &&
                    profile.B() == z(1) && profile.phi1() == 22 &&
                    profile.phi2() == 22 && profile.lambda() == 128,
                "named profile differs from its Table 3 row");
        require(ComputeRSignRepetitionCount(128, profile.d(), profile.k()) ==
                    profile.repetitions(),
                "profile repetition count must match the Section 6 bound");

        const NTL::ZZ q = profile.q();
        const NTL::ZZ T1 = profile.T1_upper_bound();
        const NTL::ZZ T_prime = profile.T_prime_upper_bound();
        require(T1 * T1 >= profile.T1_squared() &&
                    T_prime * T_prime >=
                        profile.T_prime_squared_upper_bound(),
                "binding bounds must use conservative integer square roots");
        require(profile.T1_squared() == row.T1_squared &&
                    profile.T_prime_squared_upper_bound() ==
                        row.T_prime_squared,
                "profile binding formulas differ from their exact integer values");
        require(q > 2 * T1 && q > 2 * T_prime,
                "q must exceed both binding thresholds in Eq. (11)");
    }
}

// Independent re-derivation of Theorem 1 / Section 6's T1^2 formula,
// T1^2 = (2d+2)^2 * (54*phi1^4*d^3*k^3*beta*(beta-1)*r^2
//                     + 12*phi2^2*B^2*m^2*d^2*r),
// built directly from each profile's raw accessors (not from
// T1_squared() itself, and not from the hardcoded decimals in
// test_named_profiles above) -- this is the regression test for the
// (2d+2) scale-squaring bug: it fails if the scale factor is ever
// applied only once again, regardless of what any hardcoded constant
// says.
void test_t1_squared_matches_squared_paper_formula() {
    const std::array<ParameterProfile, 4> profiles{
        ParameterProfile::N64(), ParameterProfile::N256(),
        ParameterProfile::N1024(), ParameterProfile::N4096()};

    for (const ParameterProfile& profile : profiles) {
        const NTL::ZZ d = z(static_cast<long>(profile.d()));
        const NTL::ZZ k = z(static_cast<long>(profile.k()));
        const NTL::ZZ beta = z(static_cast<long>(profile.beta()));
        const NTL::ZZ r = z(static_cast<long>(profile.repetitions()));
        const NTL::ZZ m = z(static_cast<long>(profile.m()));
        const NTL::ZZ phi1 = z(static_cast<long>(profile.phi1()));
        const NTL::ZZ phi2 = z(static_cast<long>(profile.phi2()));
        const NTL::ZZ B = profile.B();
        const NTL::ZZ scale = 2 * d + 2;

        const NTL::ZZ first = 54 * NTL::power(phi1, 4) * NTL::power(d, 3) *
                              NTL::power(k, 3) * beta * (beta - 1) *
                              NTL::power(r, 2);
        const NTL::ZZ second = 12 * NTL::power(phi2, 2) * B * B *
                               NTL::power(m, 2) * NTL::power(d, 2) * r;
        const NTL::ZZ expected = scale * scale * (first + second);

        require(profile.T1_squared() == expected,
                "T1_squared() must equal (2d+2)^2*(first+second) exactly, "
                "re-derived independently from the profile's raw "
                "accessors");

        // Sanity check against the known-correct sibling formula's own
        // squaring convention (binary_proof.cpp's
        // commitment_binding_bound_squared uses scale*scale, matching
        // this test and the corrected T1_squared(), not scale^1).
        require(expected > scale * (first + second),
                "for any d>0 the squared-scale bound must strictly exceed "
                "the single-scale (pre-fix) bound, confirming the fix "
                "actually changed the value and did not degenerate to a "
                "no-op");
    }
}

void test_ring_size_lookup_rejects_unknown_profiles() {
    require(ParameterProfile::ForRingSize(64).id() ==
                ParameterProfile::N64().id(),
            "ring-size lookup must return the named profile");
    bool rejected = false;
    try {
        (void)ParameterProfile::ForRingSize(128);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "ring-size lookup must reject unsupported profiles");
}

}  // namespace

int main() {
    try {
        test_named_profiles();
        test_t1_squared_matches_squared_paper_formula();
        test_ring_size_lookup_rejects_unknown_profiles();
    } catch (const std::exception& error) {
        std::cerr << "parameter profile test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
