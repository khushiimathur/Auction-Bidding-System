// Phase B tests: H' (lattice_lrs::lrs::HashOvkToPublicKeySpace) and the
// public-key masking transformation it drives (MaskPublicKey/UnmaskPublicKey),
// per WCM Section 4. See public_key_mask.hpp for the exact equations and the
// implementation choices flagged as not mandated by the paper text.
//
// These are correctness/determinism/round-trip checks only. They do not,
// and cannot, establish that H' behaves as a random oracle, that the masking
// transformation preserves anonymity, or any other cryptographic security
// property claimed by the WCM paper's proofs.

#include "lattice_lrs/lrs/public_key_mask.hpp"

#include <NTL/ZZ.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::ots::DilithiumPublicKey;
using lattice_lrs::ots::kDilithiumPublicKeyBytes;
using lattice_lrs::sampling::PolynomialVector;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

Parameters test_parameters(std::size_t n = 3, std::size_t degree = 8,
                          long q_value = 97) {
    Parameters parameters{n,
                          n + 2,  // m >= n
                          2,      // v
                          degree,
                          NTL::to_ZZ(q_value),
                          NTL::to_ZZ(1),
                          SquaredNormBound(NTL::to_ZZ(1), NTL::to_ZZ(1))};
    parameters.validate();
    return parameters;
}

DilithiumPublicKey ovk_from_byte(std::uint8_t fill_byte) {
    DilithiumPublicKey key;
    key.bytes.fill(fill_byte);
    return key;
}

DilithiumPublicKey ovk_with_marker(std::uint8_t marker) {
    DilithiumPublicKey key = ovk_from_byte(0x00);
    key.bytes[0] = marker;
    key.bytes[kDilithiumPublicKeyBytes - 1] = marker;
    return key;
}

PolynomialVector zero_public_key(const Parameters& parameters) {
    const Polynomial zero(parameters.degree, parameters.q);
    return PolynomialVector(parameters.n, zero);
}

bool vectors_equal(const PolynomialVector& left, const PolynomialVector& right) {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (left[i] != right[i]) return false;
    }
    return true;
}

void test_h_prime_is_deterministic() {
    const Parameters parameters = test_parameters();
    const DilithiumPublicKey ovk = ovk_with_marker(0x42);

    const PolynomialVector first =
        lattice_lrs::lrs::HashOvkToPublicKeySpace(parameters, ovk);
    const PolynomialVector second =
        lattice_lrs::lrs::HashOvkToPublicKeySpace(parameters, ovk);

    require(vectors_equal(first, second),
            "H'(ovk) must be deterministic for the same (parameters, ovk)");
}

void test_h_prime_dimensions_and_ranges() {
    const Parameters parameters = test_parameters();
    const DilithiumPublicKey ovk = ovk_with_marker(0x07);

    const PolynomialVector output =
        lattice_lrs::lrs::HashOvkToPublicKeySpace(parameters, ovk);

    require(output.size() == parameters.n,
            "H'(ovk) must produce exactly n polynomials");
    for (const Polynomial& polynomial : output) {
        require(polynomial.degree() == parameters.degree,
                "H'(ovk) polynomial degree must match parameters.degree");
        require(polynomial.modulus() == parameters.q,
                "H'(ovk) polynomial modulus must match parameters.q");
        for (std::size_t i = 0; i < polynomial.degree(); ++i) {
            const NTL::ZZ& coefficient = polynomial.coefficient(i);
            require(coefficient >= 0 && coefficient < parameters.q,
                    "H'(ovk) coefficients must lie in the canonical range "
                    "[0, q)");
        }
    }
}

// Statistical spot-check only (explicitly not a proof of random-oracle
// behaviour, pseudorandomness, or collision resistance): a handful of
// distinct OTS public keys must not collide on H'(ovk), and must not all
// agree coefficient-by-coefficient.
void test_distinct_ovks_give_distinct_outputs() {
    const Parameters parameters = test_parameters();
    std::vector<PolynomialVector> outputs;
    for (int marker = 0; marker < 8; ++marker) {
        outputs.push_back(lattice_lrs::lrs::HashOvkToPublicKeySpace(
            parameters, ovk_with_marker(static_cast<std::uint8_t>(marker))));
    }
    for (std::size_t i = 0; i < outputs.size(); ++i) {
        for (std::size_t j = i + 1; j < outputs.size(); ++j) {
            require(!vectors_equal(outputs[i], outputs[j]),
                    "distinct OTS public keys unexpectedly produced an "
                    "identical H'(ovk) in this small statistical sample");
        }
    }
}

void test_mask_then_unmask_recovers_original_key() {
    const Parameters parameters = test_parameters();
    const DilithiumPublicKey ovk = ovk_with_marker(0x99);
    const PolynomialVector base_key = zero_public_key(parameters);

    const PolynomialVector masked =
        lattice_lrs::lrs::MaskPublicKey(parameters, base_key, ovk);
    const PolynomialVector recovered =
        lattice_lrs::lrs::UnmaskPublicKey(parameters, masked, ovk);

    require(vectors_equal(recovered, base_key),
            "UnmaskPublicKey(Mask(pk, ovk), ovk) must recover pk exactly");
    require(!vectors_equal(masked, base_key),
            "masking with a nonzero H'(ovk) must change the public key "
            "(the zero-fixture would only fail to change if H'(ovk) were "
            "the zero vector, astronomically unlikely for SHAKE256 output)");
}

void test_mask_preserves_original_key_object() {
    const Parameters parameters = test_parameters();
    const DilithiumPublicKey ovk = ovk_with_marker(0x11);
    const PolynomialVector base_key = zero_public_key(parameters);
    const PolynomialVector base_key_copy = base_key;

    (void)lattice_lrs::lrs::MaskPublicKey(parameters, base_key, ovk);

    require(vectors_equal(base_key, base_key_copy),
            "MaskPublicKey must not mutate the caller's base public key");
}

void test_changing_ovk_changes_masked_key() {
    const Parameters parameters = test_parameters();
    const PolynomialVector base_key = zero_public_key(parameters);

    const PolynomialVector masked_a = lattice_lrs::lrs::MaskPublicKey(
        parameters, base_key, ovk_with_marker(0x01));
    const PolynomialVector masked_b = lattice_lrs::lrs::MaskPublicKey(
        parameters, base_key, ovk_with_marker(0x02));

    require(!vectors_equal(masked_a, masked_b),
            "masking the same key under two different OTS public keys must "
            "produce different results");
}

void test_mismatched_base_key_length_rejected() {
    const Parameters parameters = test_parameters(/*n=*/3);
    const Parameters wrong_n_parameters = test_parameters(/*n=*/4);
    const PolynomialVector wrong_length_key = zero_public_key(wrong_n_parameters);
    const DilithiumPublicKey ovk = ovk_with_marker(0x05);

    bool threw = false;
    try {
        (void)lattice_lrs::lrs::MaskPublicKey(parameters, wrong_length_key, ovk);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw,
            "MaskPublicKey must reject a base key whose length does not "
            "match parameters.n");
}

void test_mismatched_degree_rejected() {
    const Parameters parameters = test_parameters(/*n=*/3, /*degree=*/8);
    const Parameters wrong_degree_parameters =
        test_parameters(/*n=*/3, /*degree=*/16);
    const PolynomialVector wrong_degree_key =
        zero_public_key(wrong_degree_parameters);
    const DilithiumPublicKey ovk = ovk_with_marker(0x06);

    bool threw = false;
    try {
        (void)lattice_lrs::lrs::UnmaskPublicKey(parameters, wrong_degree_key,
                                                ovk);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw,
            "UnmaskPublicKey must reject a masked key whose polynomial "
            "degree does not match parameters.degree");
}

void test_invalid_commitment_parameters_rejected() {
    Parameters invalid = test_parameters();
    invalid.q = NTL::to_ZZ(1);  // violates q > 1
    const DilithiumPublicKey ovk = ovk_with_marker(0x08);

    bool threw = false;
    try {
        (void)lattice_lrs::lrs::HashOvkToPublicKeySpace(invalid, ovk);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "H' must reject commitment parameters that fail validate()");
}

}  // namespace

int main() {
    const std::pair<const char*, void (*)()> cases[] = {
        {"h_prime_is_deterministic", test_h_prime_is_deterministic},
        {"h_prime_dimensions_and_ranges", test_h_prime_dimensions_and_ranges},
        {"distinct_ovks_give_distinct_outputs",
         test_distinct_ovks_give_distinct_outputs},
        {"mask_then_unmask_recovers_original_key",
         test_mask_then_unmask_recovers_original_key},
        {"mask_preserves_original_key_object",
         test_mask_preserves_original_key_object},
        {"changing_ovk_changes_masked_key", test_changing_ovk_changes_masked_key},
        {"mismatched_base_key_length_rejected",
         test_mismatched_base_key_length_rejected},
        {"mismatched_degree_rejected", test_mismatched_degree_rejected},
        {"invalid_commitment_parameters_rejected",
         test_invalid_commitment_parameters_rejected},
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
