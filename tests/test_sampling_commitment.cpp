#include "lattice_lrs/commitment/commitment.hpp"
#include "lattice_lrs/sampling/sampler.hpp"

#include <NTL/ZZ.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::Commit;
using lattice_lrs::commitment::CommitmentKey;
using lattice_lrs::commitment::Open;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::sampling::PolynomialVector;
using lattice_lrs::sampling::RandomSource;

static_assert(std::is_base_of_v<RandomSource,
                                lattice_lrs::sampling::SystemRandomSource>,
              "SystemRandomSource must preserve the RandomSource interface");

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

// Test-only deterministic byte source. The supplied bytes repeat cyclically.
class CyclingByteSource final : public RandomSource {
public:
    explicit CyclingByteSource(std::vector<std::uint8_t> sequence)
        : sequence_(std::move(sequence)) {
        if (sequence_.empty()) {
            throw std::invalid_argument("test byte sequence must not be empty");
        }
    }

    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        for (std::size_t i = 0; i < length; ++i) {
            output[i] = sequence_[position_++ % sequence_.size()];
        }
    }

private:
    std::vector<std::uint8_t> sequence_;
    std::size_t position_ = 0;
};

class FailingRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t*, std::size_t) override {
        throw std::runtime_error("simulated entropy failure");
    }
};

Parameters baseline_test_parameters(const NTL::ZZ& q = z(15),
                                    const NTL::ZZ& bound_numerator = z(1000000)) {
    return Parameters{5, 13, 16, 256, q, z(1),
                      SquaredNormBound(bound_numerator, z(1))};
}

PolynomialVector zero_vector(std::size_t length, std::size_t degree,
                             const NTL::ZZ& q) {
    return PolynomialVector(length, Polynomial(degree, q));
}

PolynomialVector scale_vector(const PolynomialVector& vector,
                              const Polynomial& scalar) {
    PolynomialVector result;
    result.reserve(vector.size());
    for (const Polynomial& item : vector) {
        result.push_back(scalar * item);
    }
    return result;
}

void test_uniform_sampling_and_rejection() {
    CyclingByteSource source({0, 1, 2, 3, 4, 5, 6, 7});
    std::vector<NTL::ZZ> seen;
    for (int i = 0; i < 5; ++i) {
        seen.push_back(lattice_lrs::sampling::sample_uniform_coefficient(z(5), source));
    }
    require(seen == std::vector<NTL::ZZ>({z(0), z(1), z(2), z(3), z(4)}),
            "uniform sampler must reject out-of-range bit patterns instead of reducing modulo q");

    CyclingByteSource polynomial_source({0, 1, 2, 3, 4});
    const Polynomial sampled = lattice_lrs::sampling::sample_uniform_polynomial(
        4, z(5), polynomial_source);
    require(sampled == Polynomial(4, z(5), {z(0), z(1), z(2), z(3)}),
            "uniform polynomial coefficients must be sampled in Zq");
}

void test_bounded_sampling_and_vectors() {
    CyclingByteSource source({0, 1, 2});
    const std::vector<NTL::ZZ> expected = {z(-1), z(0), z(1), z(-1), z(0), z(1)};
    for (const NTL::ZZ& value : expected) {
        require(lattice_lrs::sampling::sample_bounded_coefficient(z(1), source) == value,
                "B=1 sampling must produce the ternary support");
    }

    CyclingByteSource vector_source({0, 1, 2});
    const PolynomialVector vector = lattice_lrs::sampling::sample_bounded_vector(
        2, 3, z(15), z(1), vector_source);
    require(vector.size() == 2, "sampled polynomial vector length mismatch");
    for (const Polynomial& polynomial : vector) {
        require(polynomial.degree() == 3 && polynomial.modulus() == z(15),
                "sampled vector polynomial ring mismatch");
        for (std::size_t i = 0; i < polynomial.degree(); ++i) {
            const NTL::ZZ coefficient = polynomial.centered_coefficient(i);
            require(coefficient >= z(-1) && coefficient <= z(1),
                    "bounded sampler output is outside [-B,B]");
        }
    }

    CyclingByteSource matrix_source({0, 1, 2, 3, 4});
    const Matrix matrix = lattice_lrs::sampling::sample_uniform_matrix(
        2, 3, 4, z(5), matrix_source);
    require(matrix.rows() == 2 && matrix.columns() == 3,
            "sampled matrix dimensions mismatch");
    for (std::size_t row = 0; row < matrix.rows(); ++row) {
        for (std::size_t column = 0; column < matrix.columns(); ++column) {
            require(matrix.at(row, column).degree() == 4 &&
                        matrix.at(row, column).modulus() == z(5),
                    "sampled matrix entry ring mismatch");
            for (const NTL::ZZ& coefficient : matrix.at(row, column).coefficients()) {
                require(coefficient >= 0 && coefficient < z(5),
                        "uniform matrix coefficient is not a canonical Zq representative");
            }
        }
    }

    CyclingByteSource bounded_matrix_source({0, 1, 2});
    const Matrix bounded_matrix = lattice_lrs::sampling::sample_bounded_matrix(
        2, 2, 3, z(15), z(1), bounded_matrix_source);
    require(bounded_matrix.rows() == 2 && bounded_matrix.columns() == 2,
            "bounded polynomial matrix dimensions mismatch");
    for (std::size_t row = 0; row < bounded_matrix.rows(); ++row) {
        for (std::size_t column = 0; column < bounded_matrix.columns(); ++column) {
            for (std::size_t i = 0; i < bounded_matrix.degree(); ++i) {
                const NTL::ZZ coefficient = bounded_matrix.at(row, column).centered_coefficient(i);
                require(coefficient >= z(-1) && coefficient <= z(1),
                        "bounded matrix coefficient is outside ternary support");
            }
        }
    }
}

void test_os_random_source_and_fail_closed_behavior() {
    lattice_lrs::sampling::SystemRandomSource system_random;
    RandomSource& compatible_interface = system_random;
    std::uint8_t bytes[32];
    std::fill(std::begin(bytes), std::end(bytes), static_cast<std::uint8_t>(0xA5));
    compatible_interface.fill_bytes(bytes, sizeof(bytes));
    require(std::any_of(std::begin(bytes), std::end(bytes),
                        [](std::uint8_t byte) { return byte != 0xA5; }),
            "OS random source must write generated bytes through RandomSource");

    // A zero-length request is a no-op even with a null buffer.
    compatible_interface.fill_bytes(nullptr, 0);

    bool null_buffer_rejected = false;
    try {
        compatible_interface.fill_bytes(nullptr, 1);
    } catch (const std::invalid_argument&) {
        null_buffer_rejected = true;
    }
    require(null_buffer_rejected,
            "random source must reject a null buffer for a nonempty request");

    FailingRandomSource failing;
    bool threw = false;
    try {
        (void)lattice_lrs::sampling::sample_uniform_coefficient(z(5), failing);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    require(threw, "sampling must propagate entropy-source failure rather than fall back");
}

void test_commitment_key_and_commit_open() {
    const Parameters parameters = baseline_test_parameters();
    CyclingByteSource key_random({1});
    const CommitmentKey key = lattice_lrs::commitment::CKeygen(parameters, key_random);
    require(key.G_r().rows() == 5 && key.G_r().columns() == 13,
            "G_r must have dimensions n by m");
    require(key.G_m().rows() == 5 && key.G_m().columns() == 16,
            "G_m must have dimensions n by v");
    require(key.G().rows() == 5 && key.G().columns() == 29,
            "combined G must have dimensions n by m+v");
    for (std::size_t row = 0; row < parameters.n; ++row) {
        for (std::size_t column = 0; column < parameters.n; ++column) {
            const NTL::ZZ expected = (row == column) ? z(1) : z(0);
            require(key.G_r().at(row, column).coefficient(0) == expected,
                    "G_r must begin with the n by n identity block");
        }
        for (std::size_t column = 0; column < parameters.m + parameters.v; ++column) {
            const Polynomial& expected = column < parameters.m
                ? key.G_r().at(row, column)
                : key.G_m().at(row, column - parameters.m);
            require(key.G().at(row, column) == expected,
                    "combined G must concatenate G_r and G_m");
        }
    }

    PolynomialVector message = zero_vector(parameters.v, parameters.degree, parameters.q);
    message[0] = Polynomial(parameters.degree, parameters.q, {z(1)});
    CyclingByteSource commit_random({0, 1, 2});
    const auto committed = Commit(key, message, commit_random);
    require(committed.commitment.size() == parameters.n,
            "commitment output dimension mismatch");
    require(committed.opening_randomness.size() == parameters.m,
            "opening randomness dimension mismatch");
    for (const Polynomial& item : committed.opening_randomness) {
        for (std::size_t i = 0; i < item.degree(); ++i) {
            const NTL::ZZ coefficient = item.centered_coefficient(i);
            require(coefficient >= z(-1) && coefficient <= z(1),
                    "Commit must sample r from S_B^m");
        }
    }

    const Polynomial one(parameters.degree, parameters.q, {z(1)});
    require(Open(key, committed.commitment, one, message, committed.opening_randomness),
            "honest commitment opening must verify");

    const Polynomial two(parameters.degree, parameters.q, {z(2)});
    require(Open(key, committed.commitment, two,
                 scale_vector(message, two), scale_vector(committed.opening_randomness, two)),
            "Open must honor the supplied non-unit relaxation factor y");

    const Polynomial three(parameters.degree, parameters.q, {z(3)});
    require(!Open(key, committed.commitment, three, message, committed.opening_randomness),
            "incorrect relaxation factor must be rejected");

    PolynomialVector changed_message = message;
    changed_message[0] = changed_message[0] + one;
    require(!Open(key, committed.commitment, one, changed_message,
                  committed.opening_randomness),
            "changed message must be rejected");

    PolynomialVector changed_randomness = committed.opening_randomness;
    changed_randomness[0] = changed_randomness[0] + one;
    require(!Open(key, committed.commitment, one, message, changed_randomness),
            "changed randomness must be rejected");

    const Parameters tight_parameters = baseline_test_parameters(z(15), z(1));
    const CommitmentKey tight_key(tight_parameters, key.G_r(), key.G_m());
    require(!Open(tight_key, committed.commitment, one, message,
                  committed.opening_randomness),
            "opening outside the exact Euclidean norm bound must be rejected");
}

void test_composite_odd_q_and_invalid_parameters() {
    Parameters composite_parameters{2, 4, 3, 256, z(15), z(1),
                                    SquaredNormBound(z(1000000), z(1))};
    CyclingByteSource source({1});
    const CommitmentKey key = lattice_lrs::commitment::CKeygen(composite_parameters, source);
    require(key.G().modulus() == z(15), "odd composite q must be accepted");

    Parameters even_parameters{2, 4, 3, 256, z(14), z(1),
                                SquaredNormBound(z(1000000), z(1))};
    bool rejected = false;
    try {
        even_parameters.validate();
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "Esgin-specific parameter validation must reject even q");
}

void test_open_dimension_rejection() {
    const Parameters parameters = baseline_test_parameters();
    CyclingByteSource source({1});
    const CommitmentKey key = lattice_lrs::commitment::CKeygen(parameters, source);
    const Polynomial one(parameters.degree, parameters.q, {z(1)});
    require(!Open(key, zero_vector(parameters.n - 1, parameters.degree, parameters.q),
                  one, zero_vector(parameters.v, parameters.degree, parameters.q),
                  zero_vector(parameters.m, parameters.degree, parameters.q)),
            "Open must reject a commitment with the wrong dimension");
}

void test_exact_rational_norm_boundary() {
    const NTL::ZZ q = z(5);
    const Polynomial one(1, q, {z(1)});
    const Polynomial zero(1, q);
    Matrix G_r(1, 1, 1, q);
    Matrix G_m(1, 1, 1, q);
    G_r.at(0, 0) = one;

    Parameters at_boundary{1, 1, 1, 1, q, z(1), SquaredNormBound(z(1), z(1))};
    const CommitmentKey accepting_key(at_boundary, G_r, G_m);
    require(Open(accepting_key, {one}, one, {zero}, {one}),
            "opening exactly at T_com must be accepted");

    Parameters below_boundary{1, 1, 1, 1, q, z(1),
                              SquaredNormBound(z(999), z(1000))};
    const CommitmentKey rejecting_key(below_boundary, G_r, G_m);
    require(!Open(rejecting_key, {one}, one, {zero}, {one}),
            "exact rational norm comparison must reject just below the opening norm");
}

}  // namespace

int main() {
    try {
        test_uniform_sampling_and_rejection();
        test_bounded_sampling_and_vectors();
        test_os_random_source_and_fail_closed_behavior();
        test_commitment_key_and_commit_open();
        test_composite_odd_q_and_invalid_parameters();
        test_open_dimension_rejection();
        test_exact_rational_norm_boundary();
    } catch (const std::exception& error) {
        std::cerr << "sampling/commitment test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
