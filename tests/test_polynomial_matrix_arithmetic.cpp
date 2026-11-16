#include "lattice_lrs/arithmetic/matrix.hpp"

#include <NTL/ZZ.h>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

void test_polynomial_add_subtract_and_reduction() {
    const NTL::ZZ q = z(5);
    const Polynomial a(3, q, {z(-1), z(6), z(2)});  // [4, 1, 2]
    const Polynomial b(3, q, {z(2), z(-7), z(1)});  // [2, 3, 1]

    require(a.coefficients() == std::vector<NTL::ZZ>({z(4), z(1), z(2)}),
            "constructor must reduce negative and oversized coefficients");
    require((a + b) == Polynomial(3, q, {z(1), z(4), z(3)}),
            "polynomial addition must reduce modulo q");
    require((a - b) == Polynomial(3, q, {z(2), z(3), z(1)}),
            "polynomial subtraction must canonicalize negative results");

    const Polynomial composite_q(2, z(15), {z(-31), z(47)});
    require(composite_q == Polynomial(2, z(15), {z(14), z(2)}),
            "coefficient reduction must work for a composite modulus");
}

void test_negacyclic_multiplication() {
    const NTL::ZZ q = z(5);
    const Polynomial a(3, q, {z(4), z(1), z(2)});
    const Polynomial b(3, q, {z(2), z(3), z(1)});
    require((a * b) == Polynomial(3, q, {z(1), z(2), z(1)}),
            "negacyclic convolution must fold high terms with a minus sign");

    const Polynomial x_squared(3, z(5), {z(0), z(0), z(1)});
    const Polynomial x(3, z(5), {z(0), z(1), z(0)});
    require((x_squared * x) == Polynomial(3, z(5), {z(4), z(0), z(0)}),
            "X^degree must equal -1");
}

void test_centered_coefficients() {
    const Polynomial even(5, z(10), {z(0), z(4), z(5), z(6), z(9)});
    require(even.centered_coefficient(0) == z(0), "centered zero mismatch");
    require(even.centered_coefficient(1) == z(4), "positive centered coefficient mismatch");
    require(even.centered_coefficient(2) == z(-5), "even-modulus midpoint convention mismatch");
    require(even.centered_coefficient(3) == z(-4), "negative centered coefficient mismatch");
    require(even.centered_coefficient(4) == z(-1), "centered residue mismatch");

    const Polynomial odd(1, z(9), {z(5)});
    require(odd.centered_coefficient(0) == z(-4), "odd-modulus centered range mismatch");
}

void test_matrix_operations() {
    const NTL::ZZ q = z(7);
    Matrix left(1, 2, 2, q);
    left.at(0, 0) = Polynomial(2, q, {z(1), z(0)});
    left.at(0, 1) = Polynomial(2, q, {z(2), z(0)});

    Matrix right(2, 1, 2, q);
    right.at(0, 0) = Polynomial(2, q, {z(3), z(0)});
    right.at(1, 0) = Polynomial(2, q, {z(4), z(0)});
    const Matrix product = left * right;
    require(product.rows() == 1 && product.columns() == 1, "matrix product dimensions mismatch");
    require(product.at(0, 0) == Polynomial(2, q, {z(4), z(0)}),
            "matrix product must multiply and add in Rq");

    Matrix first(1, 1, 2, q, {Polynomial(2, q, {z(-1), z(8)})});
    Matrix second(1, 1, 2, q, {Polynomial(2, q, {z(3), z(6)})});
    require((first + second).at(0, 0) == Polynomial(2, q, {z(2), z(0)}),
            "matrix addition must reduce entries");
    require((first - second).at(0, 0) == Polynomial(2, q, {z(3), z(2)}),
            "matrix subtraction must reduce entries");
}

void test_degree_256_and_large_integer_modulus() {
    const Polynomial x255(256, z(97), [&] {
        std::vector<NTL::ZZ> coefficients(256, z(0));
        coefficients[255] = z(1);
        return coefficients;
    }());
    const Polynomial x(256, z(97), [&] {
        std::vector<NTL::ZZ> coefficients(256, z(0));
        coefficients[1] = z(1);
        return coefficients;
    }());
    require((x255 * x).coefficient(0) == z(96),
            "degree-256 multiplication must correctly wrap X^256 to -1");

    const NTL::ZZ large_q = (NTL::ZZ(1) << 50) + z(12345);  // synthetic test modulus only
    const Polynomial large(2, large_q, {large_q + z(2), -large_q - z(3)});
    require(large == Polynomial(2, large_q, {z(2), large_q - z(3)}),
            "arbitrary-precision q reduction mismatch");
}

void test_invalid_inputs() {
    bool rejected = false;
    try {
        (void)Polynomial(2, z(1));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "q <= 1 must be rejected");

    rejected = false;
    try {
        (void)(Polynomial(2, z(5)) + Polynomial(2, z(7)));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "mixed polynomial rings must be rejected");

    rejected = false;
    try {
        Matrix a(1, 2, 2, z(5));
        Matrix b(1, 1, 2, z(5));
        (void)(a * b);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "incompatible matrix multiplication dimensions must be rejected");
}

}  // namespace

int main() {
    try {
        test_polynomial_add_subtract_and_reduction();
        test_negacyclic_multiplication();
        test_centered_coefficients();
        test_matrix_operations();
        test_degree_256_and_large_integer_modulus();
        test_invalid_inputs();
    } catch (const std::exception& error) {
        std::cerr << "arithmetic test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
