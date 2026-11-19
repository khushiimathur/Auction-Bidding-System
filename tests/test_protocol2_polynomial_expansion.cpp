#include "lattice_lrs/proofs/protocol2_polynomial.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::proofs::ExpandProtocol2Polynomial;
using lattice_lrs::sampling::PolynomialVector;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

PolynomialVector make_a_values() {
    const NTL::ZZ q = z(7);
    return {
        Polynomial(2, q, {z(1), z(1)}),  // a_{0,0} = 1 + Y
        Polynomial(2, q, {z(2)}),        // a_{0,1} = 2
        Polynomial(2, q, {z(2), z(1)}),  // a_{1,0} = 2 + Y
        Polynomial(2, q, {z(3), z(1)}),  // a_{1,1} = 3 + Y
    };
}

void test_leading_coefficient_one() {
    const auto expansion = ExpandProtocol2Polynomial(
        make_a_values(), 2, 2, {0, 1}, {0, 1});

    require(expansion.coefficients.size() == 2,
            "expansion must return the coefficients below degree k");
    require(expansion.coefficients[0] == Polynomial(2, z(7), {z(2), z(4)}),
            "constant coefficient mismatch");
    require(expansion.coefficients[1] == Polynomial(2, z(7), {z(4), z(2)}),
            "linear coefficient mismatch");
    require(expansion.leading_coefficient == Polynomial(2, z(7), {z(1)}),
            "matching digit tuples must have leading coefficient one");

    const Polynomial challenge(2, z(7), {z(1), z(1)});
    const Polynomial factored =
        (challenge + make_a_values()[0]) * (challenge + make_a_values()[3]);
    const Polynomial expanded = expansion.coefficients[0] +
        expansion.coefficients[1] * challenge +
        expansion.leading_coefficient * challenge * challenge;
    require(expanded == factored, "expanded polynomial must match its factored form");
}

void test_leading_coefficient_zero() {
    const auto expansion = ExpandProtocol2Polynomial(
        make_a_values(), 2, 2, {0, 1}, {0, 0});

    require(expansion.coefficients[0] == Polynomial(2, z(7), {z(1), z(3)}),
            "constant coefficient mismatch when leading coefficient is zero");
    require(expansion.coefficients[1] == Polynomial(2, z(7), {z(2), z(1)}),
            "linear coefficient mismatch when leading coefficient is zero");
    require(expansion.leading_coefficient == Polynomial(2, z(7)),
            "nonmatching digit tuples must have leading coefficient zero");

    const Polynomial challenge(2, z(7), {z(1), z(1)});
    const Polynomial factored =
        (challenge + make_a_values()[0]) * make_a_values()[2];
    const Polynomial expanded = expansion.coefficients[0] +
        expansion.coefficients[1] * challenge +
        expansion.leading_coefficient * challenge * challenge;
    require(expanded == factored, "expanded polynomial must match its factored form");
}

template <typename Exception, typename Function>
void require_throws(Function&& function, const std::string& message) {
    bool threw = false;
    try {
        function();
    } catch (const Exception&) {
        threw = true;
    }
    require(threw, message);
}

void test_invalid_dimensions_and_digits() {
    const PolynomialVector a = make_a_values();
    require_throws<std::invalid_argument>(
        [&] { (void)ExpandProtocol2Polynomial(a, 0, 2, {}, {}); },
        "zero k must be rejected");
    require_throws<std::invalid_argument>(
        [&] { (void)ExpandProtocol2Polynomial(a, 2, 0, {0, 0}, {0, 0}); },
        "zero beta must be rejected");
    require_throws<std::invalid_argument>(
        [&] { (void)ExpandProtocol2Polynomial(a, 2, 2, {0}, {0, 1}); },
        "incorrect digit-vector dimensions must be rejected");
    require_throws<std::invalid_argument>(
        [&] { (void)ExpandProtocol2Polynomial(a, 2, 2, {0, 2}, {0, 1}); },
        "out-of-range selected digits must be rejected");
    require_throws<std::invalid_argument>(
        [&] { (void)ExpandProtocol2Polynomial(a, 2, 2, {0, 1}, {0, 2}); },
        "out-of-range index digits must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            PolynomialVector short_a = a;
            short_a.pop_back();
            (void)ExpandProtocol2Polynomial(short_a, 2, 2, {0, 1}, {0, 1});
        },
        "incorrect a-value dimensions must be rejected");

    PolynomialVector mixed_ring = a;
    mixed_ring[1] = Polynomial(2, z(11), {z(2)});
    require_throws<std::invalid_argument>(
        [&] { (void)ExpandProtocol2Polynomial(mixed_ring, 2, 2, {0, 1}, {0, 1}); },
        "mixed polynomial rings must be rejected");
}

void test_dimension_overflow() {
    const std::size_t max_size = std::numeric_limits<std::size_t>::max();
    require_throws<std::length_error>(
        [&] { (void)ExpandProtocol2Polynomial({}, max_size, 2, {}, {}); },
        "k * beta overflow must be rejected");
    require_throws<std::length_error>(
        [&] { (void)ExpandProtocol2Polynomial({}, max_size, 1, {}, {}); },
        "k + 1 overflow must be rejected");
}

}  // namespace

int main() {
    try {
        test_leading_coefficient_one();
        test_leading_coefficient_zero();
        test_invalid_dimensions_and_digits();
        test_dimension_overflow();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 polynomial expansion test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
