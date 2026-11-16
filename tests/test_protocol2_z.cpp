#include "lattice_lrs/proofs/protocol2_response.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::proofs::ComputeProtocol2Z;
using lattice_lrs::sampling::PolynomialVector;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

void test_k_one() {
    const Polynomial x(2, z(7), {z(0), z(6)});  // -Y
    const PolynomialVector r{Polynomial(2, z(7), {z(1), z(2)})};
    const std::vector<PolynomialVector> rho{
        {Polynomial(2, z(7), {z(3), z(1)})},
    };

    require(ComputeProtocol2Z(x, 1, r, rho) ==
                PolynomialVector{Polynomial(2, z(7), {z(6), z(5)})},
            "k=1 result must equal x*r-rho[0]");
}

void test_multiple_masks_and_negacyclic_powers() {
    const Polynomial x(2, z(7), {z(0), z(6)});  // -Y
    require(x * x == Polynomial(2, z(7), {z(6)}),
            "the challenge square must reduce using Y^2=-1");

    const PolynomialVector r{Polynomial(2, z(7), {z(2), z(1)})};
    const std::vector<PolynomialVector> rho{
        {Polynomial(2, z(7), {z(1), z(1)})},
        {Polynomial(2, z(7), {z(3), z(2)})},
        {Polynomial(2, z(7), {z(4), z(1)})},
    };
    const PolynomialVector expected{Polynomial(2, z(7), {z(0), z(5)})};
    require(ComputeProtocol2Z(x, 3, r, rho) == expected,
            "multiple-mask result must use powers in R_q");

    auto reordered_rho = rho;
    std::swap(reordered_rho[0], reordered_rho[1]);
    require(ComputeProtocol2Z(x, 3, r, reordered_rho) != expected,
            "rho masks must be used in their supplied order");
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

void test_invalid_inputs() {
    const Polynomial x(2, z(7), {z(0), z(1)});
    const PolynomialVector r{Polynomial(2, z(7), {z(1)})};
    const std::vector<PolynomialVector> rho{
        {Polynomial(2, z(7), {z(2)})},
    };

    require_throws<std::invalid_argument>(
        [&] { (void)ComputeProtocol2Z(x, 0, r, {}); },
        "k=0 must be rejected");
    require_throws<std::invalid_argument>(
        [&] { (void)ComputeProtocol2Z(x, 2, r, rho); },
        "mask count different from k must be rejected");
    require_throws<std::invalid_argument>(
        [&] { (void)ComputeProtocol2Z(x, 1, {}, rho); },
        "empty r must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2Z(
                x, 1, r, {PolynomialVector{Polynomial(2, z(7)), Polynomial(2, z(7))}});
        },
        "mask vector length different from r must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2Z(
                x, 1, PolynomialVector{Polynomial(3, z(7))}, rho);
        },
        "r with a different degree must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2Z(
                x, 1, r, {PolynomialVector{Polynomial(2, z(11))}});
        },
        "mask with a different modulus must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2Z(
                Polynomial(2, z(11), {z(0), z(1)}), 1, r, rho);
        },
        "challenge with a different modulus must be rejected");
}

}  // namespace

int main() {
    try {
        test_k_one();
        test_multiple_masks_and_negacyclic_powers();
        test_invalid_inputs();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 z test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
