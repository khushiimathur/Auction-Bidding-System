#include "lattice_lrs/proofs/protocol2_response_lift.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::proofs::ComputeProtocol2IntegerLiftResponses;
using lattice_lrs::proofs::Protocol2IntegerLiftResponses;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

void test_hand_calculated_lifts_and_ordering() {
    const Polynomial x(2, z(17), {z(0), z(1)});
    const Protocol2IntegerLiftResponses actual =
        ComputeProtocol2IntegerLiftResponses(
            x, 1,
            {z(1), z(2), z(3), z(4)},
            {{z(5), z(6), z(7), z(8)}},
            {z(1), z(2), z(3), z(4)},
            {z(20), z(-30), z(40), z(-50)},
            {z(9), z(-2), z(5), z(-6)},
            {z(-3), z(4), z(-7), z(8)});

    require(actual.z_lift ==
                std::vector<NTL::ZZ>{z(-7), z(-5), z(-11), z(-5)},
            "z must preserve mask and coefficient ordering");
    require(actual.z_b_lift ==
                std::vector<NTL::ZZ>{z(18), z(-29), z(36), z(-47)},
            "z_b must use x*r_b+r_a over unreduced integer lifts");
    require(actual.z_c_lift ==
                std::vector<NTL::ZZ>{z(-1), z(13), z(-1), z(13)},
            "z_c must use x*r_c+r_d in vector-major order");
    require(actual.z_b_lift[1] == z(-29),
            "negative lifts must not be reduced modulo q");
}

void test_multiple_masks_and_negacyclic_wraparound() {
    const Polynomial x(2, z(17), {z(0), z(1)});
    const Protocol2IntegerLiftResponses actual =
        ComputeProtocol2IntegerLiftResponses(
            x, 2, {z(2), z(-3)},
            {{z(1), z(4)}, {z(-2), z(5)}},
            {z(3), z(4)}, {z(-1), z(2)},
            {z(-2), z(1)}, {z(4), z(-3)});

    require(actual.z_lift == std::vector<NTL::ZZ>{z(2), z(1)},
            "z must use x^2*r and ordered rho masks with X^2=-1");
    require(actual.z_b_lift == std::vector<NTL::ZZ>{z(-5), z(5)},
            "z_b must preserve the negacyclic wrap sign");
    require(actual.z_c_lift == std::vector<NTL::ZZ>{z(3), z(-5)},
            "z_c must preserve negative coefficients after rotation");
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
    const Polynomial x(2, z(17), {z(0), z(1)});
    const std::vector<NTL::ZZ> pair{z(1), z(2)};

    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2IntegerLiftResponses(
                x, 0, pair, {}, pair, pair, pair, pair);
        },
        "k=0 must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2IntegerLiftResponses(
                x, 2, pair, {pair}, pair, pair, pair, pair);
        },
        "mask count different from k must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2IntegerLiftResponses(
                x, 1, pair, {pair}, pair, {z(1)}, pair, pair);
        },
        "inconsistent vector lengths must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2IntegerLiftResponses(
                x, 1, {z(1), z(2), z(3)}, {{z(1), z(2), z(3)}},
                {z(1), z(2), z(3)}, {z(1), z(2), z(3)},
                {z(1), z(2), z(3)}, {z(1), z(2), z(3)});
        },
        "vectors not divisible into the challenge degree must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)ComputeProtocol2IntegerLiftResponses(
                Polynomial(2, z(17), {z(1), z(1)}), 1, pair, {pair},
                pair, pair, pair, pair);
        },
        "a non-monomial challenge must be rejected");
}

}  // namespace

int main() {
    try {
        test_hand_calculated_lifts_and_ordering();
        test_multiple_masks_and_negacyclic_wraparound();
        test_invalid_inputs();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 integer-lift response test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
