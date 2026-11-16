#include "lattice_lrs/proofs/protocol2_commitment.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::CommitmentKey;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::proofs::BuildProtocol2E;
using lattice_lrs::proofs::ExpandProtocol2Polynomial;
using lattice_lrs::proofs::Protocol2PolynomialExpansion;
using lattice_lrs::sampling::PolynomialVector;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

CommitmentKey make_key() {
    Parameters parameters{1, 1, 1, 2, z(7), z(1), SquaredNormBound(z(100), z(1))};
    Matrix G_r(1, 1, 2, z(7));
    G_r.at(0, 0) = Polynomial(2, z(7), {z(1)});
    Matrix G_m(1, 1, 2, z(7));
    return CommitmentKey(parameters, std::move(G_r), std::move(G_m));
}

std::vector<PolynomialVector> make_commitments() {
    return {
        {Polynomial(2, z(7), {z(1), z(1)})},
        {Polynomial(2, z(7), {z(2)})},
        {Polynomial(2, z(7), {z(3), z(1)})},
        {Polynomial(2, z(7), {z(4)})},
    };
}

std::vector<Protocol2PolynomialExpansion> make_expansions() {
    const PolynomialVector a_values{
        Polynomial(2, z(7), {z(1)}),
        Polynomial(2, z(7), {z(2)}),
        Polynomial(2, z(7), {z(3)}),
        Polynomial(2, z(7), {z(4)}),
    };
    const std::vector<std::size_t> selected_digits{0, 1};
    std::vector<Protocol2PolynomialExpansion> expansions;
    expansions.reserve(4);
    for (std::size_t index = 0; index < 4; ++index) {
        expansions.push_back(ExpandProtocol2Polynomial(
            a_values, 2, 2, selected_digits, {index % 2, index / 2}));
    }
    return expansions;
}

void test_hand_calculated_results_and_ordering() {
    const CommitmentKey key = make_key();
    const auto commitments = make_commitments();
    const auto expansions = make_expansions();

    const PolynomialVector rho_0{Polynomial(2, z(7), {z(5), z(1)})};
    const PolynomialVector rho_1{Polynomial(2, z(7), {z(6), z(2)})};
    const PolynomialVector E_0 =
        BuildProtocol2E(key, commitments, expansions, 2, 2, 0, rho_0);
    const PolynomialVector E_1 =
        BuildProtocol2E(key, commitments, expansions, 2, 2, 1, rho_1);

    require(E_0 == PolynomialVector{Polynomial(2, z(7), {z(1), z(1)})},
            "E_0 hand calculation or list ordering is incorrect");
    require(E_1 == PolynomialVector{Polynomial(2, z(7), {z(4), z(3)})},
            "E_1 hand calculation or list ordering is incorrect");

    auto reordered_commitments = commitments;
    std::swap(reordered_commitments[0], reordered_commitments[1]);
    require(BuildProtocol2E(key, reordered_commitments, expansions, 2, 2, 0, rho_0) != E_0,
            "list entries must be paired with expansions in the supplied index order");
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
    const CommitmentKey key = make_key();
    const auto commitments = make_commitments();
    const auto expansions = make_expansions();
    const PolynomialVector rho{Polynomial(2, z(7), {z(1)})};

    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, commitments, expansions, 2, 2, 2, rho); },
        "out-of-range j must be rejected");

    auto short_commitments = commitments;
    short_commitments.pop_back();
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, short_commitments, expansions, 2, 2, 0, rho); },
        "incorrect list size must be rejected");

    auto short_expansions = expansions;
    short_expansions.pop_back();
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, commitments, short_expansions, 2, 2, 0, rho); },
        "incorrect expansion count must be rejected");

    auto short_coefficients = expansions;
    short_coefficients[0].coefficients.pop_back();
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, commitments, short_coefficients, 2, 2, 0, rho); },
        "incorrect coefficient count must be rejected");

    auto wrong_commitment = commitments;
    wrong_commitment[0].push_back(Polynomial(2, z(7)));
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, wrong_commitment, expansions, 2, 2, 0, rho); },
        "incorrect commitment-vector dimension must be rejected");

    auto mixed_ring_commitments = commitments;
    mixed_ring_commitments[0][0] = Polynomial(2, z(11));
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, mixed_ring_commitments, expansions, 2, 2, 0, rho); },
        "commitments in the wrong modulus must be rejected");

    auto mixed_ring_expansions = expansions;
    mixed_ring_expansions[0].coefficients[0] = Polynomial(2, z(11));
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, commitments, mixed_ring_expansions, 2, 2, 0, rho); },
        "expansion coefficients in the wrong modulus must be rejected");

    require_throws<std::invalid_argument>(
        [&] {
            (void)BuildProtocol2E(
                key, commitments, expansions, 2, 2, 0,
                PolynomialVector{Polynomial(3, z(7))});
        },
        "rho_j in the wrong degree must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)BuildProtocol2E(
                key, commitments, expansions, 2, 2, 0,
                PolynomialVector{Polynomial(2, z(11))});
        },
        "rho_j in the wrong modulus must be rejected");
    require_throws<std::invalid_argument>(
        [&] {
            (void)BuildProtocol2E(
                key, commitments, expansions, 2, 2, 0,
                PolynomialVector{Polynomial(2, z(7)), Polynomial(2, z(7))});
        },
        "incorrect rho_j dimension must be rejected");

    auto mixed_ring_leading = expansions;
    mixed_ring_leading[0].leading_coefficient = Polynomial(2, z(11));
    require_throws<std::invalid_argument>(
        [&] { (void)BuildProtocol2E(key, commitments, mixed_ring_leading, 2, 2, 0, rho); },
        "leading coefficients in the wrong modulus must be rejected");

    require_throws<std::length_error>(
        [&] {
            (void)BuildProtocol2E(
                key, {}, {}, std::numeric_limits<std::size_t>::digits, 2, 0, {});
        },
        "overflow in beta^k must be rejected");
}

}  // namespace

int main() {
    try {
        test_hand_calculated_results_and_ordering();
        test_invalid_inputs();
    } catch (const std::exception& error) {
        std::cerr << "Protocol 2 commitment test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
