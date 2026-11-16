#include "lattice_lrs/proofs/protocol2_response.hpp"

#include <stdexcept>

namespace lattice_lrs::proofs {
namespace {

bool matches_ring(const arithmetic::Polynomial& polynomial,
                  const arithmetic::Polynomial& ring_example) {
    return polynomial.degree() == ring_example.degree() &&
           polynomial.modulus() == ring_example.modulus();
}

}  // namespace

sampling::PolynomialVector ComputeProtocol2Z(
    const arithmetic::Polynomial& x,
    std::size_t k,
    const sampling::PolynomialVector& r,
    const std::vector<sampling::PolynomialVector>& rho) {
    if (k == 0) {
        throw std::invalid_argument("Protocol 2 response k must be positive");
    }
    if (rho.size() != k) {
        throw std::invalid_argument("Protocol 2 response mask count must equal k");
    }
    if (r.empty()) {
        throw std::invalid_argument("Protocol 2 response vector r must be nonempty");
    }

    for (const arithmetic::Polynomial& value : r) {
        if (!matches_ring(value, x)) {
            throw std::invalid_argument("Protocol 2 response r uses an incompatible ring");
        }
    }
    for (const sampling::PolynomialVector& mask : rho) {
        if (mask.size() != r.size()) {
            throw std::invalid_argument("Protocol 2 response masks must match r's length");
        }
        for (const arithmetic::Polynomial& value : mask) {
            if (!matches_ring(value, x)) {
                throw std::invalid_argument("Protocol 2 response mask uses an incompatible ring");
            }
        }
    }

    const arithmetic::Polynomial zero(x.degree(), x.modulus());
    const arithmetic::Polynomial one(x.degree(), x.modulus(), {NTL::ZZ(1)});
    sampling::PolynomialVector weighted_masks(r.size(), zero);
    arithmetic::Polynomial power = one;

    for (std::size_t j = 0; j < k; ++j) {
        for (std::size_t coordinate = 0; coordinate < r.size(); ++coordinate) {
            weighted_masks[coordinate] =
                weighted_masks[coordinate] + power * rho[j][coordinate];
        }
        power = power * x;
    }

    sampling::PolynomialVector result;
    result.reserve(r.size());
    for (std::size_t coordinate = 0; coordinate < r.size(); ++coordinate) {
        result.push_back(power * r[coordinate] - weighted_masks[coordinate]);
    }
    return result;
}

}  // namespace lattice_lrs::proofs
