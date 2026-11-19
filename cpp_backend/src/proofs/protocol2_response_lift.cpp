#include "lattice_lrs/proofs/protocol2_response_lift.hpp"

#include <stdexcept>
#include <string>

namespace lattice_lrs::proofs {
namespace {

struct SignedMonomial {
    std::size_t degree;
    bool negative;
};

SignedMonomial require_signed_monomial(const arithmetic::Polynomial& x) {
    if (x.degree() == 0 || x.modulus() <= 2 || !NTL::IsOdd(x.modulus())) {
        throw std::invalid_argument(
            "Protocol 2 challenge must use an odd-modulus polynomial ring");
    }

    std::size_t nonzero_count = 0;
    SignedMonomial result{0, false};
    for (std::size_t i = 0; i < x.degree(); ++i) {
        const NTL::ZZ& coefficient = x.coefficient(i);
        if (coefficient == 0) continue;
        ++nonzero_count;
        if (coefficient == 1) {
            result = {i, false};
        } else if (coefficient == x.modulus() - 1) {
            result = {i, true};
        } else {
            throw std::invalid_argument(
                "Protocol 2 challenge must be a signed monomial");
        }
    }
    if (nonzero_count != 1) {
        throw std::invalid_argument(
            "Protocol 2 challenge must be a signed monomial");
    }
    return result;
}

SignedMonomial multiply_monomials(const SignedMonomial& left,
                                  const SignedMonomial& right,
                                  std::size_t degree) {
    const bool wraps = right.degree >= degree - left.degree;
    const std::size_t result_degree =
        wraps ? right.degree - (degree - left.degree)
              : left.degree + right.degree;
    return {result_degree, (left.negative != right.negative) != wraps};
}

std::vector<NTL::ZZ> multiply_by_monomial(
    const std::vector<NTL::ZZ>& input,
    const SignedMonomial& monomial,
    std::size_t degree) {
    std::vector<NTL::ZZ> result(input.size(), NTL::ZZ(0));
    for (std::size_t base = 0; base < input.size(); base += degree) {
        for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
            const bool wraps = coefficient >= degree - monomial.degree;
            const std::size_t target =
                wraps ? coefficient - (degree - monomial.degree)
                      : coefficient + monomial.degree;
            result[base + target] =
                monomial.negative != wraps ? -input[base + coefficient]
                                           : input[base + coefficient];
        }
    }
    return result;
}

void require_same_length(const std::vector<NTL::ZZ>& values,
                         std::size_t expected,
                         const char* name) {
    if (values.size() != expected) {
        throw std::invalid_argument(std::string("Protocol 2 integer-lift ") +
                                    name + " has an incompatible dimension");
    }
}

void add_in_place(std::vector<NTL::ZZ>& destination,
                  const std::vector<NTL::ZZ>& addend) {
    for (std::size_t i = 0; i < destination.size(); ++i) {
        destination[i] += addend[i];
    }
}

std::vector<NTL::ZZ> subtract(const std::vector<NTL::ZZ>& left,
                              const std::vector<NTL::ZZ>& right) {
    std::vector<NTL::ZZ> result(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        result[i] = left[i] - right[i];
    }
    return result;
}

std::vector<NTL::ZZ> add(const std::vector<NTL::ZZ>& left,
                         const std::vector<NTL::ZZ>& right) {
    std::vector<NTL::ZZ> result = left;
    add_in_place(result, right);
    return result;
}

}  // namespace

Protocol2IntegerLiftResponses ComputeProtocol2IntegerLiftResponses(
    const arithmetic::Polynomial& x,
    std::size_t k,
    const std::vector<NTL::ZZ>& r_lift,
    const std::vector<std::vector<NTL::ZZ>>& rho_lifts,
    const std::vector<NTL::ZZ>& r_b_lift,
    const std::vector<NTL::ZZ>& r_a_lift,
    const std::vector<NTL::ZZ>& r_c_lift,
    const std::vector<NTL::ZZ>& r_d_lift) {
    if (k == 0) {
        throw std::invalid_argument("Protocol 2 integer-lift k must be positive");
    }
    if (rho_lifts.size() != k) {
        throw std::invalid_argument(
            "Protocol 2 integer-lift mask count must equal k");
    }
    if (r_lift.empty() || r_lift.size() % x.degree() != 0) {
        throw std::invalid_argument(
            "Protocol 2 integer-lift vectors must contain complete polynomials");
    }

    const std::size_t coefficient_count = r_lift.size();
    require_same_length(r_b_lift, coefficient_count, "r_b");
    require_same_length(r_a_lift, coefficient_count, "r_a");
    require_same_length(r_c_lift, coefficient_count, "r_c");
    require_same_length(r_d_lift, coefficient_count, "r_d");
    for (const auto& rho : rho_lifts) {
        require_same_length(rho, coefficient_count, "rho mask");
    }

    const SignedMonomial challenge = require_signed_monomial(x);
    const std::size_t degree = x.degree();

    std::vector<NTL::ZZ> weighted_rho(coefficient_count, NTL::ZZ(0));
    SignedMonomial power{0, false};
    for (const auto& rho : rho_lifts) {
        add_in_place(weighted_rho, multiply_by_monomial(rho, power, degree));
        power = multiply_monomials(power, challenge, degree);
    }

    return {
        subtract(multiply_by_monomial(r_lift, power, degree), weighted_rho),
        add(multiply_by_monomial(r_b_lift, challenge, degree), r_a_lift),
        add(multiply_by_monomial(r_c_lift, challenge, degree), r_d_lift),
    };
}

}  // namespace lattice_lrs::proofs
