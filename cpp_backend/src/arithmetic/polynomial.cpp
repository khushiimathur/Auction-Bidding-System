#include "lattice_lrs/arithmetic/polynomial.hpp"

#include <stdexcept>

namespace lattice_lrs::arithmetic {

Polynomial::Polynomial(std::size_t degree, const NTL::ZZ& modulus)
    : Polynomial(degree, modulus, std::vector<NTL::ZZ>(degree, NTL::ZZ(0))) {}

Polynomial::Polynomial(std::size_t degree, const NTL::ZZ& modulus,
                       const std::vector<NTL::ZZ>& coefficients)
    : degree_(degree), modulus_(modulus), coefficients_(degree, NTL::ZZ(0)) {
    if (degree_ == 0) {
        throw std::invalid_argument("polynomial ring degree must be positive");
    }
    if (modulus_ <= 1) {
        throw std::invalid_argument("polynomial modulus q must be greater than 1");
    }
    for (std::size_t i = 0; i < coefficients.size() && i < degree_; ++i) {
        coefficients_[i] = canonical_residue(coefficients[i], modulus_);
    }
}

const NTL::ZZ& Polynomial::coefficient(std::size_t index) const {
    return coefficients_.at(index);
}

NTL::ZZ Polynomial::centered_coefficient(std::size_t index) const {
    NTL::ZZ centered = coefficient(index);
    // For even q this selects [-q/2, q/2-1]; for odd q it selects
    // [-floor(q/2), floor(q/2)].
    if (2 * centered >= modulus_) {
        centered -= modulus_;
    }
    return centered;
}

Polynomial Polynomial::operator+(const Polynomial& other) const {
    require_compatible(other);
    std::vector<NTL::ZZ> result(degree_);
    for (std::size_t i = 0; i < degree_; ++i) {
        result[i] = canonical_residue(coefficients_[i] + other.coefficients_[i], modulus_);
    }
    return Polynomial(degree_, modulus_, result);
}

Polynomial Polynomial::operator-(const Polynomial& other) const {
    require_compatible(other);
    std::vector<NTL::ZZ> result(degree_);
    for (std::size_t i = 0; i < degree_; ++i) {
        result[i] = canonical_residue(coefficients_[i] - other.coefficients_[i], modulus_);
    }
    return Polynomial(degree_, modulus_, result);
}

Polynomial Polynomial::operator*(const Polynomial& other) const {
    require_compatible(other);
    std::vector<NTL::ZZ> result(degree_, NTL::ZZ(0));
    for (std::size_t i = 0; i < degree_; ++i) {
        for (std::size_t j = 0; j < degree_; ++j) {
            const std::size_t exponent = i + j;
            const std::size_t target = exponent % degree_;
            const NTL::ZZ product = coefficients_[i] * other.coefficients_[j];
            // X^degree = -1. Since i,j < degree, exponent wraps at most once.
            if (exponent >= degree_) {
                result[target] -= product;
            } else {
                result[target] += product;
            }
        }
    }
    for (NTL::ZZ& coefficient : result) {
        coefficient = canonical_residue(coefficient, modulus_);
    }
    return Polynomial(degree_, modulus_, result);
}

bool Polynomial::operator==(const Polynomial& other) const noexcept {
    return degree_ == other.degree_ && modulus_ == other.modulus_ &&
           coefficients_ == other.coefficients_;
}

NTL::ZZ Polynomial::canonical_residue(const NTL::ZZ& value, const NTL::ZZ& modulus) {
    NTL::ZZ quotient;
    NTL::ZZ residue;
    NTL::DivRem(quotient, residue, value, modulus);
    if (residue < 0) {
        residue += modulus;
    }
    return residue;
}

void Polynomial::require_compatible(const Polynomial& other) const {
    if (degree_ != other.degree_ || modulus_ != other.modulus_) {
        throw std::invalid_argument("polynomial operands must use the same degree and modulus");
    }
}

}  // namespace lattice_lrs::arithmetic
