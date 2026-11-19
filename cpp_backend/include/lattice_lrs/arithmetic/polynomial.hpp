#pragma once

#include <NTL/ZZ.h>

#include <cstddef>
#include <vector>

namespace lattice_lrs::arithmetic {

// An element of Z_q[X]/(X^degree + 1). Coefficients are always stored in
// their canonical residues [0, q-1]. No field operations are performed, so q
// may be composite.
class Polynomial {
public:
    Polynomial(std::size_t degree, const NTL::ZZ& modulus);
    Polynomial(std::size_t degree, const NTL::ZZ& modulus,
               const std::vector<NTL::ZZ>& coefficients);

    std::size_t degree() const noexcept { return degree_; }
    const NTL::ZZ& modulus() const noexcept { return modulus_; }
    const NTL::ZZ& coefficient(std::size_t index) const;
    NTL::ZZ centered_coefficient(std::size_t index) const;
    const std::vector<NTL::ZZ>& coefficients() const noexcept { return coefficients_; }

    Polynomial operator+(const Polynomial& other) const;
    Polynomial operator-(const Polynomial& other) const;
    Polynomial operator*(const Polynomial& other) const;

    bool operator==(const Polynomial& other) const noexcept;
    bool operator!=(const Polynomial& other) const noexcept { return !(*this == other); }

private:
    std::size_t degree_;
    NTL::ZZ modulus_;
    std::vector<NTL::ZZ> coefficients_;

    static NTL::ZZ canonical_residue(const NTL::ZZ& value, const NTL::ZZ& modulus);
    void require_compatible(const Polynomial& other) const;
};

}  // namespace lattice_lrs::arithmetic
