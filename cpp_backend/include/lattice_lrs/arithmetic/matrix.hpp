#pragma once

#include "lattice_lrs/arithmetic/polynomial.hpp"

#include <cstddef>
#include <vector>

namespace lattice_lrs::arithmetic {

// A dense matrix over the same configurable polynomial ring as Polynomial.
class Matrix {
public:
    Matrix(std::size_t rows, std::size_t columns, std::size_t degree,
           const NTL::ZZ& modulus);
    Matrix(std::size_t rows, std::size_t columns, std::size_t degree,
           const NTL::ZZ& modulus, const std::vector<Polynomial>& entries);

    std::size_t rows() const noexcept { return rows_; }
    std::size_t columns() const noexcept { return columns_; }
    std::size_t degree() const noexcept { return degree_; }
    const NTL::ZZ& modulus() const noexcept { return modulus_; }

    const Polynomial& at(std::size_t row, std::size_t column) const;
    Polynomial& at(std::size_t row, std::size_t column);

    Matrix operator+(const Matrix& other) const;
    Matrix operator-(const Matrix& other) const;
    Matrix operator*(const Matrix& other) const;

    bool operator==(const Matrix& other) const noexcept;
    bool operator!=(const Matrix& other) const noexcept { return !(*this == other); }

private:
    std::size_t rows_;
    std::size_t columns_;
    std::size_t degree_;
    NTL::ZZ modulus_;
    std::vector<Polynomial> entries_;

    std::size_t offset(std::size_t row, std::size_t column) const;
    void require_compatible(const Matrix& other) const;
};

}  // namespace lattice_lrs::arithmetic
