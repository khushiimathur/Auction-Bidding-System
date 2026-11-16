#include "lattice_lrs/arithmetic/matrix.hpp"

#include <stdexcept>

namespace lattice_lrs::arithmetic {

Matrix::Matrix(std::size_t rows, std::size_t columns, std::size_t degree,
               const NTL::ZZ& modulus)
    : rows_(rows), columns_(columns), degree_(degree), modulus_(modulus),
      entries_(rows * columns, Polynomial(degree, modulus)) {}

Matrix::Matrix(std::size_t rows, std::size_t columns, std::size_t degree,
               const NTL::ZZ& modulus, const std::vector<Polynomial>& entries)
    : Matrix(rows, columns, degree, modulus) {
    if (entries.size() != entries_.size()) {
        throw std::invalid_argument("matrix entry count does not match its dimensions");
    }
    for (const Polynomial& entry : entries) {
        if (entry.degree() != degree_ || entry.modulus() != modulus_) {
            throw std::invalid_argument("matrix entries must use the matrix degree and modulus");
        }
    }
    entries_ = entries;
}

const Polynomial& Matrix::at(std::size_t row, std::size_t column) const {
    return entries_.at(offset(row, column));
}

Polynomial& Matrix::at(std::size_t row, std::size_t column) {
    return entries_.at(offset(row, column));
}

Matrix Matrix::operator+(const Matrix& other) const {
    require_compatible(other);
    Matrix result(rows_, columns_, degree_, modulus_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        result.entries_[i] = entries_[i] + other.entries_[i];
    }
    return result;
}

Matrix Matrix::operator-(const Matrix& other) const {
    require_compatible(other);
    Matrix result(rows_, columns_, degree_, modulus_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        result.entries_[i] = entries_[i] - other.entries_[i];
    }
    return result;
}

Matrix Matrix::operator*(const Matrix& other) const {
    if (columns_ != other.rows_) {
        throw std::invalid_argument("matrix multiplication dimensions do not match");
    }
    if (degree_ != other.degree_ || modulus_ != other.modulus_) {
        throw std::invalid_argument("matrix operands must use the same degree and modulus");
    }
    Matrix result(rows_, other.columns_, degree_, modulus_);
    for (std::size_t row = 0; row < rows_; ++row) {
        for (std::size_t column = 0; column < other.columns_; ++column) {
            Polynomial sum(degree_, modulus_);
            for (std::size_t inner = 0; inner < columns_; ++inner) {
                sum = sum + at(row, inner) * other.at(inner, column);
            }
            result.at(row, column) = sum;
        }
    }
    return result;
}

bool Matrix::operator==(const Matrix& other) const noexcept {
    return rows_ == other.rows_ && columns_ == other.columns_ &&
           degree_ == other.degree_ && modulus_ == other.modulus_ &&
           entries_ == other.entries_;
}

std::size_t Matrix::offset(std::size_t row, std::size_t column) const {
    if (row >= rows_ || column >= columns_) {
        throw std::out_of_range("matrix index out of range");
    }
    return row * columns_ + column;
}

void Matrix::require_compatible(const Matrix& other) const {
    if (rows_ != other.rows_ || columns_ != other.columns_ ||
        degree_ != other.degree_ || modulus_ != other.modulus_) {
        throw std::invalid_argument("matrix operands must have matching dimensions and ring");
    }
}

}  // namespace lattice_lrs::arithmetic
