#pragma once

#include "lattice_lrs/arithmetic/matrix.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

#include <cstddef>
#include <vector>

namespace lattice_lrs::sampling {

using PolynomialVector = std::vector<arithmetic::Polynomial>;

NTL::ZZ sample_uniform_coefficient(const NTL::ZZ& modulus, RandomSource& random);
NTL::ZZ sample_bounded_coefficient(const NTL::ZZ& bound, RandomSource& random);

arithmetic::Polynomial sample_uniform_polynomial(std::size_t degree,
                                                 const NTL::ZZ& modulus,
                                                 RandomSource& random);
arithmetic::Polynomial sample_bounded_polynomial(std::size_t degree,
                                                 const NTL::ZZ& modulus,
                                                 const NTL::ZZ& bound,
                                                 RandomSource& random);

PolynomialVector sample_uniform_vector(std::size_t length, std::size_t degree,
                                       const NTL::ZZ& modulus, RandomSource& random);
PolynomialVector sample_bounded_vector(std::size_t length, std::size_t degree,
                                       const NTL::ZZ& modulus, const NTL::ZZ& bound,
                                       RandomSource& random);

arithmetic::Matrix sample_uniform_matrix(std::size_t rows, std::size_t columns,
                                         std::size_t degree, const NTL::ZZ& modulus,
                                         RandomSource& random);
arithmetic::Matrix sample_bounded_matrix(std::size_t rows, std::size_t columns,
                                         std::size_t degree, const NTL::ZZ& modulus,
                                         const NTL::ZZ& bound, RandomSource& random);

}  // namespace lattice_lrs::sampling
