#include "lattice_lrs/sampling/sampler.hpp"

#include <limits>
#include <stdexcept>
#include <vector>

namespace lattice_lrs::sampling {
namespace {

NTL::ZZ sample_uniform_below(const NTL::ZZ& exclusive_upper_bound,
                             RandomSource& random) {
    if (exclusive_upper_bound <= 0) {
        throw std::invalid_argument("exclusive sampling bound must be positive");
    }
    if (exclusive_upper_bound == 1) {
        return NTL::ZZ(0);
    }

    const NTL::ZZ maximum = exclusive_upper_bound - 1;
    const long bit_count = NTL::NumBits(maximum);
    const std::size_t byte_count = static_cast<std::size_t>((bit_count + 7) / 8);
    if (byte_count > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        throw std::length_error("sampling interval is too large");
    }

    std::vector<unsigned char> bytes(byte_count);
    const unsigned int excess_bits = static_cast<unsigned int>(byte_count * 8 - bit_count);
    const unsigned char high_order_byte_mask =
        static_cast<unsigned char>(0xffU >> excess_bits);
    // NTL::ZZFromBytes treats bytes[0] as the LOW-order byte (little-
    // endian), so the mask that trims the excess high bits must be
    // applied to bytes.back() (the HIGH-order byte in that layout), not
    // bytes.front() -- masking the front byte instead (a bug fixed
    // here) left the high-order byte almost always forced to 0 by the
    // rejection check below, collapsing the sampled range to a handful
    // of small values for any modulus that isn't a power of two.
    while (true) {
        random.fill_bytes(bytes.data(), bytes.size());
        bytes.back() &= high_order_byte_mask;
        NTL::ZZ candidate;
        NTL::ZZFromBytes(candidate, bytes.data(), static_cast<long>(bytes.size()));
        if (candidate < exclusive_upper_bound) {
            return candidate;
        }
    }
}

void validate_ring(std::size_t degree, const NTL::ZZ& modulus) {
    if (degree == 0) {
        throw std::invalid_argument("polynomial ring degree must be positive");
    }
    if (modulus <= 1) {
        throw std::invalid_argument("polynomial modulus q must be greater than 1");
    }
}

}  // namespace

NTL::ZZ sample_uniform_coefficient(const NTL::ZZ& modulus, RandomSource& random) {
    if (modulus <= 1) {
        throw std::invalid_argument("uniform coefficient modulus q must be greater than 1");
    }
    return sample_uniform_below(modulus, random);
}

NTL::ZZ sample_bounded_coefficient(const NTL::ZZ& bound, RandomSource& random) {
    if (bound < 0) {
        throw std::invalid_argument("coefficient bound B must be nonnegative");
    }
    if (bound == 0) {
        return NTL::ZZ(0);
    }
    const NTL::ZZ width = 2 * bound + 1;
    return sample_uniform_below(width, random) - bound;
}

arithmetic::Polynomial sample_uniform_polynomial(std::size_t degree,
                                                 const NTL::ZZ& modulus,
                                                 RandomSource& random) {
    validate_ring(degree, modulus);
    std::vector<NTL::ZZ> coefficients(degree);
    for (NTL::ZZ& coefficient : coefficients) {
        coefficient = sample_uniform_coefficient(modulus, random);
    }
    return arithmetic::Polynomial(degree, modulus, coefficients);
}

arithmetic::Polynomial sample_bounded_polynomial(std::size_t degree,
                                                 const NTL::ZZ& modulus,
                                                 const NTL::ZZ& bound,
                                                 RandomSource& random) {
    validate_ring(degree, modulus);
    if (bound < 0) {
        throw std::invalid_argument("coefficient bound B must be nonnegative");
    }
    std::vector<NTL::ZZ> coefficients(degree);
    for (NTL::ZZ& coefficient : coefficients) {
        coefficient = sample_bounded_coefficient(bound, random);
    }
    return arithmetic::Polynomial(degree, modulus, coefficients);
}

PolynomialVector sample_uniform_vector(std::size_t length, std::size_t degree,
                                       const NTL::ZZ& modulus, RandomSource& random) {
    validate_ring(degree, modulus);
    PolynomialVector result;
    result.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(sample_uniform_polynomial(degree, modulus, random));
    }
    return result;
}

PolynomialVector sample_bounded_vector(std::size_t length, std::size_t degree,
                                       const NTL::ZZ& modulus, const NTL::ZZ& bound,
                                       RandomSource& random) {
    validate_ring(degree, modulus);
    if (bound < 0) {
        throw std::invalid_argument("coefficient bound B must be nonnegative");
    }
    PolynomialVector result;
    result.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(sample_bounded_polynomial(degree, modulus, bound, random));
    }
    return result;
}

arithmetic::Matrix sample_uniform_matrix(std::size_t rows, std::size_t columns,
                                         std::size_t degree, const NTL::ZZ& modulus,
                                         RandomSource& random) {
    validate_ring(degree, modulus);
    arithmetic::Matrix result(rows, columns, degree, modulus);
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t column = 0; column < columns; ++column) {
            result.at(row, column) = sample_uniform_polynomial(degree, modulus, random);
        }
    }
    return result;
}

arithmetic::Matrix sample_bounded_matrix(std::size_t rows, std::size_t columns,
                                         std::size_t degree, const NTL::ZZ& modulus,
                                         const NTL::ZZ& bound, RandomSource& random) {
    validate_ring(degree, modulus);
    if (bound < 0) {
        throw std::invalid_argument("coefficient bound B must be nonnegative");
    }
    arithmetic::Matrix result(rows, columns, degree, modulus);
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t column = 0; column < columns; ++column) {
            result.at(row, column) = sample_bounded_polynomial(degree, modulus, bound, random);
        }
    }
    return result;
}

}  // namespace lattice_lrs::sampling
