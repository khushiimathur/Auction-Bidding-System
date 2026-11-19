#include "lattice_lrs/lpcom/lpcom.hpp"

#include "lattice_lrs/sampling/sampler.hpp"

#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_p.h>

#include <stdexcept>

namespace lattice_lrs::lpcom {
namespace {

NTL::ZZ mod_normalize(const NTL::ZZ& value, const NTL::ZZ& modulus) {
    NTL::ZZ reduced = value % modulus;
    if (reduced < 0) reduced += modulus;
    return reduced;
}

// Centers a value already known to be in [0, q) to the representative
// of least absolute value in (-q/2, q/2]. This is what lets Unv recover
// a SIGNED error coordinate from a commitment that only carries values
// mod q.
NTL::ZZ centered_representative(const NTL::ZZ& value_mod_q,
                                const NTL::ZZ& q) {
    NTL::ZZ half = q / 2;
    if (value_mod_q > half) return value_mod_q - q;
    return value_mod_q;
}

Matrix sample_uniform_matrix_plain(std::size_t rows, std::size_t columns,
                                   const NTL::ZZ& q,
                                   sampling::RandomSource& random) {
    Matrix matrix(rows, Vector(columns));
    for (std::size_t i = 0; i < rows; ++i) {
        for (std::size_t j = 0; j < columns; ++j) {
            matrix[i][j] = sampling::sample_uniform_coefficient(q, random);
        }
    }
    return matrix;
}

// Rank of [A1 | A2] over the FIELD Z_q (q prime, checked by the caller).
// Full column rank (rank == n + k) is equivalent to [A1 | A2] having
// trivial kernel mod q, which is exactly what GenCom's sampling
// condition requires -- this computes that property rather than
// assuming it holds for a random draw.
long combined_rank_mod_q(const Matrix& a1, const Matrix& a2,
                         std::size_t m, std::size_t n, std::size_t k,
                         const NTL::ZZ& q) {
    // ZZ_pPush saves the CALLER's current ZZ_p context (if any) and
    // restores it when this scope ends, then we initialize a fresh
    // modulus q for this computation only -- this keeps the rank check
    // from depending on, or disturbing, any ZZ_p state a caller
    // elsewhere in the process might have active.
    NTL::ZZ_pPush push;
    NTL::ZZ_p::init(q);

    NTL::mat_ZZ_p matrix;
    matrix.SetDims(static_cast<long>(m), static_cast<long>(n + k));
    for (std::size_t row = 0; row < m; ++row) {
        for (std::size_t col = 0; col < n; ++col) {
            matrix[static_cast<long>(row)][static_cast<long>(col)] =
                NTL::conv<NTL::ZZ_p>(a1[row][col]);
        }
        for (std::size_t col = 0; col < k; ++col) {
            matrix[static_cast<long>(row)][static_cast<long>(n + col)] =
                NTL::conv<NTL::ZZ_p>(a2[row][col]);
        }
    }
    return NTL::gauss(matrix);
}

void validate_vector_in_range(const Vector& values, std::size_t expected_size,
                              const NTL::ZZ& q, const char* name) {
    if (values.size() != expected_size) {
        throw std::invalid_argument(
            std::string(name) + " has the wrong dimension");
    }
    for (const NTL::ZZ& value : values) {
        if (value < 0 || value >= q) {
            throw std::invalid_argument(
                std::string(name) + " has a coordinate outside [0, q)");
        }
    }
}

}  // namespace

Parameters GenCom(std::size_t n, std::size_t k, std::size_t m,
                   const NTL::ZZ& q,
                   const NTL::ZZ& sigma_squared_numerator,
                   const NTL::ZZ& sigma_squared_denominator,
                   const NTL::ZZ& B, sampling::RandomSource& random,
                   std::size_t max_attempts) {
    if (n == 0 || k == 0 || m == 0) {
        throw std::invalid_argument("GenCom: n, k, m must all be positive");
    }
    if (m < n + k) {
        throw std::invalid_argument(
            "GenCom: m must be at least n + k for [A1|A2] to possibly have "
            "trivial kernel mod a prime q");
    }
    if (q <= 1 || NTL::ProbPrime(q) == 0) {
        throw std::invalid_argument(
            "GenCom: q must be prime (required by this implementation's "
            "exact rank-based trivial-kernel validation)");
    }
    if (sigma_squared_numerator <= 0 || sigma_squared_denominator <= 0) {
        throw std::invalid_argument(
            "GenCom: sigma^2 must be a positive rational");
    }
    if (B <= 0) {
        throw std::invalid_argument("GenCom: B must be positive");
    }

    for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
        Matrix a1 = sample_uniform_matrix_plain(m, n, q, random);
        Matrix a2 = sample_uniform_matrix_plain(m, k, q, random);
        const long rank = combined_rank_mod_q(a1, a2, m, n, k, q);
        if (rank == static_cast<long>(n + k)) {
            Parameters parameters;
            parameters.n = n;
            parameters.k = k;
            parameters.m = m;
            parameters.q = q;
            parameters.sigma_squared_numerator = sigma_squared_numerator;
            parameters.sigma_squared_denominator = sigma_squared_denominator;
            parameters.B = B;
            parameters.A1 = std::move(a1);
            parameters.A2 = std::move(a2);
            return parameters;
        }
    }
    throw std::runtime_error(
        "GenCom: failed to sample [A1|A2] with trivial kernel mod q within "
        "max_attempts; this is a genuine failure, not something this "
        "function will paper over by accepting a degenerate A");
}

ComResult Com(const Parameters& params, const Vector& v,
               proofs::DiscreteGaussianSProvider& gaussian,
               sampling::RandomSource& random) {
    validate_vector_in_range(v, params.n, params.q, "Com: v");

    Vector r(params.k);
    for (NTL::ZZ& coordinate : r) {
        coordinate = sampling::sample_uniform_coefficient(params.q, random);
    }

    Vector e(params.m);
    for (NTL::ZZ& coordinate : e) {
        coordinate = gaussian.sample_coefficient_from_scale_squared(
            params.sigma_squared_numerator, params.sigma_squared_denominator,
            random);
    }

    Vector c(params.m);
    for (std::size_t row = 0; row < params.m; ++row) {
        NTL::ZZ accumulator = e[row];
        for (std::size_t col = 0; col < params.n; ++col) {
            accumulator += params.A1[row][col] * v[col];
        }
        for (std::size_t col = 0; col < params.k; ++col) {
            accumulator += params.A2[row][col] * r[col];
        }
        c[row] = mod_normalize(accumulator, params.q);
    }

    ComResult result;
    result.commitment.c = std::move(c);
    result.opening.v = v;
    result.opening.r = std::move(r);
    return result;
}

bool Unv(const Parameters& params, const Commitment& commitment,
          const Vector& v, const Vector& r) {
    validate_vector_in_range(commitment.c, params.m, params.q, "Unv: c");
    validate_vector_in_range(v, params.n, params.q, "Unv: v");
    validate_vector_in_range(r, params.k, params.q, "Unv: r");

    NTL::ZZ squared_norm(0);
    for (std::size_t row = 0; row < params.m; ++row) {
        NTL::ZZ accumulator = commitment.c[row];
        for (std::size_t col = 0; col < params.n; ++col) {
            accumulator -= params.A1[row][col] * v[col];
        }
        for (std::size_t col = 0; col < params.k; ++col) {
            accumulator -= params.A2[row][col] * r[col];
        }
        const NTL::ZZ error_coordinate =
            centered_representative(mod_normalize(accumulator, params.q),
                                    params.q);
        squared_norm += error_coordinate * error_coordinate;
    }

    return squared_norm <= params.B * params.B;
}

Parameters ExperimentalDemoParameters(sampling::RandomSource& random) {
    // k = 16 = 2^4, chosen so sigma^2 = k^2.5 = 2^10 = 1024 is an EXACT
    // integer (see the header comment: the exact D_s sampler needs an
    // exact rational scale-squared). n = k, m = 3k, per the paper's
    // Figure 2 asymptotic shape.
    const std::size_t k = 16;
    const std::size_t n = k;
    const std::size_t m = 3 * k;

    // Nearest prime to k^2 = 256.
    const NTL::ZZ q = NTL::to_ZZ(257);

    const NTL::ZZ sigma_squared_numerator = NTL::to_ZZ(1024);  // = 32^2
    const NTL::ZZ sigma_squared_denominator = NTL::to_ZZ(1);

    // B = ceil(sqrt(m) * sigma) = ceil(sqrt(48) * 32) = ceil(221.70...) = 222.
    const NTL::ZZ B = NTL::to_ZZ(222);

    return GenCom(n, k, m, q, sigma_squared_numerator,
                 sigma_squared_denominator, B, random);
}

Parameters ScalarMessageDemoParameters(sampling::RandomSource& random) {
    const std::size_t n = 1;
    const std::size_t k = 16;
    const std::size_t m = 24;  // >= n + k = 17

    const NTL::ZZ q = NTL::to_ZZ(257);
    const NTL::ZZ sigma_squared_numerator = NTL::to_ZZ(1024);  // = 32^2
    const NTL::ZZ sigma_squared_denominator = NTL::to_ZZ(1);

    // B = ceil(sqrt(24) * 32) = ceil(156.77...) = 157.
    const NTL::ZZ B = NTL::to_ZZ(157);

    return GenCom(n, k, m, q, sigma_squared_numerator,
                 sigma_squared_denominator, B, random);
}

}  // namespace lattice_lrs::lpcom
