#include "lattice_lrs/ring_signature/parameter_profile.hpp"

#include <array>
#include <limits>
#include <stdexcept>

namespace lattice_lrs::ring_signature {
namespace {

NTL::ZZ parse_decimal(const char* digits) {
    NTL::ZZ value(0);
    if (digits == nullptr || *digits == '\0') {
        throw std::invalid_argument("parameter profile modulus is empty");
    }
    for (const char* cursor = digits; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            throw std::invalid_argument(
                "parameter profile modulus must be decimal digits");
        }
        value *= 10;
        value += *cursor - '0';
    }
    return value;
}

NTL::ZZ to_zz(std::size_t value) {
    if (value > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        throw std::length_error("parameter profile dimension exceeds NTL index range");
    }
    return NTL::to_ZZ(static_cast<long>(value));
}

NTL::ZZ integer_power(NTL::ZZ base, std::size_t exponent) {
    NTL::ZZ result(1);
    for (std::size_t i = 0; i < exponent; ++i) result *= base;
    return result;
}

NTL::ZZ ceil_sqrt(const NTL::ZZ& value) {
    if (value < 0) {
        throw std::invalid_argument("cannot take square root of a negative bound");
    }
    NTL::ZZ result;
    NTL::SqrRoot(result, value);
    if (result * result < value) ++result;
    return result;
}

bool is_prime_u64(const NTL::ZZ& value) {
    if (value < 2) return false;
    static const std::array<long, 12> small_primes{
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (long prime : small_primes) {
        const NTL::ZZ p = NTL::to_ZZ(prime);
        if (value == p) return true;
        if (value % p == 0) return false;
    }
    if (value < 2 || !NTL::IsOdd(value)) return false;

    const NTL::ZZ max_u64 = (NTL::ZZ(1) << 64) - 1;
    if (value > max_u64) return false;

    NTL::ZZ odd_part = value - 1;
    long powers_of_two = 0;
    while (!NTL::IsOdd(odd_part)) {
        odd_part /= 2;
        ++powers_of_two;
    }

    // This witness set is deterministic for all unsigned 64-bit integers.
    static const std::array<long, 7> witnesses{
        2, 325, 9375, 28178, 450775, 9780504, 1795265022};
    for (long witness : witnesses) {
        const NTL::ZZ base = NTL::to_ZZ(witness) % value;
        if (base == 0) continue;

        NTL::ZZ residue;
        NTL::PowerMod(residue, base, odd_part, value);
        if (residue == 1 || residue == value - 1) continue;

        bool composite = true;
        for (long round = 1; round < powers_of_two; ++round) {
            residue = (residue * residue) % value;
            if (residue == value - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

}  // namespace

ParameterProfile::ParameterProfile(
    ParameterProfileId id, std::string_view name, std::size_t ring_size,
    std::size_t n, std::size_t m, std::size_t d,
    std::size_t reference_log2_q, std::size_t k, std::size_t beta,
    std::size_t repetitions, const char* q_decimal)
    : id_(id),
      name_(name),
      ring_size_(ring_size),
      n_(n),
      m_(m),
      d_(d),
      reference_log2_q_(reference_log2_q),
      k_(k),
      beta_(beta),
      repetitions_(repetitions),
      v_(k * beta),
      lambda_(128),
      phi1_(22),
      phi2_(22),
      q_(parse_decimal(q_decimal)),
      B_(1) {}

ParameterProfile ParameterProfile::N64() {
    return ParameterProfile(ParameterProfileId::N64, "Esgin Table 3 N=64",
                            64, 5, 13, 256, 50, 2, 8, 16,
                            "1125899906826241");
}

ParameterProfile ParameterProfile::N256() {
    return ParameterProfile(ParameterProfileId::N256, "Esgin Table 3 N=256",
                            256, 5, 13, 256, 53, 2, 16, 16,
                            "9007199254740481");
}

ParameterProfile ParameterProfile::N1024() {
    return ParameterProfile(ParameterProfileId::N1024,
                            "Esgin Table 3 N=1024", 1024, 11, 25, 128,
                            46, 2, 32, 19, "119569584450049");
}

ParameterProfile ParameterProfile::N4096() {
    return ParameterProfile(ParameterProfileId::N4096,
                            "Esgin Table 3 N=4096", 4096, 21, 50, 64, 47,
                            2, 64, 22, "140737488355201");
}

ParameterProfile ParameterProfile::ForRingSize(std::size_t ring_size) {
    switch (ring_size) {
        case 64: return N64();
        case 256: return N256();
        case 1024: return N1024();
        case 4096: return N4096();
        default:
            throw std::invalid_argument(
                "no production parameter profile for the requested ring size");
    }
}

NTL::ZZ ParameterProfile::T1_squared() const {
    const NTL::ZZ d = to_zz(d_);
    const NTL::ZZ k = to_zz(k_);
    const NTL::ZZ beta = to_zz(beta_);
    const NTL::ZZ r = to_zz(repetitions_);
    const NTL::ZZ m = to_zz(m_);
    const NTL::ZZ phi1 = to_zz(phi1_);
    const NTL::ZZ phi2 = to_zz(phi2_);
    const NTL::ZZ first =
        54 * integer_power(phi1, 4) * integer_power(d, 3) *
        integer_power(k, 3) * beta * (beta - 1) * integer_power(r, 2);
    const NTL::ZZ second =
        12 * integer_power(phi2, 2) * integer_power(B_, 2) *
        integer_power(m, 2) * integer_power(d, 2) * r;
    return (2 * d + 2) * (first + second);
}

NTL::ZZ ParameterProfile::T1_upper_bound() const {
    return ceil_sqrt(T1_squared());
}

NTL::ZZ ParameterProfile::T_prime_squared_upper_bound() const {
    const NTL::ZZ factor =
        24 * B_ * to_zz(m_) * to_zz(d_) * (to_zz(k_) + 1) *
        integer_power(to_zz(d_), k_);
    return integer_power(factor, 2) * 3 * to_zz(repetitions_);
}

NTL::ZZ ParameterProfile::T_prime_upper_bound() const {
    return ceil_sqrt(T_prime_squared_upper_bound());
}

commitment::Parameters ParameterProfile::commitment_parameters() const {
    return commitment::Parameters{
        n_, m_, v_, d_, q_, B_,
        commitment::SquaredNormBound(T1_squared(), NTL::ZZ(1))};
}

proofs::Protocol2Parameters ParameterProfile::protocol2_parameters() const {
    const NTL::ZZ one(1);
    return proofs::Protocol2Parameters{
        k_, beta_, proofs::PositiveRational(to_zz(phi1_), one),
        proofs::PositiveRational(to_zz(phi2_), one)};
}

void ParameterProfile::validate() const {
    if (lambda_ != 128 || B_ != 1 || phi1_ != 22 || phi2_ != 22) {
        throw std::invalid_argument(
            "production profile differs from the Section 6/Table 3 values");
    }
    if (n_ == 0 || m_ < n_ || d_ < 7 || k_ == 0 || beta_ < 2 ||
        repetitions_ == 0) {
        throw std::invalid_argument("production profile has invalid dimensions");
    }

    const NTL::ZZ N = to_zz(ring_size_);
    const NTL::ZZ d = to_zz(d_);
    const NTL::ZZ k = to_zz(k_);
    const NTL::ZZ beta = to_zz(beta_);
    const NTL::ZZ repetitions = to_zz(repetitions_);
    const NTL::ZZ m = to_zz(m_);
    if (integer_power(beta, k_) != N || to_zz(v_) != k * beta) {
        throw std::invalid_argument(
            "production profile must satisfy N=beta^k and v=k*beta");
    }
    if (m * d < 86) {
        throw std::invalid_argument(
            "production profile must satisfy m*d >= 86");
    }

    const NTL::ZZ q_lower = NTL::ZZ(1) << (reference_log2_q_ - 1);
    const NTL::ZZ q_upper = NTL::ZZ(1) << (reference_log2_q_ + 1);
    if (q_ < q_lower || q_ >= q_upper) {
        throw std::invalid_argument(
            "selected modulus is not near the paper's rounded log2(q)");
    }
    if (!is_prime_u64(q_) || q_ % (2 * d) != 1) {
        throw std::invalid_argument(
            "selected modulus must be prime and congruent to 1 modulo 2d");
    }

    const NTL::ZZ W = d * k * repetitions * (beta - 1);
    const NTL::ZZ A = 10 * to_zz(phi1_) * d;
    const NTL::ZZ remainder = q_ - A * A * W - 4;
    if (remainder <= 0 ||
        remainder * remainder <= 16 * A * A * W) {
        throw std::invalid_argument(
            "selected modulus fails Section 6 Assumption 1");
    }

    const NTL::ZZ T1_upper = T1_upper_bound();
    const NTL::ZZ T_prime_upper = T_prime_upper_bound();
    if (q_ <= 2 * T1_upper || q_ <= 2 * T_prime_upper) {
        throw std::invalid_argument(
            "selected modulus fails the q-side of the Section 6.1 Eq. (11) binding bound");
    }

    if (T1_upper * T1_upper < T1_squared() ||
        T_prime_upper * T_prime_upper <
            T_prime_squared_upper_bound()) {
        throw std::logic_error("computed binding upper bound is not conservative");
    }
}

}  // namespace lattice_lrs::ring_signature
