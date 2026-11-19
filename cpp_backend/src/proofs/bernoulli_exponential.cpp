#include "lattice_lrs/proofs/bernoulli_exponential.hpp"

#include <stdexcept>
#include <utility>

namespace lattice_lrs::proofs {
namespace {

class ExactFraction {
public:
    ExactFraction(NTL::ZZ numerator, NTL::ZZ denominator)
        : numerator_(std::move(numerator)), denominator_(std::move(denominator)) {
        if (denominator_ <= 0 || numerator_ < 0) {
            throw std::invalid_argument("internal rational must be nonnegative with positive denominator");
        }
        normalize();
    }

    const NTL::ZZ& numerator() const noexcept { return numerator_; }
    const NTL::ZZ& denominator() const noexcept { return denominator_; }

private:
    void normalize() {
        if (numerator_ == 0) {
            denominator_ = 1;
            return;
        }
        const NTL::ZZ divisor = NTL::GCD(numerator_, denominator_);
        numerator_ /= divisor;
        denominator_ /= divisor;
    }

    NTL::ZZ numerator_;
    NTL::ZZ denominator_;
};

ExactFraction add(const ExactFraction& left,
                const ExactFraction& right) {
    return ExactFraction(
        left.numerator() * right.denominator() +
            right.numerator() * left.denominator(),
        left.denominator() * right.denominator());
}

ExactFraction subtract(const ExactFraction& left,
                       const ExactFraction& right) {
    if (left.numerator() * right.denominator() <
        right.numerator() * left.denominator()) {
        throw std::logic_error("internal interval arithmetic became negative");
    }
    return ExactFraction(
        left.numerator() * right.denominator() -
            right.numerator() * left.denominator(),
        left.denominator() * right.denominator());
}

ExactFraction multiply(const ExactFraction& left,
                       const ExactFraction& right) {
    return ExactFraction(left.numerator() * right.numerator(),
                         left.denominator() * right.denominator());
}

ExactFraction divide_by_positive_integer(const ExactFraction& value,
                                          const NTL::ZZ& divisor) {
    if (divisor <= 0) {
        throw std::logic_error("internal rational divisor must be positive");
    }
    return ExactFraction(value.numerator(), value.denominator() * divisor);
}

int compare(const ExactFraction& left, const ExactFraction& right) {
    const NTL::ZZ lhs = left.numerator() * right.denominator();
    const NTL::ZZ rhs = right.numerator() * left.denominator();
    return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
}

class RandomBitStream {
public:
    explicit RandomBitStream(sampling::RandomSource& random) : random_(random) {}

    bool next_bit() {
        if (remaining_bits_ == 0) {
            random_.fill_bytes(&byte_, 1);
            remaining_bits_ = 8;
        }
        const bool bit = (byte_ & 0x80U) != 0;
        byte_ = static_cast<std::uint8_t>(byte_ << 1U);
        --remaining_bits_;
        return bit;
    }

private:
    sampling::RandomSource& random_;
    std::uint8_t byte_ = 0;
    unsigned int remaining_bits_ = 0;
};

// Returns an exact Bernoulli(exp(-x)) for rational 0 < x <= 1.
bool sample_unit_interval_exp_coin(const ExactFraction& x,
                                   sampling::RandomSource& random) {
    const ExactFraction one(NTL::ZZ(1), NTL::ZZ(1));
    if (compare(x, one) > 0) {
        throw std::logic_error("unit exponential input exceeds one");
    }
    if (x.numerator() == 0) {
        return true;
    }

    // Alternating-series enclosure, valid because 0 < x <= 1 and the term
    // magnitudes x^n/n! decrease monotonically:
    // S_1 <= exp(-x) <= S_0, S_3 <= exp(-x) <= S_2, ... .
    ExactFraction term = x;
    ExactFraction partial_sum = subtract(one, x);
    ExactFraction exp_lower = partial_sum;
    ExactFraction exp_upper = one;
    NTL::ZZ next_order(2);
    bool next_term_is_positive = true;

    RandomBitStream bits(random);
    ExactFraction uniform_lower(NTL::ZZ(0), NTL::ZZ(1));
    ExactFraction uniform_width(NTL::ZZ(1), NTL::ZZ(1));

    for (;;) {
        const ExactFraction uniform_upper = add(uniform_lower, uniform_width);
        if (compare(uniform_upper, exp_lower) <= 0) {
            return true;
        }
        if (compare(uniform_lower, exp_upper) >= 0) {
            return false;
        }

        const ExactFraction half_width = divide_by_positive_integer(
            uniform_width, NTL::ZZ(2));
        if (bits.next_bit()) {
            uniform_lower = add(uniform_lower, half_width);
        }
        uniform_width = half_width;

        term = divide_by_positive_integer(multiply(term, x), next_order);
        if (next_term_is_positive) {
            partial_sum = add(partial_sum, term);
            exp_upper = partial_sum;
        } else {
            partial_sum = subtract(partial_sum, term);
            exp_lower = partial_sum;
        }
        next_term_is_positive = !next_term_is_positive;
        ++next_order;
    }
}

}  // namespace

bool ExactBernoulliExponentialProvider::sample_exp(
    const NTL::ZZ& log_numerator, const NTL::ZZ& log_denominator,
    sampling::RandomSource& random) {
    if (log_denominator <= 0) {
        throw std::invalid_argument("Bernoulli-exponential denominator must be positive");
    }
    if (log_numerator >= 0) {
        throw std::invalid_argument("Bernoulli-exponential provider requires a negative log probability");
    }

    // For x=-r, use exp(-x)=exp(-floor(x))*exp(-frac(x)). The integer part
    // is a product of exact exp(-1) coins; stop immediately on the first
    // failure. The remaining rational lies in [0,1).
    const NTL::ZZ magnitude = -log_numerator;
    NTL::ZZ whole_units = magnitude / log_denominator;
    const NTL::ZZ remainder = magnitude % log_denominator;
    const ExactFraction one(NTL::ZZ(1), NTL::ZZ(1));

    while (whole_units > 0) {
        if (!sample_unit_interval_exp_coin(one, random)) {
            return false;
        }
        --whole_units;
    }

    if (remainder == 0) {
        return true;
    }
    return sample_unit_interval_exp_coin(
        ExactFraction(remainder, log_denominator), random);
}

}  // namespace lattice_lrs::proofs
