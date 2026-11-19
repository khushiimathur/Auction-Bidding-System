#include "lattice_lrs/proofs/bernoulli_pi_exponential.hpp"

#include <cstdint>
#include <stdexcept>
#include <utility>

namespace lattice_lrs::proofs {
namespace {

class ExactFraction {
public:
    ExactFraction(NTL::ZZ numerator, NTL::ZZ denominator)
        : numerator_(std::move(numerator)), denominator_(std::move(denominator)) {
        if (numerator_ < 0 || denominator_ <= 0) {
            throw std::invalid_argument(
                "internal fraction must be nonnegative with positive denominator");
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

struct RationalInterval {
    ExactFraction lower;
    ExactFraction upper;
};

ExactFraction add(const ExactFraction& left, const ExactFraction& right) {
    return ExactFraction(
        left.numerator() * right.denominator() +
            right.numerator() * left.denominator(),
        left.denominator() * right.denominator());
}

ExactFraction subtract(const ExactFraction& left, const ExactFraction& right) {
    if (left.numerator() * right.denominator() <
        right.numerator() * left.denominator()) {
        throw std::logic_error("internal interval arithmetic became negative");
    }
    return ExactFraction(
        left.numerator() * right.denominator() -
            right.numerator() * left.denominator(),
        left.denominator() * right.denominator());
}

ExactFraction multiply(const ExactFraction& left, const ExactFraction& right) {
    return ExactFraction(left.numerator() * right.numerator(),
                         left.denominator() * right.denominator());
}

ExactFraction multiply_by_integer(const ExactFraction& value,
                                 const NTL::ZZ& multiplier) {
    if (multiplier < 0) {
        throw std::logic_error("internal fraction multiplier must be nonnegative");
    }
    return ExactFraction(value.numerator() * multiplier, value.denominator());
}

ExactFraction divide_by_integer(const ExactFraction& value,
                                const NTL::ZZ& divisor) {
    if (divisor <= 0) {
        throw std::logic_error("internal fraction divisor must be positive");
    }
    return ExactFraction(value.numerator(), value.denominator() * divisor);
}

int compare(const ExactFraction& left, const ExactFraction& right) {
    const NTL::ZZ lhs = left.numerator() * right.denominator();
    const NTL::ZZ rhs = right.numerator() * left.denominator();
    return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
}

RationalInterval arctan_reciprocal_bounds(const NTL::ZZ& reciprocal,
                                          const NTL::ZZ& term_count) {
    if (reciprocal <= 1 || term_count < 2 || NTL::IsOdd(term_count)) {
        throw std::logic_error("invalid arctangent interval parameters");
    }

    const NTL::ZZ reciprocal_squared = reciprocal * reciprocal;
    NTL::ZZ odd_denominator(1);
    ExactFraction term(NTL::ZZ(1), reciprocal);
    ExactFraction partial_sum(NTL::ZZ(0), NTL::ZZ(1));

    for (NTL::ZZ index(0); index < term_count; ++index) {
        partial_sum = NTL::IsOdd(index) ? subtract(partial_sum, term)
                                        : add(partial_sum, term);
        term = divide_by_integer(
            multiply_by_integer(term, odd_denominator),
            (odd_denominator + 2) * reciprocal_squared);
        odd_denominator += 2;
    }

    // An even number of alternating terms ends below arctan(1/reciprocal).
    return {partial_sum, add(partial_sum, term)};
}

RationalInterval pi_bounds(const NTL::ZZ& even_term_count) {
    // Machin's identity: pi = 16*atan(1/5) - 4*atan(1/239).
    const RationalInterval atan_five =
        arctan_reciprocal_bounds(NTL::ZZ(5), even_term_count);
    const RationalInterval atan_239 =
        arctan_reciprocal_bounds(NTL::ZZ(239), even_term_count);
    const ExactFraction lower = subtract(
        multiply_by_integer(atan_five.lower, NTL::ZZ(16)),
        multiply_by_integer(atan_239.upper, NTL::ZZ(4)));
    const ExactFraction upper = subtract(
        multiply_by_integer(atan_five.upper, NTL::ZZ(16)),
        multiply_by_integer(atan_239.lower, NTL::ZZ(4)));

    if (compare(lower, ExactFraction(NTL::ZZ(3), NTL::ZZ(1))) <= 0 ||
        compare(upper, ExactFraction(NTL::ZZ(4), NTL::ZZ(1))) >= 0 ||
        compare(lower, upper) > 0) {
        throw std::logic_error("certified pi interval failed its range check");
    }
    return {lower, upper};
}

RationalInterval exp_neg_unit_interval_bounds(const ExactFraction& x,
                                              const NTL::ZZ& even_order) {
    const ExactFraction one(NTL::ZZ(1), NTL::ZZ(1));
    if (compare(x, one) > 0 || even_order < 2 || NTL::IsOdd(even_order)) {
        throw std::logic_error("invalid exponential interval parameters");
    }

    ExactFraction term(NTL::ZZ(1), NTL::ZZ(1));
    ExactFraction partial_sum = term;
    for (NTL::ZZ order(1); order <= even_order; ++order) {
        term = divide_by_integer(multiply(term, x), order);
        partial_sum = NTL::IsOdd(order) ? subtract(partial_sum, term)
                                        : add(partial_sum, term);
    }
    const ExactFraction next_term =
        divide_by_integer(multiply(term, x), even_order + 1);

    // The alternating Taylor terms decrease for 0 <= x <= 1.
    return {subtract(partial_sum, next_term), partial_sum};
}

ExactFraction fourth_power(const ExactFraction& value) {
    const ExactFraction square = multiply(value, value);
    return multiply(square, square);
}

RationalInterval exp_neg_pi_fraction_bounds(const ExactFraction& t,
                                            const NTL::ZZ& precision) {
    const NTL::ZZ terms = 2 * precision;
    const RationalInterval pi = pi_bounds(terms);
    const ExactFraction x_lower =
        divide_by_integer(multiply(pi.lower, t), NTL::ZZ(4));
    const ExactFraction x_upper =
        divide_by_integer(multiply(pi.upper, t), NTL::ZZ(4));
    if (compare(x_upper, ExactFraction(NTL::ZZ(1), NTL::ZZ(1))) >= 0) {
        throw std::logic_error("range-reduced exponential input must be below one");
    }

    const RationalInterval lower_endpoint =
        exp_neg_unit_interval_bounds(x_upper, terms);
    const RationalInterval upper_endpoint =
        exp_neg_unit_interval_bounds(x_lower, terms);
    return {fourth_power(lower_endpoint.lower),
            fourth_power(upper_endpoint.upper)};
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

bool sample_unit_pi_exponential(const ExactFraction& t,
                                sampling::RandomSource& random) {
    const ExactFraction one(NTL::ZZ(1), NTL::ZZ(1));
    if (t.numerator() == 0) return true;
    if (compare(t, one) > 0) {
        throw std::logic_error("unit pi-exponential input exceeds one");
    }

    RandomBitStream bits(random);
    ExactFraction uniform_lower(NTL::ZZ(0), NTL::ZZ(1));
    ExactFraction uniform_width(NTL::ZZ(1), NTL::ZZ(1));
    NTL::ZZ precision(1);

    for (;;) {
        const RationalInterval probability =
            exp_neg_pi_fraction_bounds(t, precision);
        const ExactFraction uniform_upper = add(uniform_lower, uniform_width);
        if (compare(uniform_upper, probability.lower) <= 0) {
            return true;
        }
        if (compare(uniform_lower, probability.upper) >= 0) {
            return false;
        }

        const ExactFraction half_width =
            divide_by_integer(uniform_width, NTL::ZZ(2));
        if (bits.next_bit()) {
            uniform_lower = add(uniform_lower, half_width);
        }
        uniform_width = half_width;
        ++precision;
    }
}

}  // namespace

bool ExactBernoulliPiExponentialProvider::sample_exp_neg_pi_rational(
    const NTL::ZZ& t_numerator, const NTL::ZZ& t_denominator,
    sampling::RandomSource& random) {
    if (t_numerator < 0 || t_denominator <= 0) {
        throw std::invalid_argument(
            "pi-exponential input must be a nonnegative rational");
    }
    if (t_numerator == 0) return true;

    NTL::ZZ whole_units = t_numerator / t_denominator;
    const NTL::ZZ remainder = t_numerator % t_denominator;
    const ExactFraction one(NTL::ZZ(1), NTL::ZZ(1));
    while (whole_units > 0) {
        if (!sample_unit_pi_exponential(one, random)) return false;
        --whole_units;
    }
    if (remainder == 0) return true;

    return sample_unit_pi_exponential(
        ExactFraction(remainder, t_denominator), random);
}

}  // namespace lattice_lrs::proofs
