#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <gmp.h>

int main() {
    const NTL::ZZ expected_integer = NTL::to_ZZ("123456789012345678901234567890");
    const NTL::ZZ integer = NTL::to_ZZ("123456789012345678901234567890");
    if (integer != expected_integer) {
        return 1;
    }

    NTL::ZZX polynomial;
    NTL::SetCoeff(polynomial, 0, NTL::to_ZZ(3));
    NTL::SetCoeff(polynomial, 2, NTL::to_ZZ(5));
    if (NTL::deg(polynomial) != 2 || NTL::coeff(polynomial, 2) != NTL::to_ZZ(5)) {
        return 2;
    }

    mpz_t gmp_integer;
    mpz_init(gmp_integer);
    const int parse_result = mpz_set_str(gmp_integer, "97", 10);
    const bool gmp_value_is_correct = parse_result == 0 && mpz_cmp_ui(gmp_integer, 97) == 0;
    mpz_clear(gmp_integer);
    if (!gmp_value_is_correct) {
        return 3;
    }

    return 0;
}
