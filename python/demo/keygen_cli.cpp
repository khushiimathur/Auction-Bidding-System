#include "lattice_lrs/ring_signature/ring_signature.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <NTL/ZZ.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

class UnavailableHashToChallenges final
    : public lattice_lrs::ring_signature::HashToChallenges {
public:
    lattice_lrs::ring_signature::ChallengeVector hash(
        const std::vector<std::uint8_t>&,
        const lattice_lrs::ring_signature::ChallengeSet&,
        std::size_t) const override {
        throw std::runtime_error(
            "hash-to-challenges is not configured; RSign/RVerify are unavailable");
    }
};

std::string to_hex(const NTL::ZZ& value) {
    const long signed_value = NTL::conv<long>(value);
    const bool negative = signed_value < 0;
    const unsigned long magnitude = negative
        ? static_cast<unsigned long>(-(signed_value + 1)) + 1
        : static_cast<unsigned long>(signed_value);
    std::ostringstream stream;
    if (negative) stream << '-';
    stream << "0x" << std::hex << magnitude;
    return stream.str();
}

void write_polynomial_vector(
    std::ostream& output,
    const lattice_lrs::sampling::PolynomialVector& vector,
    bool centered) {
    output << '[';
    for (std::size_t polynomial_index = 0;
         polynomial_index < vector.size(); ++polynomial_index) {
        if (polynomial_index != 0) output << ',';
        output << '[';
        const auto& polynomial = vector[polynomial_index];
        for (std::size_t coefficient_index = 0;
             coefficient_index < polynomial.degree(); ++coefficient_index) {
            if (coefficient_index != 0) output << ',';
            const NTL::ZZ coefficient = centered
                ? polynomial.centered_coefficient(coefficient_index)
                : polynomial.coefficient(coefficient_index);
            output << '"' << to_hex(coefficient) << '"';
        }
        output << ']';
    }
    output << ']';
}

std::size_t bidder_count(int argc, char** argv) {
    if (argc == 1) return 5;
    if (argc != 2) {
        throw std::invalid_argument("usage: lrs_keygen_cli [bidder-count 1..5]");
    }
    std::size_t parsed = 0;
    const std::string argument(argv[1]);
    const unsigned long value = std::stoul(argument, &parsed);
    if (parsed != argument.size() || value < 1 || value > 5) {
        throw std::invalid_argument("bidder count must be between 1 and 5");
    }
    return static_cast<std::size_t>(value);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::size_t count = bidder_count(argc, argv);
        using namespace lattice_lrs;
        const ring_signature::SetupParameters setup{
            commitment::Parameters{
                1, 2, 1, 3, NTL::to_ZZ(101), NTL::to_ZZ(3),
                commitment::SquaredNormBound(NTL::to_ZZ(100000), NTL::to_ZZ(1))},
            1};
        auto hash = std::make_shared<UnavailableHashToChallenges>();
        sampling::SystemRandomSource random;
        const ring_signature::PublicParameters public_parameters =
            ring_signature::RSetup(setup, std::move(hash), random);

        std::cout << "{\"parameters\":{\"n\":1,\"m\":2,\"v\":1,"
                     "\"degree\":3,\"q\":\"0x65\",\"B\":\"0x3\","
                     "\"security\":\"demo-only\"},\"bidders\":[";
        for (std::size_t index = 0; index < count; ++index) {
            if (index != 0) std::cout << ',';
            const ring_signature::KeyPair key_pair =
                ring_signature::RKeygen(public_parameters, random);
            std::cout << "{\"id\":\"B" << index + 1
                      << "\",\"public_key\":";
            write_polynomial_vector(std::cout, key_pair.public_key.commitment, false);
            std::cout << ",\"private_key\":";
            write_polynomial_vector(std::cout, key_pair.secret_key.randomness, true);
            std::cout << '}';
        }
        std::cout << "]}\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "key generation failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
