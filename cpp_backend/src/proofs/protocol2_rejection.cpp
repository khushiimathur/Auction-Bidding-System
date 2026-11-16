#include "lattice_lrs/proofs/protocol2_rejection.hpp"

#include <limits>
#include <stdexcept>

namespace lattice_lrs::proofs {
namespace {

std::size_t checked_coefficient_count(std::size_t m, std::size_t degree) {
    if (degree == 0 || m > std::numeric_limits<std::size_t>::max() / degree) {
        throw std::length_error("Protocol 2 rejection dimensions overflow");
    }
    if (m > static_cast<std::size_t>(std::numeric_limits<long>::max()) ||
        degree > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
        throw std::length_error("Protocol 2 rejection dimensions exceed NTL's index range");
    }
    return m * degree;
}

void require_block_size(const std::vector<NTL::ZZ>& block,
                        std::size_t expected_size) {
    if (block.size() != expected_size) {
        throw std::invalid_argument(
            "Protocol 2 rejection blocks must each contain m*d coefficients");
    }
}

}  // namespace

bool AcceptProtocol2JointResponse(
    const commitment::CommitmentKey& key,
    const PositiveRational& phi2,
    const Protocol2JointRejectionInput& input,
    sampling::RandomSource& random,
    BernoulliExponentialProvider& exponential) {
    const commitment::Parameters& parameters = key.parameters();
    parameters.validate();
    if (parameters.B <= 0) {
        throw std::invalid_argument("Protocol 2 rejection bound B must be positive");
    }
    if (phi2.numerator <= 0 || phi2.denominator <= 0) {
        throw std::invalid_argument("Protocol 2 rejection parameter phi2 must be positive");
    }

    const std::size_t coefficient_count =
        checked_coefficient_count(parameters.m, parameters.degree);
    require_block_size(input.z_lift, coefficient_count);
    require_block_size(input.z_b_lift, coefficient_count);
    require_block_size(input.z_c_lift, coefficient_count);
    require_block_size(input.center_z_lift, coefficient_count);
    require_block_size(input.center_z_b_lift, coefficient_count);
    require_block_size(input.center_z_c_lift, coefficient_count);

    const NTL::ZZ m = NTL::to_ZZ(static_cast<long>(parameters.m));
    const NTL::ZZ degree = NTL::to_ZZ(static_cast<long>(parameters.degree));
    const NTL::ZZ K_squared = 3 * parameters.B * parameters.B * m * degree;

    NTL::ZZ inner_product(0);
    NTL::ZZ center_norm_squared(0);
    const std::vector<const std::vector<NTL::ZZ>*> responses{
        &input.z_lift, &input.z_b_lift, &input.z_c_lift};
    const std::vector<const std::vector<NTL::ZZ>*> centers{
        &input.center_z_lift, &input.center_z_b_lift, &input.center_z_c_lift};
    for (std::size_t block = 0; block < responses.size(); ++block) {
        for (std::size_t i = 0; i < coefficient_count; ++i) {
            const NTL::ZZ& z = (*responses[block])[i];
            const NTL::ZZ& c = (*centers[block])[i];
            inner_product += z * c;
            center_norm_squared += c * c;
        }
    }
    if (center_norm_squared > K_squared) {
        throw std::invalid_argument(
            "Protocol 2 rejection center exceeds B*sqrt(3*m*d)");
    }

    const NTL::ZZ p = phi2.numerator;
    const NTL::ZZ t = phi2.denominator;
    const NTL::ZZ exponent_denominator = 2 * p * p * K_squared;
    const NTL::ZZ exponent_numerator =
        -(2 * p * t + t * t) * K_squared +
        t * t * (-2 * inner_product + center_norm_squared);
    if (exponent_numerator >= 0) {
        return true;
    }
    return exponential.sample_exp(exponent_numerator, exponent_denominator, random);
}

}  // namespace lattice_lrs::proofs
