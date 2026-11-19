#include "lattice_lrs/demo/demo_parameters.hpp"

#include <NTL/ZZ.h>

namespace lattice_lrs::demo {
namespace {
NTL::ZZ z(long value) { return NTL::to_ZZ(value); }
}  // namespace

commitment::Parameters DemoCommitmentParameters() {
    constexpr std::size_t degree = 64;
    constexpr std::size_t n = 1;
    constexpr std::size_t m = 2;
    constexpr std::size_t v = 6;  // k*beta = 3*2
    return commitment::Parameters{
        n, m, v, degree, z(1099511627791LL), z(1),
        commitment::SquaredNormBound(NTL::ZZ(1) << 256, z(1))};
}

proofs::Protocol2Parameters DemoProtocol2Parameters() {
    return proofs::Protocol2Parameters{
        3, 2, proofs::PositiveRational(z(22), z(1)),
        proofs::PositiveRational(z(22), z(1))};
}

}  // namespace lattice_lrs::demo
