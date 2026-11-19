#pragma once

#include "lattice_lrs/commitment/commitment.hpp"
#include "lattice_lrs/proofs/protocol2_proof.hpp"

#include <cstddef>
#include <string_view>

namespace lattice_lrs::ring_signature {

enum class ParameterProfileId {
    N64,
    N256,
    N1024,
    N4096,
};

class ParameterProfile final {
public:
    static ParameterProfile N64();
    static ParameterProfile N256();
    static ParameterProfile N1024();
    static ParameterProfile N4096();
    static ParameterProfile ForRingSize(std::size_t ring_size);

    ParameterProfileId id() const noexcept { return id_; }
    std::string_view name() const noexcept { return name_; }
    std::size_t ring_size() const noexcept { return ring_size_; }
    std::size_t n() const noexcept { return n_; }
    std::size_t m() const noexcept { return m_; }
    std::size_t d() const noexcept { return d_; }
    std::size_t reference_log2_q() const noexcept {
        return reference_log2_q_;
    }
    std::size_t k() const noexcept { return k_; }
    std::size_t beta() const noexcept { return beta_; }
    std::size_t repetitions() const noexcept { return repetitions_; }
    std::size_t v() const noexcept { return v_; }
    std::size_t lambda() const noexcept { return lambda_; }
    const NTL::ZZ& q() const noexcept { return q_; }
    const NTL::ZZ& B() const noexcept { return B_; }
    std::size_t phi1() const noexcept { return phi1_; }
    std::size_t phi2() const noexcept { return phi2_; }

    NTL::ZZ T1_squared() const;
    NTL::ZZ T1_upper_bound() const;
    NTL::ZZ T_prime_squared_upper_bound() const;
    NTL::ZZ T_prime_upper_bound() const;
    commitment::Parameters commitment_parameters() const;
    proofs::Protocol2Parameters protocol2_parameters() const;

    void validate() const;

private:
    ParameterProfile(ParameterProfileId id, std::string_view name,
                     std::size_t ring_size, std::size_t n, std::size_t m,
                     std::size_t d, std::size_t reference_log2_q,
                     std::size_t k, std::size_t beta,
                     std::size_t repetitions, const char* q_decimal);

    ParameterProfileId id_;
    std::string_view name_;
    std::size_t ring_size_;
    std::size_t n_;
    std::size_t m_;
    std::size_t d_;
    std::size_t reference_log2_q_;
    std::size_t k_;
    std::size_t beta_;
    std::size_t repetitions_;
    std::size_t v_;
    std::size_t lambda_;
    std::size_t phi1_;
    std::size_t phi2_;
    NTL::ZZ q_;
    NTL::ZZ B_;
};

}  // namespace lattice_lrs::ring_signature
