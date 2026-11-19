set(_homebrew_prefix "$ENV{HOMEBREW_PREFIX}")
if(NOT _homebrew_prefix)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
        set(_homebrew_prefix "/opt/homebrew")
    else()
        set(_homebrew_prefix "/usr/local")
    endif()
endif()

find_path(GMP_INCLUDE_DIR NAMES gmp.h
    HINTS "${_homebrew_prefix}/opt/gmp/include")
find_library(GMP_LIBRARY NAMES gmp
    HINTS "${_homebrew_prefix}/opt/gmp/lib")
find_path(NTL_INCLUDE_DIR NAMES NTL/ZZ.h
    HINTS "${_homebrew_prefix}/opt/ntl/include")
find_library(NTL_LIBRARY NAMES ntl
    HINTS "${_homebrew_prefix}/opt/ntl/lib")

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY OR NOT NTL_INCLUDE_DIR OR NOT NTL_LIBRARY)
    message(FATAL_ERROR
        "Could not find NTL and GMP. Install them with Homebrew or set their include/library paths.")
endif()

set(DILITHIUM_ROUND3_REF_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../dilithium/upstream-round3/ref")
add_library(lattice_lrs_fips202 STATIC
    "${DILITHIUM_ROUND3_REF_DIR}/fips202.c")
target_include_directories(lattice_lrs_fips202 PRIVATE
    "${DILITHIUM_ROUND3_REF_DIR}")
target_compile_features(lattice_lrs_fips202 PRIVATE c_std_99)

# Dilithium5 (NIST Round 3 submission, DILITHIUM_MODE=5) one-time-signature
# backend for the WCM linkable ring signature OTS wrapper
# (lattice_lrs/ots/dilithium_ots.hpp). fips202.c is deliberately NOT
# recompiled here: it is already built into lattice_lrs_fips202 above, and
# compiling the same global FIPS-202 symbols (shake256, sha3_256, ...) into
# two static libraries linked into the same binary is a duplicate-symbol
# hazard. This mirrors the configuration already validated by the
# LATTICE_LRS_BUILD_DILITHIUM_TESTS experiment in the top-level
# CMakeLists.txt.
add_library(lattice_lrs_dilithium STATIC
    "${DILITHIUM_ROUND3_REF_DIR}/sign.c"
    "${DILITHIUM_ROUND3_REF_DIR}/packing.c"
    "${DILITHIUM_ROUND3_REF_DIR}/polyvec.c"
    "${DILITHIUM_ROUND3_REF_DIR}/poly.c"
    "${DILITHIUM_ROUND3_REF_DIR}/ntt.c"
    "${DILITHIUM_ROUND3_REF_DIR}/reduce.c"
    "${DILITHIUM_ROUND3_REF_DIR}/rounding.c"
    "${DILITHIUM_ROUND3_REF_DIR}/symmetric-shake.c"
    "${DILITHIUM_ROUND3_REF_DIR}/randombytes.c"
)
target_include_directories(lattice_lrs_dilithium PUBLIC
    "${DILITHIUM_ROUND3_REF_DIR}")
target_link_libraries(lattice_lrs_dilithium PUBLIC lattice_lrs_fips202)
target_compile_definitions(lattice_lrs_dilithium PUBLIC DILITHIUM_MODE=5)
target_compile_features(lattice_lrs_dilithium PUBLIC c_std_99)

add_library(GMP::GMP UNKNOWN IMPORTED)
set_target_properties(GMP::GMP PROPERTIES
    IMPORTED_LOCATION "${GMP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}"
)

add_library(NTL::NTL UNKNOWN IMPORTED)
set_target_properties(NTL::NTL PROPERTIES
    IMPORTED_LOCATION "${NTL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${NTL_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES GMP::GMP
)

add_library(lattice_lrs_backend STATIC
    src/arithmetic/polynomial.cpp
    src/arithmetic/matrix.cpp
    src/sampling/random_source.cpp
    src/sampling/sampler.cpp
    src/commitment/commitment.cpp
    src/proofs/bernoulli_exponential.cpp
    src/proofs/bernoulli_pi_exponential.cpp
    src/proofs/binary_proof.cpp
    src/proofs/discrete_gaussian.cpp
    src/proofs/discrete_gaussian_s.cpp
    src/proofs/shake256_auxiliary_commitment.cpp
    src/ring_signature/canonical_rsign_transcript.cpp
    src/proofs/protocol2_commitment.cpp
    src/proofs/protocol2_polynomial.cpp
    src/proofs/protocol2_proof.cpp
    src/proofs/protocol2_rejection.cpp
    src/proofs/protocol2_response.cpp
    src/proofs/protocol2_response_lift.cpp
    src/ring_signature/parameter_profile.cpp
    src/ring_signature/ring_signature.cpp
    src/ring_signature/production_rejection_provider.cpp
    src/ring_signature/production_rsign.cpp
    src/proofs/production_gaussian_provider.cpp
    src/ots/dilithium_ots.cpp
    src/lrs/public_key_mask.cpp
    src/lrs/linkable_ring_signature.cpp
    src/lrs/link.cpp
    src/lrs/production_lrsign.cpp
    src/demo/demo_parameters.cpp
    src/demo/playground_session.cpp
    src/auction/sealed_bid_auction.cpp
    src/lpcom/lpcom.cpp
)
target_include_directories(lattice_lrs_backend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(lattice_lrs_backend PRIVATE
    "${DILITHIUM_ROUND3_REF_DIR}")
target_link_libraries(lattice_lrs_backend PUBLIC NTL::NTL lattice_lrs_fips202
    lattice_lrs_dilithium)
target_compile_features(lattice_lrs_backend PUBLIC cxx_std_17)
if(APPLE)
    target_link_libraries(lattice_lrs_backend PUBLIC "-framework Security")
elseif(WIN32)
    target_link_libraries(lattice_lrs_backend PUBLIC bcrypt)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # getrandom() is provided by glibc on supported Linux systems.
else()
    message(FATAL_ERROR
        "SystemRandomSource supports macOS, Windows, and Linux only.")
endif()
