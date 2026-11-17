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
    src/proofs/protocol2_commitment.cpp
    src/proofs/protocol2_polynomial.cpp
    src/proofs/protocol2_proof.cpp
    src/proofs/protocol2_rejection.cpp
    src/proofs/protocol2_response.cpp
    src/proofs/protocol2_response_lift.cpp
    src/ring_signature/ring_signature.cpp
)
target_include_directories(lattice_lrs_backend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(lattice_lrs_backend PUBLIC NTL::NTL)
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
