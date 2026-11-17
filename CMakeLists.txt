cmake_minimum_required(VERSION 3.16)

project(Lattice_LRS LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

add_subdirectory(cpp_backend)

add_executable(cpp_build_smoke tests/test_cpp_build.cpp)
target_link_libraries(cpp_build_smoke PRIVATE lattice_lrs_backend)
add_test(NAME cpp_build_smoke COMMAND cpp_build_smoke)

add_executable(ntl_gmp_integration tests/test_ntl_gmp_integration.cpp)
target_link_libraries(ntl_gmp_integration PRIVATE lattice_lrs_backend)
add_test(NAME ntl_gmp_integration COMMAND ntl_gmp_integration)

add_executable(polynomial_matrix_arithmetic_test
    tests/test_polynomial_matrix_arithmetic.cpp)
target_link_libraries(polynomial_matrix_arithmetic_test PRIVATE lattice_lrs_backend)
add_test(NAME polynomial_matrix_arithmetic_test
    COMMAND polynomial_matrix_arithmetic_test)

add_executable(sampling_commitment_test tests/test_sampling_commitment.cpp)
target_link_libraries(sampling_commitment_test PRIVATE lattice_lrs_backend)
add_test(NAME sampling_commitment_test COMMAND sampling_commitment_test)

add_executable(random_source_platform_helpers_test
    tests/test_random_source_platform_helpers.cpp)
target_include_directories(random_source_platform_helpers_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/cpp_backend/src")
target_compile_features(random_source_platform_helpers_test PRIVATE cxx_std_17)
add_test(NAME random_source_platform_helpers_test
    COMMAND random_source_platform_helpers_test)

add_executable(binary_proof_test tests/test_binary_proof.cpp)
target_link_libraries(binary_proof_test PRIVATE lattice_lrs_backend)
add_test(NAME binary_proof_test COMMAND binary_proof_test)

add_executable(bernoulli_exponential_test tests/test_bernoulli_exponential.cpp)
target_link_libraries(bernoulli_exponential_test PRIVATE lattice_lrs_backend)
add_test(NAME bernoulli_exponential_test COMMAND bernoulli_exponential_test)

add_executable(discrete_gaussian_test tests/test_discrete_gaussian.cpp)
target_link_libraries(discrete_gaussian_test PRIVATE lattice_lrs_backend)
add_test(NAME discrete_gaussian_test COMMAND discrete_gaussian_test)

add_executable(discrete_gaussian_s_test tests/test_discrete_gaussian_s.cpp)
target_link_libraries(discrete_gaussian_s_test PRIVATE lattice_lrs_backend)
add_test(NAME discrete_gaussian_s_test COMMAND discrete_gaussian_s_test)

add_executable(protocol2_polynomial_expansion_test
    tests/test_protocol2_polynomial_expansion.cpp)
target_link_libraries(protocol2_polynomial_expansion_test PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_polynomial_expansion_test
    COMMAND protocol2_polynomial_expansion_test)

add_executable(protocol2_commitment_test tests/test_protocol2_commitment.cpp)
target_link_libraries(protocol2_commitment_test PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_commitment_test COMMAND protocol2_commitment_test)

add_executable(protocol2_z_test tests/test_protocol2_z.cpp)
target_link_libraries(protocol2_z_test PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_z_test COMMAND protocol2_z_test)

add_executable(protocol2_rejection_test tests/test_protocol2_rejection.cpp)
target_link_libraries(protocol2_rejection_test PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_rejection_test COMMAND protocol2_rejection_test)

add_executable(protocol2_response_lift_test
    tests/test_protocol2_response_lift.cpp)
target_link_libraries(protocol2_response_lift_test PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_response_lift_test
    COMMAND protocol2_response_lift_test)

add_executable(protocol2_response_rejection_integration_test
    tests/test_protocol2_response_rejection_integration.cpp)
target_link_libraries(protocol2_response_rejection_integration_test
    PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_response_rejection_integration_test
    COMMAND protocol2_response_rejection_integration_test)

add_executable(protocol2_proof_test tests/test_protocol2_proof.cpp)
target_link_libraries(protocol2_proof_test PRIVATE lattice_lrs_backend)
add_test(NAME protocol2_proof_test COMMAND protocol2_proof_test)

add_executable(ring_signature_setup_keygen_test
    tests/test_ring_signature_setup_keygen.cpp)
target_link_libraries(ring_signature_setup_keygen_test PRIVATE lattice_lrs_backend)
add_test(NAME ring_signature_setup_keygen_test
    COMMAND ring_signature_setup_keygen_test)

add_executable(rsign_batch_test tests/test_rsign_batch.cpp)
target_link_libraries(rsign_batch_test PRIVATE lattice_lrs_backend)
add_test(NAME rsign_batch_test COMMAND rsign_batch_test)

add_executable(parameter_profile_test tests/test_parameter_profile.cpp)
target_link_libraries(parameter_profile_test PRIVATE lattice_lrs_backend)
add_test(NAME parameter_profile_test COMMAND parameter_profile_test)

option(LATTICE_LRS_BUILD_DILITHIUM_TESTS
    "Build isolated tests against both official Dilithium reference implementations"
    OFF
)

if(LATTICE_LRS_BUILD_DILITHIUM_TESTS)
    enable_language(C)

    set(DILITHIUM_ROUND2_REF_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/dilithium/upstream-round2/ref")
    add_library(dilithium_round2 STATIC
        "${DILITHIUM_ROUND2_REF_DIR}/sign.c"
        "${DILITHIUM_ROUND2_REF_DIR}/polyvec.c"
        "${DILITHIUM_ROUND2_REF_DIR}/poly.c"
        "${DILITHIUM_ROUND2_REF_DIR}/packing.c"
        "${DILITHIUM_ROUND2_REF_DIR}/ntt.c"
        "${DILITHIUM_ROUND2_REF_DIR}/reduce.c"
        "${DILITHIUM_ROUND2_REF_DIR}/rounding.c"
        "${DILITHIUM_ROUND2_REF_DIR}/fips202.c"
        "${DILITHIUM_ROUND2_REF_DIR}/randombytes.c"
    )
    target_include_directories(dilithium_round2 PUBLIC "${DILITHIUM_ROUND2_REF_DIR}")
    target_compile_definitions(dilithium_round2 PUBLIC MODE=4)
    target_compile_features(dilithium_round2 PUBLIC c_std_99)

    # Round 2's config.h enables x86-only cycle-counter assembly even when
    # benchmarking is disabled. Suppress that unused instrumentation only for
    # this isolated test target; do not modify the upstream checkout.
    set(DILITHIUM_ROUND2_PORTABLE_HEADER
        "${CMAKE_CURRENT_BINARY_DIR}/dilithium_round2_portable_timing.h")
    file(WRITE "${DILITHIUM_ROUND2_PORTABLE_HEADER}"
        "#define CPUCYCLES_H\n#define DBENCH_START()\n#define DBENCH_STOP(t)\n")
    target_compile_options(dilithium_round2 PRIVATE
        "$<$<COMPILE_LANGUAGE:C>:-include${DILITHIUM_ROUND2_PORTABLE_HEADER}>")

    add_executable(dilithium_round2_test tests/dilithium_round2_test.c)
    target_link_libraries(dilithium_round2_test PRIVATE dilithium_round2)
    add_test(NAME dilithium_round2_test COMMAND dilithium_round2_test)

    set(DILITHIUM_ROUND3_REF_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/dilithium/upstream-round3/ref")
    add_library(dilithium_round3 STATIC
        "${DILITHIUM_ROUND3_REF_DIR}/sign.c"
        "${DILITHIUM_ROUND3_REF_DIR}/packing.c"
        "${DILITHIUM_ROUND3_REF_DIR}/polyvec.c"
        "${DILITHIUM_ROUND3_REF_DIR}/poly.c"
        "${DILITHIUM_ROUND3_REF_DIR}/ntt.c"
        "${DILITHIUM_ROUND3_REF_DIR}/reduce.c"
        "${DILITHIUM_ROUND3_REF_DIR}/rounding.c"
        "${DILITHIUM_ROUND3_REF_DIR}/fips202.c"
        "${DILITHIUM_ROUND3_REF_DIR}/symmetric-shake.c"
        "${DILITHIUM_ROUND3_REF_DIR}/randombytes.c"
    )
    target_include_directories(dilithium_round3 PUBLIC "${DILITHIUM_ROUND3_REF_DIR}")
    target_compile_definitions(dilithium_round3 PUBLIC DILITHIUM_MODE=5)
    target_compile_features(dilithium_round3 PUBLIC c_std_99)

    add_executable(dilithium_round3_test tests/dilithium_round3_test.c)
    target_link_libraries(dilithium_round3_test PRIVATE dilithium_round3)
    add_test(NAME dilithium_round3_test COMMAND dilithium_round3_test)
endif()
