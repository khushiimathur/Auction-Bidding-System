# Isolated Dilithium reference implementation tests

This project retains two official Dilithium reference implementations as
separate upstream checkouts. These tests exercise their APIs independently;
they do not integrate either implementation into the PQ-LRS construction.

## Implementations and APIs

- **Round 2, mode 4** (`dilithium/upstream-round2/ref`): the attached-message
  `crypto_sign_keypair`, `crypto_sign`, and `crypto_sign_open` API. The test
  checks the expected public-key (1760 bytes), secret-key (3856 bytes), and
  signature (3366 bytes) sizes, successful signing and message recovery, and
  rejection of a changed message or signature.
- **Round 3, mode 5** (`dilithium/upstream-round3/ref`): the namespaced
  `pqcrystals_dilithium5_ref_keypair`,
  `pqcrystals_dilithium5_ref_signature`, and
  `pqcrystals_dilithium5_ref_verify` detached-signature API. The test checks
  the expected public-key (2592 bytes), secret-key (4864 bytes), and signature
  (4595 bytes) sizes, successful signing and verification, and rejection of a
  changed message or signature.

The implementation sources are compiled directly into distinct static
libraries and test executables. Round 2 receives `MODE=4`; Round 3 receives
`DILITHIUM_MODE=5`. Neither checkout is altered or built in place. Round 2's
`ref/config.h` enables x86 cycle-counter assembly unconditionally, and its
`ref/test/cpucycles.h` has no ARM64 implementation. Since benchmarking is
disabled in this test, CMake writes a small compatibility header into the
build directory to suppress only the unused timing macros/header. This does
not change cryptographic code or parameters.

## Build and run

From the workspace root:

```sh
cmake -S Lattice_LRS -B Lattice_LRS/build -DLATTICE_LRS_BUILD_DILITHIUM_TESTS=ON
cmake --build Lattice_LRS/build -j 4
ctest --test-dir Lattice_LRS/build --output-on-failure
```

The option is off by default. Enabling it registers `dilithium_round2_test`
and `dilithium_round3_test` alongside the existing `cpp_build_smoke` and
`ntl_gmp_integration` tests.

## Recorded verification

On Apple Clang 21 with CMake 4.5.0, both isolated Dilithium test targets
compiled and linked. CTest reported **4/4 tests passed**: the two existing
project tests and the Round 2 and Round 3 Dilithium API tests. The Dilithium
tests cover API compatibility and basic signature acceptance/rejection only;
they are not a cryptographic security assessment or an LRS test.
