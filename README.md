# Post-Quantum Secure and Anonymous Privacy-Preserving Sealed-Bid Auction Scheme — PQ-LRS module

`Lattice_LRS` is a research implementation of lattice-based cryptographic
primitives and proof components intended for a post-quantum linkable ring
signature (PQ-LRS) module in a privacy-preserving sealed-bid auction scheme.
It is not a complete auction application.

## Scope and implementation status

The current C++ backend includes:

- Polynomial and matrix lattice arithmetic.
- A lattice commitment scheme.
- A Protocol 1 binary proof.
- Protocol 2 one-out-of-many proof prover/verifier components with an explicit
  challenge and an injected auxiliary-commitment provider.
- Discrete-Gaussian and Bernoulli-exponential sampling providers using the
  shared `RandomSource` interface.
- Dilithium Round 2 and Round 3 reference source trees. Optional isolated
  CMake tests can build the reference implementations; they are not currently
  part of the PQ-LRS proof flow.

These are research components, not a claim of cryptographic security. Passing
tests does not establish protocol correctness or production suitability.

## Technologies and dependencies

- C++17 and CMake 3.16 or newer.
- NTL and GMP development headers and libraries.
- A C compiler when the optional Dilithium reference tests are enabled.
- Python 3 and Streamlit for the optional local demo in `python/demo/`. It
  invokes a small C++ wrapper; it is not a Python binding to the backend.

## Project layout

```text
Lattice_LRS/
├── cpp_backend/
│   ├── include/                 Public C++ interfaces
│   └── src/                     Arithmetic, sampling, commitments, proofs
├── dilithium/
│   ├── upstream-round2/
│   │   ├── ref/                 Reference C implementation
│   │   └── avx2/                AVX2 implementation
│   └── upstream-round3/
│       ├── ref/                 Reference C implementation
│       └── avx2/                AVX2 implementation
├── docs/                        Design notes and mathematical audits
├── tests/                       C++ tests and test helpers
├── bindings/                    Reserved; currently empty
├── python/
│   ├── demo/                    Optional Streamlit keygen/ring-membership demo
│   └── ring_demo.py             Basic public-key membership demonstration
├── CMakeLists.txt
└── cpp_backend/CMakeLists.txt
```

The two Dilithium directories are currently separate clones of the upstream
repository. Before publishing, include them deliberately as pinned Git
submodules if retaining their upstream histories is desired; a normal clone
must then initialize submodules. Do not stage these nested repositories as
ordinary directories, since Git will record gitlinks rather than their source
files.

## Platform support

The C++ backend has OS-specific `SystemRandomSource` implementations for
macOS, Windows, and Linux. The rest of the backend uses C++17, but the project
is not OS-independent of its NTL/GMP and compiler toolchains. This platform
support describes the available code paths; it is not a claim that the full
build and test suite has been validated on every platform. The optional AVX2
Dilithium source directories are architecture-specific and are not part of the
default backend build.

## Build and test on macOS

Install the prerequisites with Homebrew:

```sh
brew install cmake gmp ntl
```

Configure, build, and run the default CTest suite from the project root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Build and test on Windows

Use a CMake-compatible C++17 toolchain (for example, Visual Studio Build Tools
with the C++ workload) and NTL/GMP libraries built for that same toolchain.
If those dependencies are installed under a nonstandard prefix, set
`CMAKE_PREFIX_PATH` to that prefix in PowerShell:

```powershell
$env:CMAKE_PREFIX_PATH = "C:\path\to\ntl-gmp-prefix"
cmake -S . -B build
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Replace the example prefix with the directory containing the dependency
`include` and `lib` directories.

The optional isolated Dilithium tests are disabled by default. Enable them
with a C compiler available:

```sh
cmake -S . -B build-dilithium \
  -DCMAKE_BUILD_TYPE=Release \
  -DLATTICE_LRS_BUILD_DILITHIUM_TESTS=ON
cmake --build build-dilithium --parallel
ctest --test-dir build-dilithium --output-on-failure
```

## Limitations

The following work is not complete:

- The full Esgin ring-signature flow and its end-to-end integration.
- Fiat–Shamir transcript/challenge integration; Protocol 2 currently takes an
  explicit challenge.
- A concrete `aCom` construction; the auxiliary commitment remains injected
  through a provider interface.
- Finalized protocol parameters.
- WCM linkability integration.
- Production security validation, independent cryptographic review, and
  platform-wide validation.
- A complete sealed-bid auction application.

Do not treat this project as production-ready or as a completed secure auction
scheme.
