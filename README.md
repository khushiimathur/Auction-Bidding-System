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
- Python is only applicable to auxiliary test/environment tooling; this
  repository does not currently provide a Python package or bindings.

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
├── python/                      Reserved; currently empty
├── CMakeLists.txt
└── cpp_backend/CMakeLists.txt
```

The two Dilithium directories are currently separate clones of the upstream
repository. Before publishing, include them deliberately as pinned Git
submodules if retaining their upstream histories is desired; a normal clone
must then initialize submodules. Do not stage these nested repositories as
ordinary directories, since Git will record gitlinks rather than their source
files.

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
