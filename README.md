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
- Exact Bernoulli-exponential, Bernoulli-\(\pi\)-exponential, \(D_\sigma\), and
  \(D_s\) sampling implementations using the shared `RandomSource` interface.
- RSign/RVerify Section 6 batch orchestration, with injected transcript,
  hash-to-challenges, Gaussian, auxiliary-commitment, and global-rejection
  providers. The orchestration is implemented; production providers are not.
- Dilithium Round 2 and Round 3 reference source trees. Optional isolated
  CMake tests can build the reference implementations; they are not currently
  part of the PQ-LRS proof flow.

These are research components, not a claim of cryptographic security. Passing
tests does not establish protocol correctness or production suitability.

## Cryptographic Parameter Configuration

The paper reference below is the \(N=64\) row of Table 3 in Esgin et al.,
[*Short Lattice-based One-out-of-Many Proofs and Applications to Ring
Signatures* (2018/773)](https://eprint.iacr.org/2018/773). It is a paper
reference, not the configuration currently used for signing by this project.

### Esgin Paper Reference Parameters

| Parameter | Esgin paper | Current implementation | Status / Notes |
|---|---:|---|---|
| \(N\) | 64 | No production RSign profile; demo lists five bidders for lookup only; test ring: 4 | \(N=\beta^k=8^2=64\) in the paper row. |
| \(n\) | 5 | Demo: 1; RSign test fixture: 1 | No production profile. |
| \(m\) | 13 | Demo: 2; RSign test fixture: 1 | No production profile. |
| \(v\) | 16, derived as \(k\beta\) | Demo: 1; RSign test fixture: 4 | Derived from Appendix D; not a Table 3 column. |
| \(d\) | 256 | Demo: 3; RSign test fixture: 86 | No production profile. |
| \(q\) | \(\log_2(q)=50\), rounded | Demo: 101; RSign test fixture: 1,000,000,007 | The table does not specify an exact \(q\); no production \(q\) is selected. |
| \(B\) | 1 | Demo: 3; RSign test fixture: 1 | No production bound. |
| \(k\) | 2 | Caller-supplied; RSign test fixture: 2 | No production profile. |
| \(\beta\) | 8 | Caller-supplied; RSign test fixture: 2 | No production profile. |
| \(r\) | 16 | `hash_output_count` is caller-supplied; demo setup: 1, RSign test: 2 | The demo count is setup metadata; the demo does not sign. |
| \(\lambda\) | 128 | Input to `ComputeRSignRepetitionCount`; test uses 128 | No production security parameter is configured. |
| \(\phi_1,\phi_2\) | Requires verification: “22” conflicts with the prior \(2^2=4\) transcription | `PositiveRational` values are caller-supplied; RSign test: 1 and 1,000,000,000 | No production rejection profile; neither reading is approved. See the deviations note. |
| \(T_{\mathrm{com}}^2\) | Derived commitment bounds; not a Table 3 value | Demo: \(100000/1\); RSign test fixture: \(2^{256}/1\) | These are demo/test values, not finalized production bounds. |
| \(\delta\) | \(\leq 1.0045\) | Not configured or checked by the implementation | Paper-reported lattice-security analysis target only. |

The paper defines \(R=\mathbb{Z}[X]/(X^d+1)\) and \(R_q=R/qR\). Its
commitment matrices use
\(G'_r\in R_q^{n\times(m-n)}\) and \(G_m\in R_q^{n\times v}\). For this row,
Appendix D derives \(v=k\beta=16\), so the paper's M-LWE instance is
\(\mathrm{M\text{-}LWE}_{8,5,q,1}\). The paper reports approximate sizes of
774 KB per signature, 7.81 KB per public key, and 0.81 KB per secret key;
these are not sizes of a serialization implemented here.

The paper's stated choices include \(\beta=8\) and \(k=2\) for \(N=64\);
\(B=1\), following prior work and checked in its M-LWE analysis; \(r=16\)
repetitions for the target protocol soundness \(\lambda=128\); and the
Section 6.1 lattice-security checks targeting \(\delta\leq1.0045\).
These are the paper's reported choices and analysis, not validations performed
by this code. In particular, \(\lambda=128\) is a protocol soundness target;
it does not by itself establish 128-bit post-quantum computational security.
The Section 6.1 rejection-parameter notation remains unresolved: existing
project notes transcribed it as \(2^2=4\), while this review raises the literal
reading “22”. Do not treat either value as verified or use it for production
configuration until the paper notation is confirmed.

### Demo-Only Parameters

**EDUCATIONAL DEMO-ONLY parameters — NOT secure production parameters and NOT
the Esgin paper reference configuration.**

| Parameter | Streamlit demo value |
|---|---:|
| \(n\) | 1 |
| \(m\) | 2 |
| \(v\) | 1 |
| \(d\) | 3 |
| \(q\) | 101 |
| \(B\) | 3 |

The C++ demo wrapper also sets \(T_{\mathrm{com}}^2=100000/1\) and a setup
`hash_output_count` of 1. That count is not an RSign repetition configuration:
the demo only generates keys and performs public-key membership lookup.

Other explicit values are test fixtures, not a selected cryptographic profile.
For example, the RSign orchestration fixture uses
\((n,m,v,d,q,B)=(1,1,4,86,1000000007,1)\), \(k=2\), \(\beta=2\),
`hash_output_count` \(=2\), and test rejection parameters. These values
exercise interfaces and control flow only.

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

## Implementation Status

### Completed

- Polynomial and matrix arithmetic for the negacyclic polynomial ring.
- OS-backed randomness for macOS, Windows, and Linux.
- Commitment-key generation, the commitment map, randomized commitment, and
  opening checks.
- Protocol 1 binary proof prover/verifier and its rejection-sampling path.
- Exact Bernoulli-exponential and Bernoulli-\(\pi\)-exponential providers, plus
  exact \(D_\sigma\) and \(D_s\) sampler implementations.
- Protocol 2 polynomial expansion and \(E_j\) construction, response
  generation, integer-lift handling, joint response rejection, and
  prover/verifier logic.
- RSign/RVerify batch control flow: repeated executions, transcript and
  hash-to-challenges interfaces, global rejection-provider calls, whole-batch
  retries, and verification of all executions. The interfaces are wired into
  the orchestration; this does not mean the injected providers are implemented.
- Isolated Dilithium Round 2 and Round 3 reference tests. They do not integrate
  Dilithium signatures into PQ-LRS or WCM.
- A Streamlit educational demo for C++ key generation and public-key ring
  membership. It does not generate or verify an Esgin signature.

The current configured build registers 20 CTest tests and the latest full run
passed 20/20, including the optional Dilithium tests. A fresh default CMake
configuration disables those two optional tests.

### In Progress

- Production RSign/RVerify provider configuration and end-to-end validation.
- The Section 6 distributions, their batch scale profile, and exact global
  rejection parameters. Existing exact samplers do not by themselves establish
  that the required repeated-run input laws are produced.

### Not Yet Implemented

- A finalized production parameter profile and exact modulus selection. The
  paper reports rounded \(\log_2(q)=50\), not an exact modulus for this row.
- A concrete cryptographically justified auxiliary commitment `aCom`; the
  current API is an injected provider.
- Production canonical Fiat-Shamir transcript serialization and a concrete
  hash-to-challenges implementation.
- Production Section 6 Gaussian scale and global rejection providers.
- WCM linkability tag generation/verification and Dilithium OTS integration.
- End-to-end real-signature tests and independent cryptographic security
  validation.

### Security and Production Readiness

The Section 6 batch coordinator and its tests do not establish the correctness
of injected cryptographic providers. The test providers are orchestration
doubles, not cryptographic implementations. The exact repeated-run raw
distribution profile and the statistical-distance qualification in Appendix E
remain unresolved. Integer lifts are retained through the implemented global
rejection interface, but canonical signature/transcript serialization is not
finalized. No claim is made that the complete PQ-LRS or WCM scheme is secure,
fully post-quantum validated, or production-ready. This is not a complete
sealed-bid auction application.
