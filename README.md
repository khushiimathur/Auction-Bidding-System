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
| \(N\) | 64 | Named profiles: 64, 256, 1024, 4096; test ring: 4 | \(N=\beta^k\); code profiles are not security-approved. |
| \(n\) | 5 | Profiles: 5, 5, 11, 21; demo: 1; test fixture: 1 | Profile order is \(N=64,256,1024,4096\). |
| \(m\) | 13 | Profiles: 13, 13, 25, 50; demo: 2; test fixture: 1 | Profile order is \(N=64,256,1024,4096\). |
| \(v\) | 16, derived as \(k\beta\) | Profiles: 16, 32, 64, 128; demo: 1; test fixture: 4 | Derived from \(k\beta\); not a Table 3 column. |
| \(d\) | 256 | Profiles: 256, 256, 128, 64; demo: 3; test fixture: 86 | Profile order is \(N=64,256,1024,4096\). |
| \(q\) | \(\log_2(q)=50\), rounded | Exact code-selected primes are listed below; demo: 101; test fixture: 1,000,000,007 | Table 3 gives only rounded \(\log_2(q)\); selected values are implementation choices, not security approvals. |
| \(B\) | 1 | 1 in all profiles; demo: 3; test fixture: 1 | Profile value follows Table 3. |
| \(k\) | 2 | 2 in all profiles; test fixture: 2 | Profiles use Table 3 values. |
| \(\beta\) | 8 | Profiles: 8, 16, 32, 64; test fixture: 2 | Profile order is \(N=64,256,1024,4096\). |
| \(r\) | 16 | Profiles: 16, 16, 19, 22; test fixture: 2 | Computed using the Section 6 repetition bound; demo setup count: 1 is not an RSign value. |
| \(\lambda\) | 128 | 128 in all profiles; test uses 128 | Protocol soundness target; not a post-quantum security level. |
| \(\phi_1,\phi_2\) | 22, literal | 22 in all profiles; test fixtures may inject other rationals | Profile selection reflects Section 6.1; no production rejection provider is supplied. |
| \(T_{\mathrm{com}}^2\) | Derived commitment bounds; not a Table 3 value | Profiles derive \(T_1^2\); demo: \(100000/1\); RSign test fixture: \(2^{256}/1\) | Profile code checks conservative q-side thresholds only; no lattice-hardness estimate is performed. |
| \(\delta\) | \(\leq 1.0045\) | Not configured or checked by the implementation | Paper-reported lattice-security analysis target only. |

The paper defines \(R=\mathbb{Z}[X]/(X^d+1)\) and \(R_q=R/qR\). Its
commitment matrices use
\(G'_r\in R_q^{n\times(m-n)}\) and \(G_m\in R_q^{n\times v}\). For this row,
Appendix D derives \(v=k\beta=16\), so the paper's M-LWE instance is
\(\mathrm{M\text{-}LWE}_{8,5,q,1}\). The paper reports approximate sizes of
774 KB per signature, 7.81 KB per public key, and 0.81 KB per secret key;
these are not sizes of a serialization implemented here.

The code includes these exact prime moduli for its named profiles:

| \(N\) | Paper \(\log_2(q)\) | Code-selected \(q\) |
|---:|---:|---:|
| 64 | 50 | 1125899906826241 |
| 256 | 53 | 9007199254740481 |
| 1024 | 46 | 119569584450049 |
| 4096 | 47 | 140737488355201 |

These choices satisfy the profile's exact repeated Assumption 1 and q-side
binding checks. The code additionally requires prime \(q\equiv1\pmod{2d}\),
which the paper does not require; with these prime moduli this makes
\(X^d+1\) split over \(\mathbb F_q\), a ring-structure choice that needs
cryptographic review. For \(N=1024\), the selected \(q\) has
\(\log_2(q)\approx46.765\), above the paper row's rounded value 46, to meet
the implemented constraints. No M-SIS/M-LWE hardness estimate was run, and
the code does not check the paper's \(\delta\leq1.0045\) lattice-reduction
condition.

The paper's stated choices include \(\beta=8\) and \(k=2\) for \(N=64\);
\(B=1\), following prior work and checked in its M-LWE analysis; \(r=16\)
repetitions for the target protocol soundness \(\lambda=128\); and the
Section 6.1 lattice-security checks targeting \(\delta\leq1.0045\).
These are the paper's reported choices and analysis, not validations performed
by this code. In particular, \(\lambda=128\) is a protocol soundness target;
it does not by itself establish 128-bit post-quantum computational security.
Earlier project notes misread the literal 22 as \(2^2=4\);
\(\mu(22)^2\approx2.983\) (versus \(\mu(4)^2\approx429.448\)) matches the
paper's stated acceptance rate above \(1/3\) and about three expected RSign
iterations.

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
- A C compiler for the shared vendored FIPS 202 SHAKE implementation and
  optional Dilithium reference tests.
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
- An experimental SHAKE256 salted auxiliary commitment provider for Protocol 1 and
  Protocol 2, using distinct domains, length-prefixed encodings, a 32-byte
  random opening, and a 32-byte digest. Its hiding/binding claims are
  conditional on the documented computational assumptions; this does not
  complete or prove the Esgin security argument.
- Named parameter profiles for \(N=64,256,1024,4096\), with exact integer
  checks for \(N=\beta^k\), \(v=k\beta\), the repeated Assumption 1, and
  conservative \(T_1/T'\) q-side bounds. These profiles are not security
  estimates or production approvals. Demo/test setups use explicitly named
  `TestOnly` APIs, rejected by production keygen/sign/verify entry points.
- RSign/RVerify batch control flow: repeated executions, transcript and
  hash-to-challenges interfaces, global rejection-provider calls, whole-batch
  retries, and verification of all executions. The interfaces are wired into
  the orchestration; this does not mean the injected providers are implemented.
- Isolated Dilithium Round 2 and Round 3 reference tests. They do not integrate
  Dilithium signatures into PQ-LRS or WCM.
- A Streamlit educational demo for C++ key generation and public-key ring
  membership. It does not generate or verify an Esgin signature.

The current configured build registers 22 CTest tests and the latest full run
passed 22/22, including the optional Dilithium tests. A fresh default CMake
configuration disables those two optional tests.

### In Progress

- Production RSign/RVerify provider configuration and end-to-end validation.
- Independent review of the SHAKE256 `aCom` instantiation and its random-oracle
  hiding/collision-resistance binding assumptions.
- The Section 6 distributions, their batch scale profile, and exact global
  rejection parameters. Existing exact samplers do not by themselves establish
  that the required repeated-run input laws are produced.

### Not Yet Implemented

- Security-reviewed final parameter selection. Named profiles and exact
  moduli are present, but the code-selected \(q\) values are not paper values
  or security approvals.
- Production canonical Fiat-Shamir transcript serialization and a concrete
  hash-to-challenges implementation.
- Production Section 6 Gaussian scale and global rejection providers.
- WCM linkability tag generation/verification and Dilithium OTS integration.
- End-to-end real-signature tests and independent cryptographic security
  validation.

### LPCom bid-amount commitment (new)

- `cpp_backend/include/lattice_lrs/lpcom/` implements `GenCom`/`Com`/`Unv`
  from Cabarcas, Demirel, Göpfert, Lancrenon, and Wunderer, "An
  Unconditionally Hiding and Long-Term Binding Post-Quantum Commitment
  Scheme" (ePrint 2015/628), Figure 1: `c = A1·v + A2·r + e mod q`. This is
  a separate, plain-`Z_q`-vector module, distinct from the ring-based
  Esgin commitment used internally by the ring signature.
- `SealedBidAuction` now commits each bid amount via LPCom before signing;
  the LRS signature covers the commitment vector, not the raw amount.
  `RevealOpening`/`VerifyOpening` support a separate settlement-stage
  opening check, and the public submission log never carries the opening.
- Two parameter profiles exist (`ExperimentalDemoParameters`,
  `ScalarMessageDemoParameters`), both explicitly labeled experimental,
  demo-scale, and **not** a post-quantum security claim.
- **Known issue, not yet fixed:** `tests/test_lpcom.cpp` and
  `tests/test_sealed_bid_auction_lpcom.cpp` currently fail 2 of ~16
  assertions. The cause is a pre-existing bug in the shared
  `sampling::sample_uniform_coefficient` utility (`sampler.cpp`): its
  byte-masking logic assumes NTL's `ZZFromBytes` is big-endian, but it is
  little-endian, which makes uniform sampling degenerate (collapsing to a
  tiny value set) for moduli such as 257. This affects any caller of that
  utility with a non-byte-aligned modulus, not just LPCom, and has not
  been fixed yet.
- Not yet integrated: the Streamlit demo (`python/demo/app.py`) and the
  `auction_cli.cpp` line protocol do not expose LPCom's commitment/opening
  flow; `docs/` has no LPCom-specific write-up yet.

### Security and Production Readiness

The Section 6 batch coordinator and its tests do not establish the correctness
of injected cryptographic providers. The test providers are orchestration
doubles, not cryptographic implementations. The exact repeated-run raw
distribution profile and the statistical-distance qualification in Appendix E
remain unresolved. Integer lifts are retained through the implemented global
rejection interface, but canonical signature/transcript serialization is not
finalized. The parameter code checks the q member of the Section 6.1 binding
inequality, not its lattice-reduction member; no M-SIS/M-LWE hardness
re-estimation has been done. No claim is made that the complete PQ-LRS or WCM
scheme is secure, fully post-quantum validated, or production-ready. The
salted-hash `aCom` is computationally hiding only under its random-oracle
assumption and has collision-resistance-based binding; the implementation
does not establish the full Esgin proof. This is not a complete sealed-bid
auction application.

# Auction-Bidding-System