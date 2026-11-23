# Post-Quantum Secure and Anonymous Privacy-Preserving Sealed-Bid Auction Scheme — PQ-LRS module

`Lattice_LRS` is a research implementation and working prototype of a
post-quantum, privacy-preserving sealed-bid auction. It follows the
project synopsis's six-stage workflow (Registration → Sealed Bidding →
Oblivious Transfer → Threshold Opening → ZK Verification → Public
Result), implementing five of the six stages end-to-end against a real
C++ cryptographic backend, with a Streamlit UI that walks through all
six in order. See `docs/WCM_AUCTION_INTEGRATION.md` §5c for the exact
synopsis-to-code mapping.

## Scope and implementation status

The current C++ backend includes:

- Polynomial and matrix lattice arithmetic.
- A lattice commitment scheme (Esgin et al.'s internal ring-signature
  commitment — used only to build a ring member's own public key, not
  to hide bid amounts).
- A Protocol 1 binary proof.
- Protocol 2 one-out-of-many proof prover/verifier components with an explicit
  challenge and an injected auxiliary-commitment provider.
- Exact Bernoulli-exponential, Bernoulli-\(\pi\)-exponential, \(D_\sigma\), and
  \(D_s\) sampling implementations using the shared `RandomSource` interface.
- RSign/RVerify Section 6 batch orchestration, with injected transcript,
  hash-to-challenges, Gaussian, auxiliary-commitment, and global-rejection
  providers, including a production (`ProductionLRSignContext`) wiring at the
  named `N64` parameter profile.
- WCM linkable ring signatures (`LRKeygen`/`LRSign`/`LRVerify`/`Link`) and
  Dilithium5 one-time signatures, composed on top of RSign/RVerify.
- **LPCom** (Cabarcas et al., ePrint 2015/628): the actual bid-amount
  commitment scheme, `GenCom`/`Com`/`Unv`, integrated into the sealed-bid
  auction's submission and settlement flow.
- **Shamir-gated threshold settlement**: a bid's LPCom opening is encrypted
  and the key Shamir-split across simulated trustees; reveal requires a
  `t`-of-`n` threshold.
- **A Merkle/hash-chain audit log** (`lattice_lrs::audit::MerkleAuditTree`)
  over each auction's public submission log.
- **Oblivious Transfer** (1-out-of-N, via a `SimROT` trusted-dealer
  simulator — explicitly not a real OT primitive yet), woven into the
  live auction flow as a private fulfillment-selection step, and also
  available as its own demo page.
- Dilithium Round 2 and Round 3 reference source trees. Optional isolated
  CMake tests can build the reference implementations.
- A Streamlit demo (`python/demo/app.py`) exercising the entire pipeline
  above against the real backend, with a dedicated end-to-end Live
  Auction page.

**Not implemented:** a lattice-based zero-knowledge range/max-bid proof
(synopsis stage 5). This is explicitly disclosed, in the UI and in
`docs/WCM_AUCTION_INTEGRATION.md`, rather than silently skipped.

These are research components, not a claim of cryptographic security. Passing
tests does not establish protocol correctness or production suitability. In
particular: LPCom's and the OT/Shamir demo parameters are explicitly
experimental/non-security-validated (see below and
`docs/WCM_AUCTION_INTEGRATION.md`); `SimROT` provides no real OT security
property; and Shamir here is ordinary, non-verifiable secret sharing.

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
- A C compiler for the shared vendored FIPS 202 SHAKE/SHA3 implementation and
  optional Dilithium reference tests.
- Python 3, Streamlit, and the `cryptography` package for the demo in
  `python/demo/` (see `python/demo/requirements.txt`). The demo invokes a
  persistent C++ subprocess (`lrs_auction_cli`) over a line protocol; it is
  not a Python binding to the backend. The OT and Shamir modules
  (`OT/`, `shamir_secret_sharing/`) are pure Python, run in-process by the
  Streamlit app, and are independent of the C++ backend.

## Project layout

```text
Lattice_LRS/
├── cpp_backend/
│   ├── include/lattice_lrs/
│   │   ├── arithmetic/, sampling/, proofs/, ring_signature/   Esgin base layer
│   │   ├── lrs/, ots/                                         WCM linkability + Dilithium OTS
│   │   ├── lpcom/                                             LPCom bid-amount commitment
│   │   ├── auction/                                           SealedBidAuction
│   │   ├── audit/                                             Merkle/hash-chain audit log
│   │   └── demo/                                               Shared demo-scale parameters, playground
│   └── src/                      Implementations mirroring the include/ tree
├── dilithium/
│   ├── upstream-round2/
│   │   ├── ref/                 Reference C implementation
│   │   └── avx2/                AVX2 implementation
│   └── upstream-round3/
│       ├── ref/                 Reference C implementation
│       └── avx2/                AVX2 implementation
├── OT/
│   ├── ot_layer_demo.py          Existing 1-out-of-N OT prototype (SimROT, HKDF, AES-GCM)
│   └── auction_ot_adapter.py     Minimal adapter wiring it into the auction demo
├── shamir_secret_sharing/
│   ├── shamir.py, committee.py   Existing Shamir split/reconstruct + threshold scheme
│   └── settlement_seal.py        Minimal adapter: AEAD-seals an LPCom opening under a Shamir-split key
├── docs/                        Design notes, mathematical audits, and WCM_AUCTION_INTEGRATION.md
├── tests/                       C++ tests and Python integration tests
├── bindings/                    Reserved; currently empty
├── python/
│   ├── demo/                    Streamlit sealed-bid auction demo + its own tests/CLI
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

## Running the complete demo

This section covers everything needed to build, test, and run the full
sealed-bid auction system (Esgin/WCM/LPCom/Shamir/OT/Merkle), end to end.

### 1. Build the C++ backend and run its tests

From the project root:

**macOS / Linux:**

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
# Fast tests (excludes the two multi-minute N64-scale production tests):
ctest --test-dir build --output-on-failure \
  -E "dilithium_round|production_rsign_integration|production_lrsign_integration"
```

```sh
# To also run the slow, real N64-scale production integration tests
# (each takes several minutes; expect ~10-30 minutes total):
ctest --test-dir build --output-on-failure \
  -R "production_rsign_integration_test|production_lrsign_integration_test"
```

Individual test binaries can also be run directly, e.g.
`./build/lpcom_test`, `./build/sealed_bid_auction_lpcom_test`,
`./build/merkle_audit_tree_test`.

**Windows (PowerShell):** see "Build and test on Windows" above for
setting `CMAKE_PREFIX_PATH` if NTL/GMP are in a nonstandard location.

```powershell
cmake -S . -B build
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure `
  -E "dilithium_round|production_rsign_integration|production_lrsign_integration"
```

```powershell
# To also run the slow production integration tests:
ctest --test-dir build -C Release --output-on-failure `
  -R "production_rsign_integration_test|production_lrsign_integration_test"
```

Individual test binaries: `.\build\Release\lpcom_test.exe`,
`.\build\Release\sealed_bid_auction_lpcom_test.exe`,
`.\build\Release\merkle_audit_tree_test.exe` (exact path depends on the
generator; Visual Studio generators nest binaries under a config
subdirectory, single-config generators like Ninja do not).

### 2. Run the Streamlit auction demo

**macOS / Linux:**

```sh
cd python/demo
pip install -r requirements.txt
streamlit run app.py
```

**Windows (PowerShell or cmd):**

```powershell
cd python\demo
pip install -r requirements.txt
streamlit run app.py
```

Open the printed `localhost` URL. The first "Create auction" click
triggers a one-time CMake configure+build of `lrs_auction_cli`
(`lrs_auction_cli.exe` on Windows) under `build/python_demo/` (cached by
Streamlit across reruns — this needs the same C++ toolchain/NTL/GMP
setup as §1 to be discoverable by CMake). Use the sidebar to navigate:

- **Overview / Ring Signatures / Linkability / Cryptographic Playground** —
  illustrative + real-backend walkthroughs of the base Esgin/WCM layer.
- **Live Auction** — the full end-to-end pipeline: create an auction,
  submit a bid (Registration → Sealed Bidding), try the private
  fulfillment selection (Oblivious Transfer), reveal/verify an opening
  under Shamir threshold authorization (Threshold Opening), see the
  explicit "not yet implemented" ZK Verification note, and check the
  Merkle audit log (Public Result).
- **Private Information Selection (OT Demo)** — the OT prototype on its
  own, independent of any auction.
- **Technical Details** — exact parameters, architecture, and
  limitations for every component.

Click **Reset demo** in the sidebar to terminate the backend subprocess
and clear all session state.

### 3. Run the Python test suites directly (without Streamlit)

**macOS / Linux:**

```sh
# Shamir (pulled verbatim from origin/feature/shamir-threshold) — 22 tests:
python3 shamir_secret_sharing/test_shamir.py
python3 shamir_secret_sharing/test_committee.py

# OT prototype's own self-test (pulled verbatim from origin/feature/ot-prototype):
python3 OT/ot_layer_demo.py

# This project's integration/adapter tests (pytest):
pip install pytest
python3 -m pytest tests/test_ot_integration.py \
  tests/test_shamir_settlement_integration.py \
  python/demo/test_app.py -v
```

**Windows (PowerShell or cmd)** — same scripts, `python` instead of `python3`:

```powershell
python shamir_secret_sharing\test_shamir.py
python shamir_secret_sharing\test_committee.py

python OT\ot_layer_demo.py

pip install pytest
python -m pytest tests\test_ot_integration.py `
  tests\test_shamir_settlement_integration.py `
  python\demo\test_app.py -v
```

`python/demo/test_app.py` uses Streamlit's `AppTest` harness: it drives
the real `app.py` script headlessly (no browser), which in turn drives
the real `lrs_auction_cli` subprocess — not mocks.

### 4. Drive the raw CLI protocol directly (for debugging)

`lrs_auction_cli`'s one-command-per-line protocol is documented at the
top of `python/demo/auction_cli.cpp`.

**macOS / Linux:**

```sh
printf 'CREATE demo1\nBID demo1 0 150\nBID demo1 0 999\nLIST demo1\nAUDIT_ROOT demo1\n' \
  | ./build/python_demo/lrs_auction_cli
```

**Windows (PowerShell)** — `printf` isn't a PowerShell builtin, so pipe a
here-string instead:

```powershell
@"
CREATE demo1
BID demo1 0 150
BID demo1 0 999
LIST demo1
AUDIT_ROOT demo1
"@ | .\build\python_demo\lrs_auction_cli.exe
```

Settlement-stage commands (`OPEN_BID`, `VERIFY_BID_AMOUNT`,
`EXPORT_RAW_OPENING`, `VERIFY_SEALED_OPENING`) and audit commands
(`AUDIT_ROOT`, `AUDIT_PROOF`, `AUDIT_VERIFY`) are all additive — none of
them change `BID`'s own accept/reject behavior.

## Implementation Status

### Completed

- Polynomial and matrix arithmetic for the negacyclic polynomial ring.
- OS-backed randomness for macOS, Windows, and Linux.
- Commitment-key generation, the commitment map, randomized commitment, and
  opening checks (Esgin's internal ring-signature commitment).
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
- RSign/RVerify Section 6 batch control flow, with a real production
  provider wiring (`ProductionRSignContext`) at the named `N64` profile,
  validated end to end (`tests/test_production_rsign_integration.cpp`).
- **WCM linkable ring signatures** (`LRKeygen`/`LRSign`/`LRVerify`/`Link`) and
  **Dilithium5 one-time signatures**, composed on top of RSign/RVerify, with
  a production wiring (`ProductionLRSignContext`) validated end to end at
  `N64` (`tests/test_production_lrsign_integration.cpp` — a real 64-member
  ring, three real signings, real `Link` linked/unlinked verdicts, real
  rejection of tampered message/ring/signature, real one-time-key-reuse
  rejection).
- Isolated Dilithium Round 2 and Round 3 reference tests.
- **`SealedBidAuction`**: a demo-scale sealed-bid auction built on the real
  WCM/Esgin algorithms (smaller dimensions than `N64` for interactivity, not
  a mock — see `docs/WCM_AUCTION_INTEGRATION.md` §3), with real `Link`-based
  duplicate-submission detection.
- **LPCom bid-amount commitment** (Cabarcas, Demirel, Göpfert, Lancrenon,
  Wunderer, ePrint 2015/628, Figure 1: \(c = A_1v + A_2r + e \bmod q\)):
  `GenCom`/`Com`/`Unv`, a separate plain-\(\mathbb{Z}_q\)-vector module
  (`cpp_backend/include/lattice_lrs/lpcom/`), distinct from Esgin's
  ring-based internal commitment. `SealedBidAuction` commits each bid
  amount via LPCom before signing; the LRS signature covers the commitment
  vector, not the raw amount. `RevealOpening`/`VerifyOpening` provide a
  separate settlement-stage opening check; the public submission log never
  carries the opening. Two explicitly experimental, non-security-claimed
  parameter profiles exist (`ExperimentalDemoParameters`,
  `ScalarMessageDemoParameters`).
- **Shamir-gated threshold settlement**: the LPCom opening is AES-256-GCM
  encrypted under a fresh per-submission key immediately after acceptance;
  that key is Shamir-split (`shamir_secret_sharing/`, pulled verbatim from
  `origin/feature/shamir-threshold`) across \(t\)-of-\(n\) simulated
  trustees. Settlement requires reconstructing the key from \(\geq t\)
  shares, decrypting, and re-verifying via the real `VerifyOpening` —
  independent of the auction's own internally stored opening copy.
- **Merkle/hash-chain audit log** (`lattice_lrs::audit::MerkleAuditTree`,
  SHA3-256) over each auction's public submission log — root, inclusion
  proofs, and independent-verifier-style checks via new CLI commands.
- **Oblivious Transfer** (1-out-of-N, pulled verbatim from
  `origin/feature/ot-prototype`): the existing `SimROT`/`Sender`/`Receiver`
  (HKDF-SHA256 key derivation, AES-256-GCM payloads), wired into the live
  auction flow as a private fulfillment-selection step and available as
  its own demo page. `SimROT` is explicitly a trusted-dealer simulator, not
  a real OT primitive.
- A full Streamlit demo (`python/demo/app.py`) exercising every component
  above against the real backend, including an end-to-end Live Auction
  page walking through all six stages of the project synopsis's workflow
  (see `docs/WCM_AUCTION_INTEGRATION.md` §5c).

The current configured build registers 31 CTest targets; the fast subset
(excluding the two multi-minute `N64`-scale production integration tests
and the optional Dilithium reference tests) passes 31/31. The two slow
production integration tests have also been run to completion and pass
(see `docs/WCM_AUCTION_INTEGRATION.md`).

### In Progress / Known Limitations

- Independent review of the SHAKE256 `aCom` instantiation and its random-oracle
  hiding/collision-resistance binding assumptions.
- The Section 6 distributions, their batch scale profile, and exact global
  rejection parameters, beyond what the `N64` production validation already
  exercises.
- LPCom's and the OT/Shamir demo parameters are explicitly experimental and
  not independently security-validated (see `docs/WCM_AUCTION_INTEGRATION.md`
  §5a/§5b for exactly what is and isn't claimed).
- Shamir here is ordinary, non-verifiable secret sharing — a corrupted
  trustee share is not detected as corrupted by Shamir itself (only
  indirectly, via AES-GCM authentication failure on the wrapped key).
- `SimROT` provides no real oblivious-transfer security property.
- This demo centralizes every simulated bidder's secret key, and briefly
  the plaintext LPCom opening during sealing, in one process — documented,
  not hidden, throughout.

### Not Yet Implemented

- Security-reviewed final parameter selection for the named Esgin profiles
  (code-selected \(q\) values are implementation choices, not paper values
  or security approvals).
- A lattice-based zero-knowledge range/max-bid proof (the project
  synopsis's stage 5, "ZK Verification") — explicitly absent, and marked
  as such in the Streamlit UI itself rather than silently skipped.
- Verifiable Secret Sharing for the Shamir settlement layer.
- A real base OT / OT extension in place of `SimROT` (the vendored
  `libOTe`/`cryptoTools` C++ library on `origin/feature/ot-prototype` is
  unbuilt and unconnected; wiring it in needs a C++↔Python bridge).
- Independent cryptographic security validation of the complete, composed
  pipeline (each stage's own assumptions still apply individually —
  composing working pieces does not by itself establish a new, stronger
  security property for the whole; see
  `docs/WCM_AUCTION_INTEGRATION.md`'s closing note).

### Security and Production Readiness

The Section 6 batch coordinator and its tests do not establish the correctness
of injected cryptographic providers beyond what the `N64` production
integration tests exercise. The exact repeated-run raw distribution profile
and the statistical-distance qualification in Appendix E remain unresolved.
The parameter code checks the q member of the Section 6.1 binding inequality,
not its lattice-reduction member; no M-SIS/M-LWE hardness re-estimation has
been done. No claim is made that the complete PQ-LRS, WCM, LPCom, Shamir, or
OT components — individually or composed — are production-ready. The
salted-hash `aCom` is computationally hiding only under its random-oracle
assumption and has collision-resistance-based binding; the implementation
does not establish the full Esgin proof. This is a research prototype, not
a production auction system.