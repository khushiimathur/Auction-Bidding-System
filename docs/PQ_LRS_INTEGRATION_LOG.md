# PQ-LRS Integration Log

## Audit-driven integration decision

The request was to inspect third-party implementations and integrate only source that is compatible with the Esgin + Wang–Chen–Ma (WCM) construction. The source audit found no cryptographic component suitable for safe transplantation without changing the protocol’s relation, assumptions, distributions, transcript, or tag semantics.

**Imported third-party source files: none.** No C++, C, Rust, Python, CMake, parameter, or Dilithium source file was changed by this audit. The two newly requested repositories were cloned/extracted under `/private/tmp/pqlrs_current_candidates`, outside the project. No external repo was cloned into `Lattice_LRS`.

This is the outcome of the requested compatibility gate: importing an unrelated scheme’s proof or tag would not be a valid implementation of the target.

## Retained local code

- NTL-backed polynomial arithmetic and polynomial matrix operations.
- OS-random source and uniform/bounded sampling.
- Esgin-inspired Section 2.2 commitment code and its existing tests.
- Isolated upstream Dilithium Round 2 and Round 3 directories and their standalone validation targets.

The module-level map is in [`PQ_LRS_COMPONENT_REUSE_MAP.md`](PQ_LRS_COMPONENT_REUSE_MAP.md). Detailed source findings are in [`PQ_LRS_IMPLEMENTATION_DISCOVERY_REPORT.md`](PQ_LRS_IMPLEMENTATION_DISCOVERY_REPORT.md).

## Verification performed

Existing project CTest suite: **6/6 passed** — `cpp_build_smoke`, `ntl_gmp_integration`, `polynomial_matrix_arithmetic_test`, `sampling_commitment_test`, `dilithium_round2_test`, `dilithium_round3_test` (reported total duration 3.14 seconds).

L2RS was built in an out-of-tree temporary directory using its CMake setup and Apple Clang 21; compilation completed with warnings, and the demo exited with status 139. This is not a passing functional test. No external source was built into or linked from the project. The archived Python NTRU repository has no valid end-to-end signature test; its verification checks are commented out.

## Outstanding integration prerequisites

1. Resolve the WCM paper’s concrete `H`/`H'` and OTS-message inconsistencies against an authoritative erratum or author clarification.
2. Confirm the intended historical Dilithium parameter set, API and canonical message encoding for WCM.
3. Finalize and independently review Esgin parameter choices, modulus constraints, and lattice-security estimates.
4. Implement the exact Esgin binary and one-out-of-many protocols locally, then define canonical Fiat–Shamir transcripts.
5. Specify whether linkability is global per one-time key or scoped to an auction/context. Context-scoped tags alter the construction and need their own analysis.

No implementation work on those cryptographic components was undertaken in this audit.

## Phase 3, Step 5 — Esgin Protocol 1 core

After inspecting the local proof header, it was confirmed that the binary-proof
API declarations existed but there was no implementation or registered test.
Implemented the local Protocol 1 core in
`cpp_backend/src/proofs/binary_proof.cpp`, retaining the existing provider-based
architecture for distributions and `aCom`. No external source was imported,
and no WCM equation was changed.

The implementation uses the Section 4 relations and equations: bounded
one-hot witness validation; `A`, `C`, and `D` commitments; signed monomial
challenges; `f=x*b+a`, `z_b=x*r+r_a`, `z_c=x*r_c+r_d`; both Algorithm 1
rejection probabilities; the reconstructed `f_{j,0}` and `g=f(x-f)`; Protocol
1 norm conditions; and the two homomorphic commitment checks. Integer lifts
are retained for Gaussian samples when computing rejection inner products.
The parameter validator checks the theorem's strict q bound and calculated
commitment `T` bound using exact integer/rational comparisons.

Added `tests/test_binary_proof.cpp` with positive transcript/equation checks,
tampering and malformed-witness rejection, challenge-domain checks, abort and
single-use-state checks, and q/commitment-bound validation. Its Gaussian,
Bernoulli and auxiliary-commitment fixtures are deterministic test doubles,
not implementations of cryptographic distributions or a secure commitment.

Build command: `cmake --build Lattice_LRS/build -j 4` — passed.
CTest: **7/7 passed**, including the six existing arithmetic, commitment,
dependency and Dilithium tests plus `binary_proof_test` (5.17 seconds on the
final run).

This does not complete a production binary proof: the source tree still lacks
production discrete-Gaussian and exact Bernoulli-exponential providers and a
reviewed `aCom` construction. The selected production q, M-LWE/M-SIS security
estimate, exact response serialization/lift policy, Protocol 2 and the Esgin
ring signature also remain outstanding. Passing fixture tests is not a
security claim.

## Protocol 1 rejection-branch correction

Reviewed `docs/REJECTION_SAMPLING_CORRECTNESS_AUDIT.md` against Esgin
Algorithm 1 (§2.3, p. 8). Since Algorithm 1 aborts only when a uniform
`u in [0,1)` exceeds its threshold, any nonnegative log threshold
`r = log(p_raw) >= 0` implies certain acceptance. Updated
`cpp_backend/src/proofs/binary_proof.cpp` so `rej_accepts` returns true for
`r >= 0` and invokes the Bernoulli-exponential provider only for `r < 0`.
The provider interface comment now explicitly specifies that negative-only
domain; no approximate or production sampler was added.

Added deterministic Protocol 1 branch tests in `tests/test_binary_proof.cpp`
for exact positive, zero and negative first-stage logs. The negative case
checks the exact rational passed to the test provider; positive and zero cases
confirm those branches do not call it. Invalid rational parameters are also
checked. These are control-flow/provider-wiring tests, not statistical tests
and not evidence of sampler security.

Verification: `cmake --build build -j 4` passed. `ctest --test-dir build --output-on-failure` passed **7/7**, including both Dilithium reference tests.
At that stage, remaining limitations were no production
Bernoulli-exponential provider, no production discrete-Gaussian sampler, and
no resolution of Lemma 6's strict
`||c|| < K` hypothesis versus protocol non-strict bounds. Protocol 2, WCM,
parameters and the construction were not changed.

## Protocol 1 discrete-Gaussian provider composition

The existing Protocol 1 API already accepts provider references, so no
protocol or prover-interface change was needed. A caller can compose the
production providers and shared random source as follows:

```cpp
ExactBernoulliExponentialProvider exponential;
ExactDiscreteGaussianProvider gaussian(exponential);
SystemRandomSource random;

auto begun = BeginBinaryProof(
    key, parameters, public_commitment, witness, random, gaussian, auxiliary);
auto response = RespondBinaryProof(
    begun.state, key, parameters, challenge, random, exponential);
```

`ExactDiscreteGaussianProvider` uses that same `BernoulliExponentialProvider`
and forwards the `RandomSource` supplied by `BeginBinaryProof`; Protocol 1's
response rejection uses the exponential provider directly. The existing
Protocol 1 sigma-squared expressions were preserved.

Expanded `binary_proof_test` to exercise the exact Gaussian implementation
through `BeginBinaryProof`, record and verify both exact sigma-squared values
and coordinate counts, connect the actual exact exponential provider on a
bounded deterministic first-coefficient case, and verify that an integer lift
above `q` is retained in the rejection exponent before the response is encoded
in the ring. Test-only scripted coin providers force deterministic branches;
they do not establish the Gaussian distribution. Random-source and
Bernoulli-provider exceptions are checked for propagation.

Validation: CMake configure and build passed; focused `binary_proof_test` and
`discrete_gaussian_test` passed (2/2); complete CTest passed (10/10).

This verifies composition through the provider-injection API, not a production
signing application or secure `aCom` instantiation. The actual sampler has
unbounded variable-time loops; passing tests does not establish production
readiness, constant-time behavior, or cryptographic security. Protocol 2,
WCM, Dilithium integration, and ring key generation remain untouched.
