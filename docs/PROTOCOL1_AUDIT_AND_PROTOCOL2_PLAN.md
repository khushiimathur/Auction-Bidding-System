# Protocol 1 Audit and Protocol 2 Implementation Plan

**Scope:** audit of the local Esgin Protocol 1 core and implementation status
of Esgin Protocol 2. This document does not certify the implementation or its
security.

**Primary reference:** M. F. Esgin et al., “Short Lattice-based One-out-of-Many
Proofs and Applications to Ring Signatures,” full version, Cryptology ePrint
2018/773, especially §2.1–2.3, §4 Protocol 1 and Theorem 1, §5 Protocol 2 and
Theorem 2, and §6 for its repeated ring-signature use. [Paper PDF](https://eprint.iacr.org/2018/773.pdf).
Page numbers below are the printed page numbers in that version.

## 1. Executive findings

- The local Protocol 1 core implements the paper’s principal witness relation,
  first-message commitments, signed-monomial challenge mapping, response
  equations, two rejection-sampling call sites, verifier norm checks and
  homomorphic commitment checks. The inspected formulas are consistent with
  §4 Protocol 1 (printed pp. 14–15) and Algorithm 1 (§2.3, p. 8).
- That is a **conditional protocol-core assessment**, not a production or
  security approval. Exact discrete-Gaussian and Bernoulli-exponential
  providers are present, but their existence and deterministic tests are not
  independent production validation. No concrete, reviewed `aCom`
  construction is selected.
- Several semantics need resolution before production use, especially the
  integer-lift versus centered-residue treatment of responses, exact
  distributions and serialization, and final security parameters.
- A standalone Protocol 2 prover/verifier path is now implemented with
  explicit challenge input and an injected P2 `aCom` provider. Its test
  provider is transparent and non-cryptographic; the code is not production-
  ready and does not establish the full Theorem 2 parameter conditions.

## 2. Project state inspected

### Relevant files

- `cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp`
- `cpp_backend/src/proofs/binary_proof.cpp`
- `cpp_backend/include/lattice_lrs/proofs/protocol2_proof.hpp`
- `cpp_backend/src/proofs/protocol2_proof.cpp`
- `tests/test_binary_proof.cpp`
- `tests/test_protocol2_proof.cpp`
- `cpp_backend/include/lattice_lrs/commitment/commitment.hpp`
- `cpp_backend/src/commitment/commitment.cpp`
- `cpp_backend/include/lattice_lrs/sampling/{random_source,sampler}.hpp`
- `cpp_backend/src/sampling/{random_source,sampler}.cpp`
- `cpp_backend/src/arithmetic/{polynomial,matrix}.cpp`
- Root and backend `CMakeLists.txt`
- `docs/PHASE3_RING_SIGNATURE_DESIGN.md`,
  `docs/PQ_LRS_PROTOCOL_RESOLUTION.md`,
  `docs/PQ_LRS_DEVIATIONS_AND_SECURITY_NOTES.md`, and
  `docs/PQ_LRS_INTEGRATION_LOG.md`

The backend already supplies negacyclic `Rq` polynomial/matrix operations,
OS-backed random bytes, unbiased uniform and bounded sampling, and the Esgin
commitment `Com_ck`. CTest contains `binary_proof_test` alongside arithmetic,
commitment, dependency-integration and Dilithium checks. Root CMake adds the
backend and links test executables to it; the backend exports NTL and transitively
GMP. Dilithium Round 2 and Round 3 are separate optional C test targets.

The Protocol 2 integration build and full CTest run passed 17/17 tests,
including `protocol2_proof_test`. These deterministic tests are evidence of
functional wiring only, not sampler conformance or cryptographic security.

## 3. Protocol 1 audit

### 3.1 Confirmed implementation relations

| Paper requirement | Local implementation | Audit result |
| --- | --- | --- |
| Witness is a `k × beta` one-hot array of constant 0/1 polynomials, with public commitment `B = Com_ck(b;r)` | `BeginBinaryProof` checks vector lengths/rings, constant coefficients, one 1 per row, bounded centered lifts for `r`, the `B²md` squared-norm limit, and recomputes the public commitment | Matches the intended relation in §4 / Definition 4, subject to the code’s centered-lift convention |
| Sample `a_{j,i}` for `i != 0` from `D^d_{phi1 sqrt(k)}` and set `a_{j,0} = -sum_{i=1}^{beta-1} a_{j,i}` | Samples each nonzero coordinate with scale squared `phi1² k`; constructs coefficientwise negative row sums | Algebra and requested scale match Protocol 1; distribution is delegated to the exact Gaussian provider, whose production suitability is not independently established |
| Sample `r_c` in `[-B,B]^(md)` and `r_a,r_d` from `D^{md}_{phi2 B sqrt(2md)}` | Uses bounded coefficient sampling for `r_c`; passes exact rational scale-squared `phi2² B² 2md` to the Gaussian provider for `r_a,r_d` | Requested distributions/scales match; provider correctness is unverified |
| `A=Com(a;r_a)`, `C=Com(a(1-2b);r_c)`, `D=Com(-a²;r_d)` | Builds those message vectors and invokes existing `Com` | Matches modulo-`q` commitment relations |
| Auxiliary commitment binds `(A,C,D)` | Injected `AuxiliaryCommitmentProvider` commits and verifies those three vectors with an opening | Interface exists; production construction/security and canonical encoding are absent |
| `x=X^omega`, `omega` uniform in `[0,2d)` | `BinaryChallengeFromExponent` maps the first half to `+X^j`, second half to `-X^j`; sampler draws an unbiased integer in `[0,2d)` | Correct mapping including `X^d=-1`; distribution depends on the existing uniform sampler |
| `f=x b+a`, `z_b=xr+r_a`, `z_c=xr_c+r_d` | Computes these over integer lifts, then encodes responses as ring polynomials modulo `q` | Formula matches; the lift/reduction/verification boundary needs an explicit protocol encoding decision (see §3.4) |
| Apply Algorithm 1 rejection to `(f_1,xb_1,phi1,sqrt(k))` and `((z_b,z_c),x(r,r_c),phi2,B sqrt(2md))` | Two `rej_accepts` calls use the corresponding concatenated integer vectors and `K²`; the second is skipped if the first aborts | Call sites and exact rational logarithm calculation match the displayed Algorithm 1 probability, assuming the Bernoulli provider samples it exactly |
| Reconstruct `f_{j,0}=x-sum_{i>0}f_{j,i}` and `g=f(x-f)` | `reconstruct_f`; computes each `g` by quotient-ring polynomial arithmetic | Matches Protocol 1 |
| Enforce response bounds: `||f_{j,i}||≤5 phi1 sqrt(dk)`, `||f_{j,0}||≤5 phi1 sqrt(dk(beta-1))`, `||z_b||,||z_c||≤2 sqrt(2) phi2 Bmd` | Exact rational squared comparisons over centered coefficient representatives | Bound values and inclusive comparisons match. Test coverage does not establish every equality boundary |
| Verify `xB+A=Com(f;z_b)` and `xC+D=Com(g;z_c)` | Computes both sides using existing commitment and polynomial operations | Matches the equations in Protocol 1 |

Paper locations: Algorithm 1, §2.3, p. 8; Definition 4 and Protocol 1,
§4, pp. 14–15; Theorem 1, §4, p. 15. The parameters are kept rational and
comparisons use integer cross-multiplication; no floating-point norm threshold
or field inverse appears in the inspected P1 code.

### 3.2 Parameter checks in the code

`BinaryProofParameters::validate` checks `k>0`, `beta>=2`, `v=k beta`,
`d>=7`, `md>=86`, the strict Theorem 1 lower bound

```text
q > (10 phi1 d sqrt(k d (beta-1)) + 2)^2,
```

and that the commitment key’s configured squared norm bound is at least

```text
T² = (2d+2)² * (
       54 phi1⁴ d³ k³ beta(beta-1)
       + 12 phi2² B² m² d²).
```

The code compares the radical q inequality exactly by integer arithmetic and
compares rational squared bounds exactly. This is consistent with the
Protocol 1 theorem as transcribed in the current design document.

Additional `2B < q` check ensures bounded integer coefficients have unique
centered representatives. It is a local encoding/domain guard, not a security
estimate. The generic commitment module independently enforces odd integer
`q>1`, without requiring prime `q`; that agrees with the paper’s odd-modulus
setting. The P1 validator does not settle q’s M-LWE/M-SIS suitability,
commitment hiding/binding, or Section 6’s repeated-proof parameter bounds.

### 3.3 Tests inspected

`tests/test_binary_proof.cpp` includes:

- Challenge mapping at exponent 0 and `2d-1`, and rejection at `2d`.
- A deterministic honest transcript with nonzero mask fixture values and
  equation verification.
- Checks that both rejection call sites are reached on the accepting fixture.
- Tampering with `f`, `z_c`, a first-message commitment, and a challenge outside
  the signed-monomial set.
- An out-of-bound `z_b` rejection.
- First-stage abort behavior and single-use prover state.
- Non-one-hot witness, invalid public commitment opening, too-small q, and
  insufficient commitment norm bound.

The fixtures are explicitly deterministic fakes: the Gaussian stand-ins return
chosen integers, the Bernoulli provider always accepts/rejects, and the test
`aCom` serializes values transparently with a fixed opening byte. They test API
flow and equations, not the distributions or security assumptions. There is no
exact equality-bound test for each verifier norm, no statistical test for
Gaussian or Bernoulli probabilities, and no adversarial production `aCom`
test. The challenge lower and upper mapping endpoints are covered; an unbiased
sampling distribution is inherited from the separate sampler tests.

### 3.4 Deviations, caveats, and unresolved P1 questions

1. **Integer lifts versus ring representatives.** Rejection inner products
   correctly use unreduced integer lifts for Gaussian samples. Responses are
   then reduced modulo q. The verifier measures norms after taking centered
   representatives. The protocol’s proof analysis needs an explicitly reviewed
   correspondence between the integer response sampled by the prover, its
   serialized residue, and the verifier’s centered lift, including Gaussian
   tail events that can cross `q/2`. The current code does not encode or prove
   that correspondence itself.
2. **`aCom` instantiation.** The paper specifies a separate hiding/binding
   auxiliary commitment and permits a random-oracle interpretation. The
   concrete construction, output format, transcript encoding, domain
   separation and randomness remain unselected. The transparent test provider
   is not suitable outside tests.
3. **Rejection provider correctness.** The source computes the exponent as an
   exact rational and rejects a positive exponent, but the provider must sample
   the corresponding Bernoulli event exactly. The interface cannot prove that
   implementation correct.
4. **Distribution convention.** The Gaussian API uses rational
   `sigma_squared` and the mass `exp(-x²/(2*sigma_squared))`, matching
   Esgin’s `D_sigma` widths. A provider implementation exists; this audit
   does not independently establish its distributional correctness or
   production suitability. No normal-distribution approximation is accepted
   by assumption.
5. **Parameter scope.** The validator covers the single Protocol 1 theorem’s
   arithmetic conditions. It is not the Section 5 or Section 6 parameter
   validator. Previously discussed `phi1=phi2=4`, `d=256`, `m=13`, `B=1`, and
   `v=k beta` are provisional profiles, not finalized production parameters.
6. **Test boundary coverage.** Current negative and edge coverage is useful but
   does not cover each norm exactly at its inclusive boundary or all malformed
   dimensions and modulus edge cases. These are recommended additions when
   production semantics are settled; no source change is proposed here.

**Assessment:** the inspected code’s algebraic Protocol 1 core is consistent
with the displayed paper equations. It is not an end-to-end faithful
cryptographic implementation because its samplers have not received
independent production validation, its auxiliary commitment has no concrete
construction, and lift/serialization semantics remain to be reviewed. Calling
it “correctly implemented” without those qualifications would overstate what
has been established.

## 4. Missing dependencies and readiness

| Dependency | Esgin requirement | Current project | What must be resolved |
| --- | --- | --- | --- |
| Discrete Gaussian | Independent coordinates from Esgin `D_sigma` with standard deviation per coefficient; §2.3, pp. 7–8; Protocols 1–2, pp. 15–17 | Provider implementation and dedicated tests; deterministic protocol fixtures also exist | Independently validate the exact positive rational `sigma_squared` law, infinite support, OS entropy use, and implementation |
| Bernoulli-exponential | Algorithm 1 exact acceptance probability, including rational exponent passed by P1 | Exact rational-interval provider and dedicated tests; deterministic provider fixtures also exist | Independently review exactness assumptions, entropy use, termination, timing, and failure behavior. Ordinary floating-point `exp` plus a comparison is not established as equivalent |
| Auxiliary commitment `aCom` | Separate hiding/binding auxiliary commitment; §4 p. 14 and §5 pp. 16–17 permit the random-oracle interpretation | P1 provider takes `(A,C,D)` and returns opaque bytes plus opening; test-only transparent encoder | Select and review a concrete instantiation; define canonical serialization, domain separation, challenge/transcript integration and opening checks consistent with the paper’s simulator/security argument |
| Parameters/security | Odd q; theorem-specific q and norm bounds; commitment hiding/binding assumptions; §2.2 Lemma 1, §4 Theorem 1, §5 Theorem 2, §6 Assumption 1/Theorem 3 | Configurable q and rational limits; theorem checks for P1 only | Finalize a complete Section 6 profile; prove all derived inequalities; independently assess M-LWE/M-SIS and commitment bounds; document the actual q algebraic conditions and ring setup |

The existing architecture **does support** injection of these dependencies and
keeps them separable from polynomial arithmetic. The interfaces do not
themselves establish correctness, exactness, secure entropy use, or the paper’s
assumptions.

## 5. Protocol 2: component-by-component plan

### 5.1 Statement and inputs

Section 5, Protocol 2 (printed pp. 16–17) proves one-out-of-many membership
for an ordered public list `L=(c_0,...,c_{N-1})`, where `N=beta^k`. The witness
is an index `ell` and opening `r` such that the selected list entry is a
commitment to zero, `c_ell=Com_ck(0;r)`, with the paper’s required bound on
`r`. Other list entries are not required to be valid commitment encodings.
Encode `ell` in base beta; for each digit `ell_j`, define a one-hot row
`delta_{ell_j,i}` and collect the `k beta` entries as `delta`. Commit to
`delta` with `B=Com_ck(delta;r_b)`. This `B` is an internal proof commitment,
not an auction-bid commitment.

### 5.2 Prover first message and dependencies

1. **Index encoding and witness validation.** Check `N=beta^k`, index range,
   the selected `c_ell` relation and required opening bounds. Existing
   polynomial/vector types and `Com_ck` can express these operations. List
   length, ordering and any padding convention must be explicit; do not infer
   well-formedness of unrelated entries.
2. **Commit one-hot digits.** Sample `r_b` from the paper’s bounded set and
   calculate `B=Com_ck(delta;r_b)`. Existing bounded sampling and commitment
   code are reusable.
3. **Embed Protocol 1.** Produce P1 first messages for the statement `(ck,B)`.
   Protocol 2, §5, printed p. 17, specifies
   `r_a,r_d <- D^{md}_{phi2 B sqrt(3md)}`, replacing the standalone Protocol 1
   width `sqrt(2md)`. It separately uses
   `rho_j <- D^{md}_{phi2 B sqrt(3md/k)}` and joint rejection width
   `phi2 B sqrt(3md)`. Appendix E, printed p. 30, explains why the rotated
   `rho_j` sum is statistically close to the common-scale distribution; it
   is not an exact discrete-Gaussian convolution. Any implementation must
   preserve that approximation and its error analysis. Protocol 1 retains its
   three-object `aCom` interface; Protocol 2 uses a separate injected provider
   for the ordered `(A,B,C,D,E_0,...,E_{k-1})` tuple. Neither interface selects
   a concrete `aCom` construction.
4. **Polynomial expansion.** For each list index represented by digits
   `i=(i_0,...,i_{k-1})`, form

   ```text
   p_i(x) = product_j (x*delta_{ell_j,i_j} + a_{j,i_j})
          = delta_{ell,i}*x^k + sum_{j=0}^{k-1} p_{i,j}*x^j.
   ```

   Compute coefficients in the quotient polynomial ring exactly as specified.
   Existing negacyclic multiplication/addition can support this, but a
   coefficient-expansion oracle test should validate the implementation.
5. **Build P2 commitments.** For each `j`, sample
   `rho_j <- D^{md}_{phi2 B sqrt(3md/k)}` as in Protocol 2, p. 17, and compute
   `E_j=sum_i p_{i,j} c_i + Com_ck(0;rho_j)`. This requires matrix/list
   dimension and ring checks, plus the production Gaussian provider.
6. **Outer `aCom`.** The P2 prover passes the ordered tuple
   `(A,B,C,D,E_0,...,E_{k-1})` to an injected provider and retains its opening.
   No production construction or security model is selected.

### 5.3 Challenge and response

The challenge is the same signed monomial `x` from `C={X^omega:0<=omega<2d}`.
The noninteractive ring-signature layer later derives challenge(s) through its
Fiat–Shamir transcript; that transcript is not part of Protocol 2’s local
interactive proof API and remains absent.

The P2 response contains the embedded P1 response and

```text
z = x^k*r - sum_{j=0}^{k-1} x^j*rho_j.
```

The paper retains the first P1 rejection on `(f_1,x b_1)` and replaces P1’s
second rejection by one joint call
`Rej((z,z_b,z_c),(x^k r,x r_b,x r_c),phi2,B sqrt(3md))` (Protocol 2, p. 17).
The three `md`-coordinate response blocks are therefore treated together;
`r_a,r_d` use `phi2 B sqrt(3md)`, while each `rho_j` uses
`phi2 B sqrt(3md/k)`. Appendix E, printed p. 30, establishes statistical
closeness—not exact equality—between the rotated sum in `z` and the
common-scale distribution. Do not compose the standalone P1 second rejection
with an additional joint call. All response objects must be
reduced/serialized in a way justified by the paper’s norm and lift semantics,
and the statistical error from Appendix E must be accounted for.

### 5.4 Verification

The verifier should:

1. Validate all dimensions, rings, list size `N=beta^k`, challenge membership
   in `C`, and exact transcript encoding.
2. Verify the outer auxiliary commitment and its opening for the exact P2
   tuple `(A,B,C,D,E_0,...,E_{k-1})` (Protocol 2, pp. 16–17).
3. Run the embedded `V_bin` checks: verify
   `xB+A=Com_ck(f;z_b)` and `xC+D=Com_ck(f*(x-f);z_c)`, and enforce
   `||f_{j,i}|| <= 5 phi1 sqrt(dk)` for `i != 0` and
   `||f_{j,0}|| <= 5 phi1 sqrt(dk)(beta-1)`, as printed for Protocol 2.
4. Check the Protocol 2 response bounds printed on p. 17:
   `||z||, ||z_b||, ||z_c|| <= 2 sqrt(3) phi2 B m d`. These are distinct from
   the rejection-center bound `B sqrt(3md)`.
5. For every base-beta digit tuple `i`, check the Protocol 2 commitment
   equation (printed p. 17):

   ```text
   sum_i c_i * product_{j=0}^{k-1} f_{j,i_j}
      - sum_{j=0}^{k-1} E_j*x^j
      = Com_ck(0; z).
   ```

   Here `f_{j,i_j}` is the reconstructed full P1 row entry. The implementation
   must follow the paper’s exact indices/signs and use quotient-ring arithmetic.

Theorem 2 (§5, pp. 17–18) states the protocol’s special-soundness and
single-run soundness result under its stated conditions, including
`d>=7`, `md>=86`, modulus/commitment requirements, and
`k'=max{2,k}` with soundness error `k'/(2d)`. These statements are paper
theorems under assumptions, not properties established by local functional
tests.

### 5.5 Tests required before considering P2 complete

- Index encoding for `N=beta^k`, first/last index, and rejection of invalid
  `N`, `ell`, `beta`, `k`, and inconsistent ring dimensions.
- One-hot digit vectors and internal commitment `B` opening.
- Small hand-computed polynomial product coefficients and P2 `p_{i,j}`
  expansion, including negacyclic wraparound.
- `E_j` equation with hand-computable toy ring/list fixtures.
- Honest proof fixture through injected deterministic providers; explicitly
  label it as algebraic wiring only.
- Verification rejection after modifying each of `B`, `E_j`, outer
  `aCom`/opening, `f`, `z`, `z_b`, `z_c`, challenge, list order/content, and
  selected index relation.
- Exact-at-bound and just-over-bound response norm tests for each of
  `z,z_b,z_c` at `2 sqrt(3) phi2 B m d`.
- Rejection at each prescribed sampling stage, restart behavior, and single-use
  prover state.
- Malformed list/ring encodings and arithmetic edge cases at composite odd q.
- Once real providers exist, separate distribution-conformance and statistical
  tests plus independent review; fixture-based tests are insufficient.

### 5.6 Dependency matrix: what can start

| P2 part | Can implement now? | Reason |
| --- | --- | --- |
| Public types, dimensions, index/base-beta conversion | Yes, as non-cryptographic validation utilities | Fully specified once `N=beta^k` and canonical ordering are fixed |
| Polynomial expansion and `p_{i,j}` arithmetic | Yes, with equation-derived unit tests | Uses existing arithmetic; does not require sampling |
| Deterministic `E_j` equation helper given caller-provided `rho_j` | Yes, as a narrowly scoped algebra helper | Equation is specified; must not present helper as a complete proof |
| P2 commitments, responses, and verification | Implemented behind injected samplers/providers | Functional path uses documented widths, integer lifts, helper equations, and response bounds; deterministic tests do not establish distributional correctness or security |
| Outer P2 `aCom` | Injected interface only; blocked for security use | Ordered P2 tuple is passed to the provider, but no concrete construction/model or encoding is selected |
| Full P2 security claim | Blocked for production readiness | Theorem 2 parameter inequalities, Appendix E aggregate statistical error, concrete `aCom`, and independent review remain unresolved |
| Fiat–Shamir ring signature / Section 6 repetition | Not in this step | Separate transcript, repeated bounds, and parameter requirements |

## 6. Recommended implementation order

1. **Protocol transcription review:** retain the verified §5 widths, joint
   rejection grouping, response bounds, verifier equations and auxiliary
   tuple as the machine-checkable specification. Preserve Appendix E’s
   statistical-closeness argument for the rotated Gaussian sum; do not treat
   it as an exact convolution.
2. **Sampling design and review:** follow
   `DISCRETE_GAUSSIAN_SAMPLER_SPEC.md` for the `D_sigma` / exact
   `sigma_squared` contract, exact Bernoulli-exponential dependency, entropy
   interface, side-channel model and error/failure behavior. Implement/test
   providers independently before protocol integration. For P2, also carry
   Appendix E’s statistical-closeness bound into the aggregate distribution-
   error analysis.
3. **`aCom` design review:** select a concrete instantiation consistent with
   the paper's hiding/binding contract or justify use of its random-oracle
   interpretation; specify serialization, order and domain separation, then
   review security composition with Protocols 1 and 2.
4. **Lift and encoding review:** define canonical wire representation, integer
   lift used for rejection and verifier norm semantics, and treatment of tail
   events.
5. **P2 prover/verifier:** the interactive proof path and pure algebra helpers
   are implemented behind injected providers. Continue with independent
   equation/parameter review and adversarial tests; do not claim a concrete
   `aCom` or production security.
7. **Section 6 ring signature:** after P2 review, implement repeated proofs,
   Fiat–Shamir transcript and ring APIs under the paper’s separate parameters.
   WCM remains deferred until its documented ambiguities are resolved.

## 7. Questions requiring resolution

1. Which exact version of EPrint 2018/773 is normative for the implementation,
   and does it include any erratum affecting Protocol 1/2 notation or bounds?
2. What exact discrete Gaussian definition, scale convention, tail treatment,
   precision, and independent-coordinate sampler are required by the selected
   version?
3. What exact algorithm may realize Algorithm 1’s Bernoulli-exponential
   probability without an approximation that changes the distribution?
4. What concrete `aCom` construction or random-oracle instantiation is intended,
   and how must its ordered input and challenge be encoded/domain-separated?
5. Does the production proof response encode raw integer lifts or only residues?
   What proof justifies centered-lift norm checks after modular reduction,
   especially for Gaussian tail events?
6. How will Appendix E's statistical-closeness error be bounded and included
   in an end-to-end Protocol 2 distribution analysis? The implementation
   preserves integer lifts through rejection and uses the paper's joint
   rejection inputs, widths, and response norm bounds; this does not itself
   establish the aggregate statistical error.
7. What final `q`, `T_com`, `T_1`, `T'`, `phi_1`, `phi_2`, `B`, `k`, `beta`,
   `r`, and security assumptions satisfy all Section 5 and Section 6 conditions?
   The earlier approximate `log2(q)` row alone does not answer this.
8. Has an independent cryptographic reviewer checked the P1 source and the
   proposed P2 transcript composition, including all extraction and security
   reductions?

## 8. Readiness conclusion

**Protocol 1:** its inspected algebraic core matches the paper’s stated
relations and checks. Its distributions, auxiliary commitment, and response
encoding are not production-complete, so the project cannot yet claim a
faithful production Protocol 1 implementation or security.

**Protocol 2:** the standalone interactive prover/verifier path, arithmetic
helpers, integer-lift responses, and joint rejection call are implemented.
The prover/verifier use an injected P2 `aCom` provider; no concrete
hiding-and-binding construction is selected. The code checks embedded P1
parameter requirements and Protocol 2 dimensions, but does not validate every
Theorem 2 security inequality. Appendix E's statistical-closeness contribution
is not accumulated into a quantitative end-to-end error budget. Treat the
implementation and deterministic integration tests as functional wiring only.

## 9. Follow-up: `aCom` path audit

This supplement records a focused review of the current Protocol 1
implementation. The earlier sections are an audit snapshot; their sampler
status statements predate the later exact Gaussian and Bernoulli-exponential
providers.

### Paper-level role

Section 4 treats `aCom` as a separate auxiliary commitment, distinct from
`Com_ck`, assumed hiding and binding; it permits treating `aCom` as a random
oracle. In Protocol 1, the prover forms `(c_a,d_a)=aCom(A,C,D)`. In Protocol 2,
the committed tuple is `(A,B,C,D,{E_j})`. In both protocols, `c_a` is sent as
first-message material before the challenge, and `d_a` is revealed in the
response. The verifier checks the opening against the corresponding ordered
tuple as part of proof verification.

The inspected Section 4 proof uses hiding in the SHVZK abort-simulation
argument to establish indistinguishability of the simulated commitment
transcript from the real one. Binding has a separate extraction role:
Protocol 1's 3-special-soundness argument (Theorem 1) and Protocol 2's
`(k+1)`-special-soundness argument (Theorem 2) rely on a fixed `c_a` binding
the committed tuple across the accepting transcripts. Theorem 2 explicitly
invokes `aCom` binding. The inspected proof steps do not identify an
equivocation or oracle-programmability operation as an additional requirement.

`Com_ck` binding is distinct: Section 2.2 gives the main lattice commitment
strong binding under M-SIS (with the stated bounded-opening setting). It fixes
the message/opening relations of the algebraic commitments used in extraction;
it does not replace `aCom`'s binding of the outer first-message tuple.

### Current code path

1. `BeginBinaryProof` forms `A=Com_ck(a;r_a)`,
   `C=Com_ck(a(1-2b);r_c)`, and `D=Com_ck(-a^2;r_d)`. Each is an `n`-element
   vector of canonical-residue polynomials in `R_q=Z_q[X]/(X^d+1)`.
2. It calls `AuxiliaryCommitmentProvider::commit(A,C,D,random)`. The returned
   opaque byte string is placed in the first message; the opening is held in
   prover state.
3. `RespondBinaryProof` returns that opening with the response. The challenge
   is supplied separately to the prover and verifier; this module does not
   derive it from `aCom` or serialize a Fiat-Shamir transcript.
4. `VerifyBinaryProof` checks dimensions and rings, then calls
   `verify(A,C,D,aCom,opening)` before response norms and the two
   `Com_ck` equations. Provider exceptions are caught by the verifier and
   produce `false`.

The `aCom` provider receives `A,C,D` after the lattice commitment has reduced
them into `R_q`; it does not receive Gaussian lifts or apply the rejection
sampling equations. The existing Gaussian widths remain `phi1^2*k` for the
nonzero `a` coordinates and `phi2^2*B^2*2*m*d` for `r_a,r_d`; `r_c` is
bounded. The only `aCom` randomness contract is the shared injected
`RandomSource`. The interface specifies neither a commitment algorithm nor
its parameterization, encoding, coin distribution, or domain separation.

### Validation and unresolved points

The provider interface and call order model the commit/open flow, but do not
instantiate or prove hiding, binding, or the random-oracle interpretation. The
opaque byte fields have no production serialization or transcript
specification, and challenge derivation is outside this module.

`TestAuxiliaryCommitment` is only a transparent test fixture: it text-serializes
the tuple and uses a fixed opening byte. It checks equality for its own
encoding, not hiding or cryptographic binding. The existing first-message
tamper test is fixture-level evidence only; it does not validate any
production `aCom`.

No concrete mismatch in the `A,C,D` ring dimensions or their `Com_ck`
equations was established. The paper-level contract is now confirmed from the
checked excerpts of §§2.2, 4 and 5 supplied for this project: `aCom` is a
separate hiding-and-binding auxiliary commitment (with a random-oracle
interpretation permitted), opened after its commitment is sent. Its concrete
instantiation and encoding remain unselected, so the existing provider is
still only an injection boundary and is not a validated production `aCom`.

## 10. `aCom` contract and reusable architecture

### Paper requirements

The checked excerpts supplied for Esgin et al., §§2.2, 4 and 5, establish:

- `Com_ck` is the main lattice commitment defined by `CKeygen`, `Commit`, and
  `Open` in §2.2. It is computationally hiding under M-LWE and strongly
  binding under M-SIS, with the bounded-opening parameter `T_com`.
- `aCom` is a distinct auxiliary commitment used in the zero-knowledge proof
  to simulate aborts. Its hiding property is used in the SHVZK abort-simulation
  argument. Binding is used in Protocol 1's 3-special-soundness argument
  (Theorem 1) and Protocol 2's `(k+1)`-special-soundness argument (Theorem 2).
  The paper permits treating `aCom` as a random oracle.
- Protocol 1 forms `(c_a,d_a)=aCom(A,C,D)`. Protocol 2 uses
  `(c_a,d_a)=aCom(A,B,C,D,{E_j})`.

Thus `Com_ck` and `aCom` have different stated roles and assumptions. The
paper does not, in the supplied excerpts, select a concrete `aCom` algorithm,
specify its byte encoding or output size, or define the random-oracle
instantiation and its opening representation. No explicit equivocation or
programmability requirement was identified in the inspected proof steps; that
does not define the random-oracle interface or rule out additional requirements
elsewhere in the full security argument.

### Existing provider and minimum interface change

The current `AuxiliaryCommitmentProvider` accepts three separate vectors
`(A,C,D)` for both `commit` and `verify`. It returns opaque commitment bytes
and opening bytes; the prover places the commitment in the first message and
the opening in the response, and the verifier checks them against the same
tuple. The prover passes the existing `RandomSource` to `commit`. This flow
already models the paper's `(c_a,d_a)` commit/open boundary for Protocol 1.

The typed-input recommendation remains:

- `Protocol1AuxiliaryInput {A,C,D}`
- `Protocol2AuxiliaryInput {A,B,C,D,E}` where `E` is an ordered vector
  `E_0,...,E_{k-1}`
- `AuxiliaryCommitmentInput = variant<Protocol1AuxiliaryInput,
  Protocol2AuxiliaryInput>`

Both `commit(input, random)` and `verify(input, c_a, d_a)` consume that same
input type. Named fields and a sum type preserve each protocol's arity and
ordering without allowing a generic unlabelled list to silently permute or
omit values. The current implementation leaves the P1 provider unchanged and
uses a separate typed `Protocol2AuxiliaryCommitmentProvider`; it does not
consolidate both under the recommended variant. Existing
`AuxiliaryCommitmentValue` and opening bytes remain opaque. This API choice
does not change the paper's protocol equations.

### Canonical encoding and wire behavior (implementation choice)

The paper-level tuple order is normative; the following serialization rules
are implementation recommendations, not paper specifications:

1. Encode a fixed scheme/version tag and a protocol tag (`P1` or `P2`).
   Encode each field with a distinct label and length; encode `E` as a
   length-counted sequence in increasing `j` order.
2. Encode ring context (`q`, degree `d`, and the polynomial `X^d+1`) and
   vector/polynomial dimensions. Encode each coefficient as its canonical
   residue in `[0,q-1]`, using a deterministic fixed-width unsigned big-endian
   representation sized from `q`. Reject noncanonical or dimensionally
   inconsistent values.
3. Keep the two outputs distinct: `c_a` is the provider's canonical
   commitment byte string in the first message; `d_a` is the provider's
   canonical opening byte string in the response. Their lengths and internal
   formats depend on the selected construction and must be fixed by its
   specification.
4. Verification reconstructs the exact tagged tuple, validates the canonical
   encodings and protocol context, then verifies `c_a` against that tuple and
   `d_a`. Malformed or invalid openings fail verification; entropy or provider
   failures during commitment creation must be surfaced, not replaced by a
   fallback.

Protocol-specific domain separation and canonical encodings prevent cross-
protocol/type ambiguity; they do not themselves establish hiding or binding.
The eventual provider must document its security parameter, randomness
requirements, output format, and assumptions.

### Concrete instantiation options and non-interactive use

- **Separate computational commitment scheme:** the closest direct
  instantiation of the stated hiding/binding contract. It must support the
  ordered typed tuple and produce the paper's commit/open flow. The paper
  excerpt does not select an algorithm; any concrete choice needs an
  independent security argument for both hiding and binding.
- **Random-oracle interpretation:** permitted as an idealized proof model by
  the paper, but not equivalent to declaring `aCom` to be an ordinary hash of
  the tuple. The statement does not fully specify how the oracle interpretation
  produces and verifies the pair `(c_a,d_a)`. The commitment/opening pair and
  its timing must be defined in the model and preserved by any concrete
  implementation.
- **Reusing `Com_ck`:** not recommended or justified by the paper. Its
  M-LWE/M-SIS guarantees, bounded opening relation and ring-shaped interface
  are for the main lattice commitment; they do not automatically instantiate
  the separate auxiliary commitment's abort-simulation assumptions.
- **Salted hash commitment:** a possible implementation proposal only, not a
  paper-specified construction. It would require explicit randomness,
  encoding, hiding/binding assumptions and proof compatibility analysis; do
  not adopt it merely because the paper mentions a random oracle.

For the non-interactive ring-signature application, the provider can supply
the `c_a` first-message value and `d_a` response opening to the enclosing
transcript. The signature's Fiat–Shamir/challenge layer must include the
properly encoded commitment and protocol context in the order specified by
the complete ring-signature construction. This provider does not derive the
challenge; the current Protocol 1 API receives the challenge separately, so a
non-interactive transcript wrapper remains a separate integration requirement.

### Protocol 2 commitment inventory

The following inventory retains the local §5 transcription. The supplied
excerpt confirms the outer `aCom` tuple's exact ordered shape, but does not
independently confirm every other equation or dimension below.

| Object | Role / shape in the local transcription | Existing `Com_ck` support |
| --- | --- | --- |
| Public list entries `c_i` | Inputs in `R_q^n`; the selected entry has an opening as a commitment to zero | Existing commitment output has shape `R_q^n`; list validation/order is not implemented |
| `B=Com_ck(delta;r_b)` | Internal commitment to the `k*beta=v` one-hot digit vector; `r_b` is `m` ring-polynomial entries (`m*d` scalar coefficients) | Supported by `Com_ck` for message length `v` and opening length `m` |
| Embedded P1 `A,C,D` | Three `R_q^n` first-message commitments for message vectors of length `v` and openings of `m` ring-polynomial entries | Supported by the existing P1 calls |
| `Com_ck(0;rho_j)` and `E_j` | Mask commitment to a zero message, combined with a linear combination of list entries; `rho_j` is `m` ring-polynomial entries (`m*d` scalar coefficients) and `E_j` is in `R_q^n` | The zero-message commitment and ring-linear combination are expressible by current `Com_ck` and polynomial operations |
| Outer `aCom` | Paper tuple is `(A,B,C,D,{E_j})`, with `E_j` ordered by `j` | Supported by a separate injected Protocol 2 provider interface; no concrete construction is implemented |
| Final `Com_ck(0;z)` relation | The verifier-side right-hand commitment in the transcribed P2 equation; `z` is an `m`-entry opening vector | Checked by the Protocol 2 verifier using the existing commitment API and response vector |

The implementation defines
`Com_ck(u;r)=G_r*r+G_m*u` in `R_q^n`, with `G_r` of shape `n x m`,
`G_m` of shape `n x v`, message `u` in `R_q^v`, and opening `r` in `R_q^m`.
Its negacyclic polynomial arithmetic and canonical
coefficient residues can represent the listed lattice-commitment operations.
This is an algebraic-capability assessment, not confirmation that the
transcribed Protocol 2 tuple/equations are complete or correctly quoted.

### Recommendation and remaining questions

Retain the typed P1/P2 input recommendation above: either a tagged typed
variant or separate typed provider interfaces should preserve each tuple's
arity and ordering, with an explicit commit/open pair and randomness
injection. The implementation uses separate interfaces and does not
conflate `aCom` with `Com_ck`.

Before selecting a production provider, resolve from the complete paper and
its security proof: the exact random-oracle treatment (if used), commitment
randomness and opening semantics, output length/security parameter, and how
`c_a,d_a` enter the challenge/transcript in the ring-signature transform.
Canonical encoding is an implementation choice that must be frozen and
reviewed with that instantiation. Protocol 2 response lift/serialization is
implemented through rejection, but faithful end-to-end handling of Appendix
E's statistical-closeness bound and parameter/security review remain
blockers. The Protocol 2 prover/verifier path is implemented with an injected
provider; its transparent test fixture does not establish hiding or binding.
The paper PDF endpoint returned HTTP 403 during integration, so the code uses
the verified project transcription. No production-readiness or
cryptographic-security claim is made.
