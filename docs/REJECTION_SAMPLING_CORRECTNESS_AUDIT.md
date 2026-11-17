# Rejection-Sampling Correctness Audit

**Scope:** Audit and correction of Esgin et al.'s rejection sampler in
Protocol 1, the standalone Protocol 2 joint rejection helper, and the
Bernoulli-exponential provider. This document does not certify a production
discrete-Gaussian provider or the complete protocol.

**Primary reference:** Esgin et al., *Short Lattice-based One-out-of-Many
Proofs and Applications to Ring Signatures*, ePrint 2018/773. Algorithm 1 and
Lemma 6 are in §2.3, printed p. 8; Protocol 1 is §4, p. 15; Protocol 2 is §5,
p. 17; the repeated construction is §6, p. 19. [Official paper PDF](https://eprint.iacr.org/2018/773.pdf).

## 1. Executive finding and correction status

Algorithm 1 accepts when `u <= p_raw`, with `u` uniform on `[0,1)`. Therefore
the effective acceptance probability is

```text
p = min(1, p_raw) = min(1, exp(r)),
r = -12/phi - 1/(2*phi^2)
    + (-2*<z,c> + ||c||^2)/(2*phi^2*K^2).
```

If `r >= 0`, `p_raw >= 1` and the comparison accepts with probability one.
The initial audit found that Protocol 1 rejected positive `r` and delegated
zero `r` to a negative-only provider. The helper has since been corrected: it
accepts for `r >= 0` and calls the Bernoulli-exponential provider only for
`r < 0`. The provider contract now documents that restricted domain.

The rejection normalizer is
`mu(phi)=exp(12/phi+1/(2*phi^2))`. The earlier implementation used
`-1/phi` rather than `-12/phi` in `r`; this correction changes the acceptance
probability (by a factor of `exp(-11/phi)` before clipping) and therefore the
output distribution. The corrected helper still does not certify the
negative-exponent sampler. This correction does not resolve the separate raw
Gaussian sampling discrepancies, irrational parameter representation,
Appendix E statistical-distance questions, or production-security concerns.

This finding concerns the Bernoulli decision. The Gaussian input widths and
support hypotheses must also match Lemma 6 for its distribution guarantee to
apply. The paper states strict `||c|| < K` in Lemma 6 but uses non-strict
bounds in Protocol 1; Section 10 derives the same rejection-distribution
bound for the closed support `||c|| <= K`.

## 2. Exact probability and comparison

Algorithm 1 (§2.3, p. 8) defines

```text
sigma = phi*K
mu(phi) = exp(12/phi + 1/(2*phi^2))
p_raw = (1/mu(phi)) * exp((-2*<z,c> + ||c||^2)/(2*sigma^2)).
```

Writing `r = log(p_raw)` and substituting `sigma = phi*K` gives

```text
r = -12/phi - 1/(2*phi^2)
    + (-2*<z,c> + ||c||^2)/(2*phi^2*K^2).
```

The algorithm draws `u` from `[0,1)` and aborts if `u > p_raw`. For `r < 0`,
this is an exponential Bernoulli coin with probability `exp(r)`. For `r = 0`,
`p_raw = 1` and all `u` in `[0,1)` pass. For `r > 0`, `p_raw > 1` and all
`u` pass as well. Equivalently, the probability implemented by the literal
comparison is `min(1, exp(r))`.

Lemma 6 (§2.3, p. 8) gives a statistical guarantee for its rejection
procedure under its hypotheses, including a shift `c` drawn from a set
`V` with `||c|| < K`, and the specified Gaussian input. It does not state
that every possible Gaussian sample produces `p_raw <= 1`. Nor does its
approximation bound authorize replacing the literal comparison by rejection
when the threshold exceeds one. A proof that a protocol-specific invariant
makes `r > 0` impossible would need to be provided; none was found in the
source or documented assumptions examined here.

The sampler design documents correctly describe the mathematical clamp
`min(1,exp(r))`. The corrected helper implements that branch behavior, using
exact rational exponent arithmetic and no floating-point evaluation.

## 3. Current Protocol 1 implementation

### 3.1 Exponent arithmetic and signs

`cpp_backend/src/proofs/binary_proof.cpp:291–319`, helper `rej_accepts`,
checks equal vector lengths and positive `K_squared`, then computes

```text
dot = sum_i z[i]*c[i]
c2  = sum_i c[i]^2
r_num/r_den =
  (-(2*p*t+t^2)*K^2 + t^2*(-2*dot+c2)) / (2*p^2*K^2),
```

where `phi = p/t`. This is algebraically the paper's `r` exactly. Dot
products, squared norms and exponent numerator/denominator use `NTL::ZZ`, so
these quantities do not overflow fixed-width integer arithmetic. The code
uses the signed integer lifts supplied by the protocol path; it does not
reduce `z` or `c` modulo `q` before computing the inner product. That matches
the integer-vector formula in Algorithm 1. `multiply_by_monomial` applies
negacyclic wraparound with a sign change when constructing the lifted `x*c`
vectors, consistent with multiplication by a monomial in
`Z[X]/(X^d+1)`.

The exponent sign itself is correct. The original defect was the branch after
computing it; that branch is now corrected:

```cpp
if (exponent_numerator >= 0) return true;
return exponential.sample_exp(...);
```

This follows directly from Algorithm 1's comparison against `u` uniform on
`[0,1)`. No invariant establishing `r <= 0` for all Gaussian inputs was
found; a bounded center does not bound its inner product with unbounded `z`.

### 3.2 Protocol 1 call sites and branches

`cpp_backend/src/proofs/binary_proof.cpp:526–529` performs the first call:

```text
Rej(f_nonzero_lift, x_b_nonzero, phi1, sqrt(k));
```

The implementation passes `K_squared = k`. It returns `nullopt` immediately
on rejection; the second rejection is not evaluated. The caller later
reconstructs accepted response values modulo `q`, after the rejection
computations on integer lifts.

The second call at `binary_proof.cpp:531–548` constructs
`z_b = x*r + r_a`, `z_c = x*r_c + r_d`, then uses

```text
Rej((z_b,z_c), (x*r,x*r_c), phi2, B*sqrt(2*m*d));
```

It passes `K_squared = B^2 * 2*m*d`, and rejects the response on a false
result. These inputs, signs and squared-bound substitutions match Protocol 1
§4, p. 15. The first and second tests are sequential, so the second
Bernoulli call is made only if the first accepts.

`PositiveRational` rejects nonpositive `phi` components, and the helper
rejects nonpositive `K_squared`; its denominator is therefore positive.
There is no floating-point exponent evaluation in this helper. One separate
hardening point is that some vector reservation/index expressions near the
first call use native `size_t` products; validation should ensure all
dimension products are checked before allocation/indexing. That is not an
overflow in the exact probability calculation itself.

### 3.3 Integer lifts and bounds

The implementation retains signed lifts for `f`, witness randomness,
`r_c`, and their responses through the rejection calls. This avoids computing
the rejection inner product from canonical residues, which would be a
different integer expression. After acceptance, values are converted to the
protocol's ring representation for the response object.

Protocol 1's proof analysis (Appendix E, Theorem 1) bounds the first shift by
`||x*b_1|| <= sqrt(k)` and the second by
`||(x*r,x*r_c)|| <= B*sqrt(2*m*d)`. Lemma 6 states the strict condition
`||c|| < K`; the theorem's displayed bounds are non-strict. Equality is
reachable under Protocol 1's explicit input constraints, as demonstrated in
Section 9. The source supplies these `K` values but does not check strict
inequality at the call boundary. Section 10 derives that the rejection
distribution argument extends to equality under the Gaussian tail bound used
by the cited Lyubashevsky result; the printed strict statement and the paper's
own completeness proof still differ textually.

### 3.4 Provider and randomness behavior

`cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp:74–82` declares
`BernoulliExponentialProvider::sample_exp(log_numerator, log_denominator,
RandomSource&)`, with a contract phrased for a negative rational logarithm.
`ExactBernoulliExponentialProvider` now implements that contract using exact
rational interval refinement and the existing `RandomSource`; its dedicated
test and the full CTest suite passed. These tests are evidence about the
implementation and covered cases, not a cryptographic security certification.
The corrected helper handles `r >= 0` itself, so the provider receives only
strictly negative exponents.

The literal paper pseudocode draws a uniform variate for each reached
rejection comparison. A mathematically faithful provider can return true
without consuming random bits for `r >= 0`, since the result is certain.
This changes random-stream consumption compared with literally drawing and
discarding a uniform, but not the acceptance distribution when the source is
independent. The corrected nonnegative branch consumes no provider
randomness and returns true, preserving the acceptance distribution. For
`r < 0`, exact random-bit consumption depends on the eventual
provider algorithm and is not implemented. On first-stage rejection, not
entering the second-stage coin is consistent with the protocol's abort
branch; the outer signing attempt must be restarted as specified by the
caller.

## 4. Protocol 2 and repeated construction trace

The Protocol 2 prover path now calls the standalone joint rejection helper
with integer-lift responses and the protocol-specific center and width. Its
deterministic integration tests exercise the positive, zero, and negative
exponent branches and failure propagation. This documents the implemented
call wiring; it is not an independent proof of distributional correctness.

| Construction | Paper rejection call | Expected squared bound | Code status |
| --- | --- | --- | --- |
| Protocol 1, binary mask | `Rej(f_1, x*b_1, phi1, sqrt(k))` (§4, p. 15) | `k` | Implemented through `rej_accepts` |
| Protocol 1, commitment randomness | `Rej((z_b,z_c), x*(r,r_c), phi2, B*sqrt(2md))` (§4, p. 15) | `B^2*2md` | Implemented through `rej_accepts` |
| Protocol 2, embedded binary part | Same first binary-mask rejection (§5, p. 17) | `k` | Implemented in the Protocol 2 prover path |
| Protocol 2, joint response | `Rej((z,z_b,z_c), (x^k*r,x*r_b,x*r_c), phi2, B*sqrt(3md))` (§5, p. 17) | `B^2*3md` | Implemented through the standalone joint helper and called by the Protocol 2 prover |
| Section 6 repeated ring signature | Rejection on concatenations across `r` repetitions (§6, p. 19) | first: `kr`; response: `B^2*3mdr` | No caller in current source |

For every row, the same exponent and `min(1,exp(r))` decision applies. The
Protocol 2 values above are direct paper mappings and the call wiring has
focused deterministic tests; Section 6 repetition remains unimplemented. In
Protocol 2, §5, printed p. 17, specifies
`D_{phi2 B sqrt(3md)}` for `r_a,r_d`, matching the joint rejection scale.
Each `rho_j` has scale `phi2 B sqrt(3md/k)`. Appendix E, printed p. 30,
explains why the sum of the rotated independent `rho_j` samples is
statistically close to the common-scale distribution. It is not an exact
discrete-Gaussian convolution. Any Protocol 2 rejection implementation must
preserve the paper's statistical-closeness argument and account for its error;
the former `sqrt(2md)` reading was incorrect.

Section 6, printed p. 19, requires one first rejection over all `r` runs'
concatenated `f` vectors (dimension `r*k*(beta-1)*d`) and one response
rejection over the run-major concatenation
`(z^1,z_b^1,z_c^1,...,z^r,z_b^r,z_c^r)` (dimension `3*r*m*d`). The
corresponding center norm-square bounds are `k*r` and `3*B^2*m*d*r`. These
are global decisions, not `r` independent per-run decisions. The stated
extracted-randomness norm bound increases from `24*sqrt(3)*B*m*d` to
`24*sqrt(3*r)*B*m*d`; this is an extraction bound, not a new per-run verifier
response bound.

The Section 6 Gaussian distributions are explicitly `D_s`:
`s=12*d*sqrt(k*r)` for `f_{j,i}` (`i != 0`) and
`s=12*B*sqrt(3*m*d*r)` for each response distribution. Section 2.3 gives
`s=sigma*sqrt(2*pi)`, so the equivalent provider variances would be
`72*d^2*k*r/pi` and `216*B^2*m*d*r/pi`. They are irrational; the current
`ExactDiscreteGaussianProvider` accepts rational `sigma_squared` for
`D_sigma` and cannot represent these Section 6 laws exactly. No Section 6
sampler or batch-rejection caller exists in current source.

An exact \(D_s\) sampler is feasible without converting to irrational
`sigma_squared`. For rational \(S=s^2>0\) and any rational \(a>0\), use the
two-sided geometric proposal with \(\lambda=e^{-\pi(2a/S)}\), then accept
integer \(y\) with probability \(e^{-\pi(|y|-a)^2/S}\). Their product is
proportional to \(e^{-\pi y^2/S}\). Both coins require certified rational
interval refinement for \(\pi\)-dependent exponentials; the existing
`BernoulliExponentialProvider` handles rational logarithms only. This is a
proposed sampler design, not an implemented or validated exact provider. See
`SAMPLER_PARAMETER_RESOLUTION.md` for the parameterized derivation and API.

`ComputeProtocol2IntegerLiftResponses` is reusable per run and returns
unreduced `z`, `z_b`, and `z_c` blocks of `m*d` coefficients. The current
`RespondProtocol2Proof` performs both rejection calls locally and only then
converts those lifts to ring residues; it cannot be used unchanged for the
global decisions. Its private first-stage `rejection_accepts` calculation can
be generalized to the concatenated `f` vector with `K^2=k*r`. The
`AcceptProtocol2JointResponse` helper fixes each block at `m*d` and
`K^2=3*B^2*m*d`; a repeated-run overload must accept `r*m*d` entries in each
response/center block and use `K^2=3*B^2*m*d*r`. Keep the integer lifts until
that global response decision passes.

If either global decision fails, discard all first messages, prover states,
commitments, challenges and partial responses, then regenerate all `r` runs.
Keep the message, ring, key and public parameters fixed across retries. The
current helper interfaces implement neither this restart orchestration nor
the batch decisions.

## 5. Discrepancies and correction status

| Finding | Evidence | Mathematical impact | Proposed correction for a separately reviewed change |
| --- | --- | --- | --- |
| Positive exponent returns rejection | Initially `binary_proof.cpp:313–317`; Algorithm 1, §2.3 p. 8 | If `r>0`, paper threshold exceeds one and always accepts | **Corrected:** `r>=0` now returns true before provider dispatch. |
| Zero exponent delegated to a negative-only API | Initially helper line 319; header API comment lines 76–82 | At `r=0`, required probability is exactly one | **Corrected:** zero is accepted deterministically; provider is called only for strictly negative logs. |
| Lemma 6 strict shift bound vs protocol non-strict bounds | Lemma 6 §2.3 p. 8; Protocol 1 proof, Appendix E Theorem 1 | The printed lemma hypothesis is strict, while the protocol permits equality | **Mathematical extension:** the tail-ratio proof below applies for `||c||<=K` with the same bound. The paper's statement/proof notation remains textually inconsistent. |
| Gaussian provider production validation | Exact Gaussian provider interface and implementation plus deterministic fixtures/tests | Provider existence does not establish its distributional conformance or production suitability | Independently review and validate the provider's distribution, entropy use, and implementation assumptions. |
| Protocol 2 full security validation | P2 prover calls the embedded and joint rejection paths; §5 p. 17 | Functional tests do not establish the Gaussian-sum approximation budget, theorem parameter profile, or cryptographic security; §6 p. 19 repetition remains absent | Account for Appendix E's statistical-closeness error and complete parameter/security review before any security claim. |

The `r>=0` behavior follows the paper's literal comparison and does not alter
any protocol equation. The sampler must still implement `exp(r)` for negative
rational `r` according to the project's separately reviewed exactness
decision.

## 6. Regression coverage and follow-up tests

The deterministic Protocol 1 branch tests in `tests/test_binary_proof.cpp`
and Protocol 2 integration tests in `tests/test_protocol2_proof.cpp` are
registered and have been run. They do not test a production sampler's
probability distribution.

1. **Positive exponent:** construct valid same-length integer vectors and
   positive `phi,K²` for which the exact numerator is positive, including a
   center strictly inside the stated bound. **Added:** assert deterministic
   acceptance; provider call accounting confirms only the later negative
   Protocol 1 stage is delegated.
2. **Zero exponent:** **Added:** construct an exact zero numerator and assert
   acceptance without an exponential-coin call for that stage.
3. **Negative exponent dispatch:** test that a negative exact rational is
   passed unchanged to the provider; use controlled test outcomes for both
   accept and reject, and verify the denominator is positive.
4. **Boundary around zero:** use cases with exponent numerator `-1`, `0`, and
   `+1` (or equivalent exact rational cases) to catch sign reversals and
   branch errors.
5. **Protocol 1 short-circuit:** first-stage rejection must not call the
   second coin; first-stage acceptance must reach it. Confirm response is
   emitted only after both accept.
6. **Signed lift / negacyclic wrap:** choose a monomial crossing degree `d`
   so the coefficient sign flips, then verify the exact lifted dot product
   and exponent supplied to the provider.
7. **Large integer arithmetic:** use large coefficients and dimensions
   within supported allocation limits to confirm `NTL::ZZ` computations
   agree with an independent exact reference and do not overflow.
8. **Norm boundary:** **Added for verifier response bounds:** exact below,
   at, and above cases are tested for the `f` and `z_b` checks. The separate
   strict Lemma 6 shift-support issue is documented below; these verifier
   tests do not settle it.
9. **Provider conformance:** after a production provider exists, test that it
   is invoked only for negative rational logs and statistically validate
   negative-exponent frequencies as a diagnostic, while keeping proof of
   exactness separate from statistical tests. The helper's zero/positive
   deterministic branches are covered independently above.

## 7. Conclusion

The Protocol 1 helper's exponent formula, rational substitution, integer-lift
usage, squared norm bounds, and `r>=0` decision match the displayed Esgin
inputs and Algorithm 1. The Protocol 2 joint helper and prover integration
preserve the joint inputs and integer lifts and apply the same branch rule.
Deterministic tests cover the decision branches, but neither these tests nor
the presence of an exact Bernoulli-exponential provider establish production
distributional correctness. The endpoint extension in Section 10 covers the
norm-bound equality case under the ideal sampler assumptions; the paper's
printed strict condition remains a textual discrepancy.

## 8. Norm-bound condition audit and deterministic boundary tests

### Paper statements

- **Lemma 6, §2.3, p. 8:** the distribution `h` is over `V` whose elements
  “have norm less than `K`.” This is strict: `||c|| < K`.
- **Protocol 1, §4, p. 15:** the verifier checks response limits with
  inclusive `<=`: `||f_{j,i}|| <= 5 phi1 sqrt(dk)`,
  `||f_{j,0}|| <= 5 phi1 sqrt(dk(beta-1))`, and
  `||z_b||, ||z_c|| <= 2 sqrt(2) phi2 B m d` (the last expression is shown
  across the typeset line break in the PDF).
- **Protocol 2, §5, printed p. 17:** the verifier checks
  `||z||, ||z_b||, ||z_c|| <= 2 sqrt(3) phi2 B m d`. These are response
  bounds, distinct from the `B sqrt(3md)` bound on the rejection center.
  The Protocol 2 verifier path checks these response bounds.
- **Appendix E, proof of Theorem 1, printed p. 28:** the completeness argument
  invokes Lemma 6 and states `||(x*b_1)|| <= sqrt(k)` and
  `||(x*r,x*r_c)|| <= B sqrt(2md)`. These are non-strict bounds. They match
  the maxima of the Protocol 1 supports, not strict upper bounds below the
  values of `K` passed to Algorithm 1.
- **Appendix E, Protocol 2 simulation, printed p. 30:** the rotated sum used
  for `z` is statistically close to the common-scale distribution. This is
  an approximation statement, not an assertion that convolution of discrete
  Gaussians is exactly a discrete Gaussian.
- **§2.1, printed p. 5:** for odd `q`, residues are represented in
  `[-(q-1)/2,(q-1)/2]` and Euclidean polynomial/vector norms are coefficient
  norms. The implementation's centered representatives use this convention.

References: [Esgin et al., ePrint 2018/773](https://eprint.iacr.org/2018/773.pdf),
Lemma 6 and Algorithm 1 (p. 8), Protocols 1 and 2 (pp. 15 and 17), and
Appendix E (pp. 28 and 30).

### Implementation trace

- `BeginBinaryProof` checks the witness randomness coefficients satisfy
  `-B <= r_i <= B` and rejects only when `||r||^2 > B^2*m*d`
  (`binary_proof.cpp:393–401`). Thus the implemented relation is inclusive;
  the maximum is attainable when every coefficient is `+B` or `-B`.
- The first Protocol 1 rejection call constructs `c=x*b_1` from the checked
  one-hot witness (`binary_proof.cpp:503–527`) and uses `K^2=k`. Monomial
  multiplication preserves the Euclidean coefficient norm. Each of the `k`
  rows contributes either zero or one unit, so `||c||^2 <= k`, with equality
  possible when every row's one is in a nonzero digit position.
- The second rejection call uses `c=(x*r,x*r_c)` and
  `K^2=B^2*2*m*d` (`binary_proof.cpp:531–541`). The checked witness `r` and
  bounded `r_c` each have `m*d` coefficients in `[-B,B]`; hence
  `||c||^2 <= B^2*2*m*d`. Equality is in the permitted support when both
  vectors have every coefficient at an endpoint. The helper does not add a
  strict `||c|| < K` check.
- `verify_norms` (`binary_proof.cpp:246–275`) evaluates reconstructed `f`
  components and `z_b,z_c` after canonical ring responses have been mapped
  to centered lifts. It squares integer coefficients and compares rational
  bounds by exact cross multiplication in `within_squared_bound`
  (`binary_proof.cpp:93–97`): acceptance is `value_squared * denominator <=
  bound_numerator`. There is no floating-point square root or rounding at the
  boundary. This implements Protocol 1's inclusive verifier inequalities.
- Responses are first reduced into canonical `Z_q` polynomials by
  `from_lift`; the verifier then uses the centered representative selected by
  `Polynomial::centered_coefficient` (`polynomial.cpp:28–35`). This is
  consistent with §2.1's stated centered representation for odd `q`. No
  separate non-centered lift is transmitted for verifier norm checks.

### Boundary tests added

`tests/test_binary_proof.cpp:test_protocol_one_response_norm_boundaries`
constructs internally equation-consistent transcripts and checks the actual
public verifier path. With the test profile `phi1=phi2=B=1`, `d=8`, `k=1`,
`beta=2`, `m=11`, and odd `q=65535`:

| Checked verifier norm | Below bound | Exactly at bound | Above bound | Expected result |
| --- | ---: | ---: | ---: | --- |
| `||f_{0,1}||^2 <= 200` | `10^2+9^2=181` | `10^2+10^2=200` | `14^2+2^2+1^2=201` | accept, accept, reject |
| `||z_b||^2 <= 61,952` | `248^2=61,504` | `248^2+7*8^2=61,952` | `249^2=62,001` | accept, accept, reject |

The companion reconstructed `f_{0,0}` norms also remain in bounds for all
three `f_{0,1}` fixtures. These are deterministic boundary tests, not
statistical sampler tests. No tests or production code were added to Protocol
2.

### Conclusion on strictness

For **Algorithm 1 / Lemma 6**, the printed condition is strictly `||c|| < K`.
For **Protocol 1's verifier responses**, the printed conditions are inclusive
`<=`, and the implementation matches those exact inequalities, centered
representatives, and rational comparisons. For **Protocol 1's rejection
shifts**, the code's support checks establish only `||c|| <= K`; equality is
reachable, as proved by the concrete counterexample in Section 9. The strict
condition is not essential to the rejection-distribution argument: Section
10 derives the same statistical bound at equality from the cited Gaussian
inner-product tail bound. The paper's printed Lemma 6 statement remains
strict, despite its Appendix E use of non-strict bounds and the cited
Lyubashevsky theorem's proof using a closed ball. No bound, parameter, or
implementation behavior was changed.

Verification after adding the deterministic boundary cases: `cmake --build build -j 4` succeeded; `ctest --test-dir build --output-on-failure` passed
**7/7**, including the updated `binary_proof_test` and both Dilithium tests.

## 9. Equality reachability in Protocol 1 rejection shifts

This section resolves reachability; Section 10 resolves the mathematical
extension of the rejection-distribution argument to equality.

### Exact rejection-shift definitions

Protocol 1 §4, p. 15 uses two calls to Algorithm 1 (§2.3, p. 8):

1. First call: `c_1 = x*b_1`, where `b_1` concatenates the one-hot witness
   entries with digit indices `i=1,...,beta-1` across the `k` rows. The bound
   passed as `K` is `sqrt(k)`.
2. Second call: `c_2 = (x*r, x*r_c)`, where `r` is the commitment opening
   randomness and `r_c` is the first-message bounded randomness. The bound
   passed is `B*sqrt(2md)`.

Here `x` is a signed monomial challenge. Multiplication by `x` permutes
coefficient positions and can negate wrapped coefficients, so it preserves
the Euclidean norm of each integer lift.

### Constraints and sharp bounds

For `c_1`, each row of `b` has exactly one constant 1 and all other entries
are zero; all nonconstant coefficients are zero. Removing digit-zero
coordinates leaves either zero or one unit coordinate per row. Thus
`||c_1||^2` equals the number of rows whose one is in a nonzero digit, so
`||c_1||^2 <= k`. Equality holds when every row selects a nonzero digit; the
one-hot rule does not require any row to select digit zero.

For `c_2`, the code validates `r` coefficientwise in `[-B,B]` and checks
`||r||^2 <= B^2md`; `r_c` is sampled coefficientwise from
`{-B,...,B}`. Each of the `2md` coordinates in `(r,r_c)` therefore has
magnitude at most `B`, giving `||c_2||^2 <= 2B^2md`. Equality holds when all
coefficients in both `r` and `r_c` are endpoints `+B` or `-B`. The witness
relation permits such an `r`, and the sampler support includes such an
`r_c`. For finite integer `B>0`, the all-endpoint `r_c` sample has positive
probability. Neither parameter validation nor `rej_accepts` excludes
equality.

### Concrete equation-consistent endpoint example

Use the existing test profile `d=8, m=11, n=1, k=1, beta=2, v=2, B=1,
q=65535, phi1=phi2=1` (toy values, not production parameters). Take
challenge `x=1`, witness bits `b_{0,0}=0`, `b_{0,1}=1`, and every coefficient
of commitment randomness `r` equal to `+1`. Define the public commitment by
`B_pub=Com_ck(b;r)`. The witness is one-hot, `r` lies in `S_B^m`, and
`||r||^2=md=88=B^2md`, so the protocol input constraints hold.

- `c_1=x*b_1=1`, so `||c_1||=1=sqrt(k)=K_1`.
- Choose the allowed bounded-sampler output `r_c` with all `md=88`
  coefficients equal to `+1`. Then `c_2=(r,r_c)` has 176 unit
  coordinates, so `||c_2||^2=176=2B^2md` and `||c_2||=sqrt(176)=K_2`.

The remaining protocol equations can also be satisfied: take the discrete
Gaussian masks `a`, `r_a`, and `r_d` to be zero, form the commitments from the
Protocol 1 equations, and use the valid public opening above. Zero is in the
support of the discrete Gaussian. For these masks, both rejection log
probabilities at `phi1=phi2=1` are `-2`; each ideal exponential decision
accepts with probability `e^-2 > 0`. Therefore an accepting execution with
both equality shifts has positive probability. The all-`+1` `r_c` event may
be small, but is not probability zero under the specified finite uniform
support.

### Effect on Lemma 6 and rejection correctness

The helper computes Algorithm 1's exponent on integer lifts and uses the
specified `min(1,exp(r))` decision. Equality `||c||=K` does not make that
pointwise decision undefined or incorrect. Although Lemma 6 is printed with a
strict hypothesis, Section 10 derives the same distribution bound for
`||c||<=K` using the Gaussian tail estimate in the result cited by Esgin.
Thus strictness is not mathematically necessary for this rejection argument
under those assumptions. The source paper does not spell out this endpoint
extension, and its stated condition remains strict as printed. No inequalities
or implementation code were changed.

## 10. Extending the rejection argument to `||c|| <= K`

This section derives the endpoint case from the Gaussian tail argument behind
the result Esgin cites. It concerns ideal discrete-Gaussian and Bernoulli
decisions; it does not establish that an implementation sampler realizes
those ideal distributions.

### Assumptions and exact ratio

Use Esgin's §2.3 convention that `D_sigma^s` is the spherical discrete normal
on `Z^s` with standard deviation `sigma`. Let `c` be fixed, or sampled from
`h` independently of `y`, with support satisfying `||c|| <= K`; let
`phi > 0`, `sigma = phi*K`, and
`M = mu(phi) = exp(12/phi + 1/(2phi^2))`. Assume `y` is an exact sample from
`f = D_sigma^s`, and use Algorithm 1's ideal clipped acceptance decision.

For fixed `c`, before rejection `z=y+c` has translated discrete-Gaussian
mass `g_c(z)=D^s_{c,sigma}(z)`, while `f(z)=D^s_sigma(z)`. Translation does
not change the normalizing sum, so

```text
R_c(z) = f(z)/g_c(z)
       = exp((-2 <z,c> + ||c||^2)/(2 sigma^2)).
```

Algorithm 1 accepts with `a_c(z)=min(1,R_c(z)/M)`. The probability is defined
for every finite pair `(z,c)`, including `||c||=K`.

### Tail bound including equality

For `c != 0`, put `alpha_c=sigma/||c||`. The closed bound implies

```text
alpha_c = phi*K/||c|| >= phi,
```

and at equality `alpha_c=phi`. Lyubashevsky's rejection-sampling analysis
(Lemma 4.3 and Lemma 4.5 in the full version cited by Esgin as [22]) gives,
for `z <- D_sigma^s`,

```text
Pr[ |<z,c>| > 12 ||c|| sigma ] <= 2 exp(-72) < 2^-100.
```

Outside this tail event,

```text
log R_c(z)
 = -<z,c>/sigma^2 + ||c||^2/(2 sigma^2)
 <= 12/alpha_c + 1/(2 alpha_c^2)
 <= 12/phi + 1/(2 phi^2)
 = log M.
```

The second inequality uses only `alpha_c >= phi`, so it remains true at
equality. Hence the clipping set `E_c={z:R_c(z)>M}` has target-Gaussian
probability at most `epsilon=2^-100`, uniformly for every `c` with
`||c||<=K`. For `c=0`, `R_c(z)=1<M`, so `E_c` is empty. The derivation has
no division by `K-||c||` and requires no strict slack.

Reference: Lyubashevsky, *Lattice Signatures Without Trapdoors*, full version
ePrint 2011/537, §4, especially Lemma 4.5, Theorem 4.6, and its proof at p. 13
([official ePrint PDF](https://eprint.iacr.org/2011/537.pdf)). Esgin cites this
result as [22] immediately before Lemma 6. The cited Theorem 4.6 statement
uses `||v||<T`, but its proof instantiates `V` as vectors of length at most
`T` (p. 13); this is a strict/non-strict textual mismatch in the cited source
too. The tail derivation above independently establishes the closed-bound
case for Esgin's concrete parameterization.

### Acceptance probability and conditional output law

For each fixed `c`, the unnormalized accepted mass is

```text
A_c(z) = g_c(z) * min(1, f(z)/(M*g_c(z)))
       = min(g_c(z), f(z)/M).
```

The ideal experiment has sub-probability mass `I_c(z)=f(z)/M`. The deficit
`I_c(z)-A_c(z)` is nonnegative, supported only on `E_c`, and bounded by

```text
delta_c = sum_z (I_c(z)-A_c(z))
         <= (1/M) * Pr_{z<-f}[E_c]
         <= epsilon/M.
```

Thus the acceptance probability is `1/M-delta_c`, within `epsilon/M` of
`1/M`; averaging over any `h` supported on the closed ball preserves this
bound.

For the conditional output distribution, let `P(c,z)=h(c)f(z)` be the ideal
normalized joint law, and let `T(c,z)=M*h(c)*A_c(z)` be the scaled accepted
sub-probability. Then `0<=T<=P`, with total mass `1-eta` and
`eta=M*E_h[delta_c]<=epsilon`. Set `D=P-T`; then `0<=D<=P` and its mass is
`eta`. On the support of `P`, write `w=D/P`, so `0<=w<=1` and `E_P[w]=eta`.
The accepted joint law is `Q=T/(1-eta)`, and

```text
TV(P,Q) = E_P[|w-eta|] / (2(1-eta)) <= eta <= epsilon,
```

because `|w-eta| <= eta(1-w)+(1-eta)w`; taking expectations bounds the
numerator by `2eta(1-eta)`. Marginalization cannot increase total variation,
so conditioned on acceptance, `z` is within `epsilon=2^-100` of
`D_sigma^s`. This proves the requested extension under the assumptions above.

### What this resolves

- **Probability defined:** the clipped probability is defined at equality
  (indeed, for every shift).
- **Intended distribution:** under the exact Gaussian model and tail bound,
  equality retains the same `2^-100` conditional output guarantee and an
  acceptance probability within `2^-100/M` of `1/M`.
- **Paper's literal statement:** Esgin Lemma 6 still prints `<K`; Protocol 1
  and its Appendix E completeness proof use `<=K`. The endpoint extension
  above is a mathematical derivation from the cited tail estimate, not an
  Esgin erratum or a statement explicitly written in their lemma.
- **Security scope:** this resolves the equality endpoint in the rejection
  sampling argument only. It does not validate production samplers, other
  protocol steps, parameters, or the full ring-signature security proof.
