# Production Sampling Design Decisions

**Purpose:** settle recommended API and production-sampling requirements for
the Esgin PQ-LRS implementation. This is a design decision record, not a
Gaussian sampler or a cryptographic security review.

**Sources reviewed:**

- Esgin et al., *Short Lattice-based One-out-of-Many Proofs and Applications
  to Ring Signatures*, ePrint 2018/773: §2.3 and Algorithm 1 (printed pp. 7–8),
  Protocol 1 (§4, pp. 14–15), Protocol 2 (§5, pp. 16–17), Section 6 (p. 19),
  and Appendix E. [Official paper PDF](https://eprint.iacr.org/2018/773.pdf).
- Local audits: [DISCRETE_GAUSSIAN_SAMPLER_SPEC.md](DISCRETE_GAUSSIAN_SAMPLER_SPEC.md),
  [SAMPLER_PARAMETER_RESOLUTION.md](SAMPLER_PARAMETER_RESOLUTION.md), and
  [PROTOCOL1_AUDIT_AND_PROTOCOL2_PLAN.md](PROTOCOL1_AUDIT_AND_PROTOCOL2_PLAN.md).

## 1. Decision: make standard deviation the canonical API convention

### Recommended API contract

The C++ Gaussian provider should accept the square of Esgin’s
**standard-deviation parameter**, named `sigma_squared`, as a
positive exact rational and sample one integer
coefficient `x in Z` with probability mass

```text
Pr[x] = exp(-x^2 / (2*sigma_squared)) / Z,
Z = sum_{t in Z} exp(-t^2 / (2*sigma_squared)).
```

This is Esgin’s `D_sigma` convention, with
`sigma=sqrt(sigma_squared)`. The
provider returns an unreduced integer coefficient. Polynomial and vector
samplers build independent coefficient draws from this scalar provider.
Sampling never reduces a Gaussian result modulo `q`.

Use this as the API’s sole public convention. Do not accept a parameter named
only `scale`, `width`, or `sigma` where its meaning is unclear. The contract
must state that the input is the square of Esgin’s `D_sigma` parameter, not
the square of the alternate `D_s` parameter.

### Mathematical justification

Esgin §2.3, p. 7 defines `D_s` with mass proportional to
`exp(-pi*x²/s²)` and defines `D_sigma` as the discrete normal with standard
deviation `sigma`, where `s=sigma*sqrt(2*pi)`. Therefore

```text
s^2 = 2*pi*sigma^2
exp(-pi*x^2/s^2) = exp(-x^2/(2*sigma^2)).
```

The protocol algorithms and Lemma 4/6 use `D_sigma` and standard-deviation
widths. Making `sigma_squared` canonical avoids carrying `pi` in
an API whose protocol widths have rational squares. The
`DiscreteGaussianProvider` declaration now uses this `D_sigma` convention.
At the time this API decision was recorded, the production sampler was not
implemented; its implementation status is recorded in §9.

### Resolution

Esgin’s Protocol 1 widths and rejection parameters use `D_sigma`. The provider
contract is aligned to that convention, and the exact-rational Protocol 1
arguments remain unchanged. The conversion `s²=2*pi*sigma²` applies only when
expressing the same law with `D_s`; no floating-point approximation of `pi`
is part of this API.

## 2. Protocol 1 mapping to the canonical API

The provider receives `sigma_squared`, obtained by squaring the
paper’s standard-deviation width. No `2*pi` factor is applied to this API.
The `2*pi` factor is only needed when converting to the alternate `D_s`
parameterization.

| Protocol 1 vector | Paper width (Esgin §4, Protocol 1, p. 15) | Canonical provider parameter squared |
| --- | --- | --- |
| Each `a_{j,i}`, `i=1,...,beta-1` | `sigma_a=phi1*sqrt(k)` | `sigma_a²=phi1²*k` |
| `r_a` and `r_d`, each an `md`-coordinate vector | `sigma_r=phi2*B*sqrt(2md)` | `sigma_r²=phi2²*B²*2md` |

The current call sites already calculate these squared widths:
`binary_proof.cpp:408–418` for `a`, and `:433–442` for `r_a,r_d`. They are
**correct values for the aligned canonical `D_sigma` API**. No runtime
Gaussian provider existed at the time of this call-site audit; deterministic
test providers do not establish a distribution.

For comparison, if a future internal implementation insists on evaluating the
`D_s` mass directly, the corresponding parameter would be
`s²=2*pi*sigma_squared`; that internal conversion must preserve the same
target law. It must not be achieved by simply passing
`sigma_squared` as
`s²`.

Protocol 1 rejection uses `sigma=phi*K` (Algorithm 1, p. 8). This is also a
standard deviation. In its current two calls, `K²=k` and `K²=B²*2md`, so
their squared rejection widths agree with the two rows above. The Bernoulli
decision calculation is separate from the base Gaussian API parameter and
must retain Algorithm 1’s exact `phi`, `K`, center and sign convention.

## 3. Protocol 2 `sqrt(2md)` versus `sqrt(3md)`

### What the paper explicitly states

1. Protocol 2 calls `P_bin[1–8]`, reusing Protocol 1’s first-message steps.
   The note below Protocol 2, p. 17, explicitly says embedded `r_a,r_d` are
   sampled from `D_sigma` with width
   `sigma_2=phi2*B*sqrt(2md)`.
2. Protocol 2 samples each of `k` vectors `rho_j` from `D_sigma` with width
   `sigma_rho=phi2*B*sqrt(3md/k)` (p. 17).
3. It forms `z=x^k*r-sum_j x^j*rho_j` and applies one rejection step to
   `(z,z_b,z_c)` with `phi2` and `K=B*sqrt(3md)` (p. 17). Algorithm 1 thus
   uses target/rejection standard deviation
   `sigma_3=phi2*B*sqrt(3md)`.
4. Because multiplication by each challenge monomial `x^j` is a signed
   coefficient permutation, the sum of their squared Gaussian parameters is
   `k*sigma_rho²=phi2²*B²*3md`, matching `sigma_3²` at the parameter level.
   This arithmetic does not prove that a convolution of discrete Gaussians is
   exactly a single discrete Gaussian with parameter `sigma_3`; no such
   equality is asserted here.
5. The same page’s note still states `sigma_2` for `r_a,r_d`. Appendix E’s
   Protocol 2 simulator samples `z,z_b,z_c` from the common
   `D_{phi2 B sqrt(3md)}` distribution. Section 6’s repeated version also
   specifies `sqrt(3mdr)` response widths (p. 19).

### Mathematical mismatch and possible interpretations

Before rejection, `z_b` and `z_c` contain `r_a` and `r_d`; under the explicit
Protocol 2 note their Gaussian noise parameter is `sigma_2`. The `rho_j`
parameter squares sum to `sigma_3²`, but their discrete convolution is not
shown to equal `D_sigma3`; the joint `Rej` is parameterized using `sigma_3`.
Lemma 6, §2.3, p. 8 establishes its rejection result for a vector
sampled from a single `D_sigma` and a bounded shift. It does not state a result
for this apparent heterogeneous-width input. The Appendix E simulator’s
common `sigma_3` output therefore does not, by itself, prove that the stated
real first-message distributions yield that output.

Possible interpretations, none selected here:

- **Typo in the Protocol 2 note:** `r_a,r_d` were intended to use
  `sigma_3`, matching the joint rejection target and simulator. This changes
  an explicit printed statement and cannot be assumed.
- **A heterogeneous rejection argument is intended:** an additional argument
  may show that the joint operation has the required law despite the
  different input widths. The cited Lemma 6 does not supply that argument as
  stated; it would need to be found in or established from the complete proof.
- **A different item is misstated:** the joint rejection scale, the `rho_j`
  width, or the simulator width could instead be wrong. Altering any one
  would change another explicit equation or proof claim.

**Decision:** keep Protocol 2 sampling and rejection implementation blocked.
Do not change `r_a,r_d`, `rho_j`, the rejection `K`, or simulator equations
without author clarification or an independent cryptographic proof review.

## 4. Exactness and statistical error budget

### Recommended contract

Require the production base Gaussian provider and Bernoulli-exponential
provider to implement their specified probability laws **exactly**. The
sampler-induced statistical-distance budget is therefore zero relative to the
mathematical distributions at the provider boundary. Exactness means the
output probability for every integer is the stated normalized mass; it does
not mean fixed-precision floating-point approximations are “close enough.”

This is the safest contract because Esgin specifies ideal distributions and
does not allocate a machine-sampler error budget. The paper’s Lemma 6 bound of
`2^-100` is a theoretical bound for its rejection-sampling statement; it is
not a mandate or allowance for 100-bit numeric arithmetic, and it is not an
aggregate implementation-error budget.

An exact algorithm may use a variable number of unbiased random bits and
terminate almost surely. Its termination and timing behavior must be reviewed
separately. If exact implementation is not practical and approximation is
proposed, production approval requires a written error analysis specifying:

- a per-scalar total-variation/statistical-distance bound;
- a union/composition bound over all coefficients, messages, abort/retry
  loops, Protocol 2 draws, Section 6 repetitions and signatures;
- numerical rounding direction, tail handling and finite support behavior;
- how this additional error composes with the paper’s Lemma 6 and security
  bounds; and
- explicit supervisor and independent cryptographic reviewer approval.

No nonzero `epsilon` is assigned here. Until such an analysis is approved, the
acceptable implementation approximation budget is **none**.

## 5. Bernoulli-exponential requirement

Algorithm 1, §2.3, p. 8 requires acceptance probability

```text
p = exp(-1/phi - 1/(2*phi^2)
        + (-2*<z,c> + ||c||^2)/(2*phi^2*K^2)),
```

where `sigma=phi*K`, `||c||<K`, and `z` is the shifted integer response as
defined by the algorithm. The response and center are integer vectors; with
rational `phi` and rational `K²`, the log-probability is an exact rational.
The current code computes that rational by integer arithmetic and delegates
the Bernoulli decision through `BernoulliExponentialProvider`.

The production interface must:

- return a Bernoulli outcome with exactly `Pr[true]=exp(r)` for the supplied
  rational `r<=0`; `r=0` has deterministic outcome true;
- consume unbiased random bits from the OS-backed source (or a reviewed
  CSPRNG seeded from it), without modulo bias;
- fail closed on entropy, arithmetic or internal errors, never substitute a
  floating-point comparison or fixed-width uniform;
- enforce or safely handle `r<=0`; if a proof precondition violation produces
  `r>0`, reject the invocation as malformed rather than clamping the
  probability;
- document almost-sure termination, worst-case runtime behavior, and
  side-channel treatment.

The paper specifies an ideal uniform `u in [0,1)` comparison. It does not
specify a finite-bit Bernoulli-exponential routine or a machine precision.
The project now implements `ExactBernoulliExponentialProvider` using rational
interval refinement and the existing `RandomSource`; its dedicated test and
full CTest suite have passed. Independent mathematical, randomness, timing,
and security review remains outstanding. The Gaussian provider was
subsequently implemented; its algorithm, test results, and remaining review
gaps are recorded in §9.

## 6. Timing and side-channel requirements

The signing implementation must treat Gaussian samples, rejection centers,
accept/abort outcomes and retry state as sensitive. Exact rejection and
geometric samplers commonly have data-dependent iteration counts. The required
production policy is:

1. No externally observable timing, branch, memory-access, cache, exception,
   logging or resource-use behavior may depend on secret witness material or
   reveal a mask/response relationship beyond the protocol’s intended public
   outputs.
2. Prefer constant-time or fixed-work implementations where feasible.
   If an exact algorithm is variable-time, document which values control its
   runtime and establish by independent review that the leakage is acceptable
   in the deployment threat model. Do not assume “random mask” means its
   timing is harmless.
3. Rejection/abort and full-signature retry counts are observable protocol
   behavior. They must follow the paper’s specified distributions and be
   included in the leakage and denial-of-service analysis; do not cap retries
   and emit a conditionally sampled result. A resource cap may terminate the
   attempt with failure only if its effect on conditioning and protocol
   security is separately analyzed.
4. Never log raw Gaussian samples, seed material, intermediate rejection
   values, private openings or exception text containing them. Clear temporary
   secret buffers where the underlying NTL allocation model permits, and
   document what cannot be reliably wiped.
5. Entropy failure must abort signing. There is no fallback to a weaker or
   non-cryptographic PRNG.

The paper does not state a side-channel threat model or require a particular
constant-time technique. The policy above is a production engineering
requirement, but the acceptable variable-time tradeoff needs supervisor and
cryptographic reviewer approval.

## 7. Recommended production sampler implementation specification

1. **Gaussian API:** a scalar provider takes exact positive rational
   `sigma_squared` and returns `ZZ` distributed as
   `exp(-x²/(2*sigma_squared))/Z` over all `Z`. Coordinate-vector
   sampling independently invokes this scalar provider and preserves integer
   lifts.
2. **Protocol 1 adapter values:** use `phi1²*k` for each coefficient of each
   `a_{j,i}` (`i>0`), and `phi2²*B²*2*m*d` for each coefficient of `r_a,r_d`.
   These values are standard-deviation squared; do not multiply by `2*pi` for
   this API. If an internal algorithm uses Esgin `D_s`, convert internally by
   `s²=2*pi*sigma_squared` without approximation or document a proven exact
   equivalent.
3. **Protocol 2 adapter values:** once the paper discrepancy is resolved,
   encode the confirmed widths as rational parameter squares. The paper
   currently prints `phi2²*B²*2md` for `r_a,r_d`,
   `phi2²*B²*3md/k` for each `rho_j`,
   and uses `K²=B²*3md` for the joint rejection. Do not ship P2 sampling while
   these statements remain unreconciled.
4. **Implemented algorithm:** exact rejection from a two-sided geometric
   proposal with the exact Bernoulli-exponential primitive, as described in
   `DISCRETE_GAUSSIAN_SAMPLER_SPEC.md`. The implementation selects
   `tau=1/k`, with `k=max(1,ceil(sqrt(sigma_squared)))`, using integer
   arithmetic. The derivation is documented; independent mathematical review,
   performance evaluation, and timing analysis remain outstanding.
5. **Bernoulli exponential:** exact `exp(r)` Bernoulli for rational `r<=0`,
   with unbiased cryptographic random bits, explicit fail-closed errors,
   and a documented runtime/leakage analysis.
6. **Numerical contract:** exact output laws are the default. A nonzero
   approximation budget requires a separate quantified composition analysis
   and written approval; no precision or epsilon is inferred from `2^-100`.
7. **Validation:** unit tests for parameter mapping and edge cases, deterministic
   branch tests using test-only sources, statistical diagnostics against
   high-precision reference values, failure propagation, independence checks,
   and an independent mathematical/implementation review. Statistical tests
   are diagnostics, not proof of exactness or cryptographic security.
8. **Readiness gates:** resolve Protocol 2 widths, response integer-lift and
   centered-residue semantics, exact Bernoulli algorithm and side-channel
   policy before production sampling is integrated into any proof.

## 8. Decisions still requiring approval or clarification

1. Independently review the implemented Gaussian provider and its
   `D_sigma`/`sigma_squared` contract.
2. Author clarification or independent proof review of the Protocol 2
   `sqrt(2md)` / `sqrt(3md)` conflict and Appendix E simulator distribution.
3. Confirmation of the exact-versus-approximate implementation contract. This
   document recommends exact; any nonzero error budget needs separate
   quantitative security analysis and approval.
4. Independent review of the implemented exact Bernoulli-exponential
   algorithm, including its randomness, termination, and timing properties.
5. Approval of the deployment side-channel threat model and any variable-time
   sampling/rejection behavior.
6. Review of modular response encoding and norm checks for rare Gaussian tails.

**Conclusion at the time of this decision:** the sampler should expose
Esgin’s standard-deviation convention as an exact rational parameter-square
API, use exact Bernoulli-exponential decisions, preserve integer lifts, and
have no sampler-induced approximation budget by default. Protocol 1’s current
numeric call values already represented the correct parameter squares for the
aligned API. The current implementation status and outstanding review gates
are recorded in §9.

## 9. Final sampler specification disposition

This section supersedes earlier open API-choice and implementation-status
wording above. It records the current implementation and remaining review
gates; it does not imply production approval.

1. **Canonical provider input:** exact positive rational `sigma_squared`,
   meaning the square of Esgin’s `D_sigma` standard deviation. The scalar
   output is an unreduced integer with mass proportional to
   `exp(-x^2/(2*sigma_squared))` over all `Z`. The source interface is now
   named and documented with these semantics. Do not offer `D_s` as a second
   mode.
2. **Protocol 1 mapping:** `phi1^2*k` per coefficient for each `a_{j,i}`
   with `i>0`; `phi2^2*B^2*2*m*d` per coefficient for `r_a` and `r_d`, each
   with `m*d` coordinates. `a_{j,0}` is the negative row sum, not an
   independent draw. The current source passes these exact rational values
   under the aligned `D_sigma` contract.
3. **Implemented algorithm:** exact rejection sampling with the difference
   of two independent geometric variables as a two-sided discrete-Laplace
   proposal. For positive rational target variance `v=a/b`, the implementation
   chooses `k=max(1,ceil(sqrt(v)))`, `tau=1/k`, and uses exact
   Bernoulli(`exp(-tau)`) proposal trials. It accepts `y` with
   `exp(-y^2/(2v)+tau*abs(y)-v*tau^2/2)`, passing the equivalent exact
   rational `-(b*k*abs(y)-a)^2/(2*a*b*k^2)`. Completing the square proves the
   exponent is nonpositive; proposal times acceptance is proportional to the
   exact target weight. The rate changes efficiency, not the target law. See
   the full derivation in
   [DISCRETE_GAUSSIAN_SAMPLER_SPEC.md](DISCRETE_GAUSSIAN_SAMPLER_SPEC.md).
4. **Tail and numerical contract:** preserve infinite support; do not truncate
   or clip. Require exact Bernoulli decisions for rational exponents using
   certified adaptive precision/unbiased random bits, with almost-sure
   termination. The sampler-induced statistical-distance budget is zero.
   The paper’s `2^-100` rejection bound is not a machine precision or
   implementation-error allowance.
5. **Protocol 2 remains unresolved:** the paper explicitly retains
   `sqrt(2md)` for embedded `r_a,r_d`, gives `sqrt(3md/k)` for each `rho_j`,
   and uses `sqrt(3md)` for joint rejection and the simulator. Neither width
   is changed here; P2 production sampling remains blocked pending
   clarification or independent proof.
6. **Testing and randomness:** production composes the existing fail-closed
   `RandomSource` and Bernoulli-exponential provider; deterministic fixtures
   stay in the test target. The focused test covers invalid parameters,
   scripted proposal/accept/reject paths, fractional and large exact values,
   RNG failure propagation, and a 2,048-draw diagnostic of mean, second
   moment, and one tail frequency at `sigma_squared=1`. The dedicated test
   and full CTest suite passed (10/10). The statistical check is diagnostic,
   not proof. More extensive tails, independence, protocol mapping, and
   formal statistical analysis remain uncovered.
7. **Side channels:** the geometric, Bernoulli-refinement, and rejection
   loops are variable-time with unbounded worst-case runtime. Esgin provides
   no sampler side-channel model. A deployment threat model and independent
   leakage review are required; do not claim constant-time behavior.

**Current disposition:** the notation and Protocol 1 API semantics are
aligned, and `ExactDiscreteGaussianProvider` is implemented. Its mathematical
exactness claim is conditional on the correctness of the Bernoulli-
exponential implementation and independent unbiased random bits. The build,
dedicated test, and complete CTest suite passed; this establishes functionality
only, not a proof of the distribution or cryptographic security. Independent
mathematical and implementation review, broader validation, and deployment
side-channel analysis remain outstanding. Protocol 2 cannot be wired until
its width/distribution proof discrepancy is resolved.
