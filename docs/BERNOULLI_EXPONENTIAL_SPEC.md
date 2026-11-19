# Bernoulli-Exponential Sampling Specification

**Status:** the standalone Bernoulli-exponential provider and its dedicated
test are implemented. This specification documents that implementation and
its limitations. It does not certify the protocol or claim production
readiness or cryptographic security.

**Primary reference:** Esgin et al., *Short Lattice-based One-out-of-Many
Proofs and Applications to Ring Signatures*, ePrint 2018/773. Algorithm 1 and
Lemma 6 (§2.3, printed p. 8), Protocol 1 (§4, pp. 14–15), Protocol 2 (§5,
p. 17), and the Section 6 repeated variant (§6, p. 19). [Official paper PDF](https://eprint.iacr.org/2018/773.pdf).

## 1. Required distribution

Algorithm 1 `Rej(z,c,phi,K)` sets

```text
sigma = phi*K
mu(phi) = exp(1/phi + 1/(2*phi^2))
p_raw = (1/mu(phi)) * exp((-2*<z,c> + ||c||^2)/(2*sigma^2)).
```

It draws `u` uniformly from `[0,1)` and aborts if `u > p_raw`; otherwise it
accepts. Thus the exact Bernoulli probability represented by the algorithm’s
comparison is

```text
p = min(1, p_raw) = min(1, exp(r)),
r = -1/phi - 1/(2*phi^2)
    + (-2*<z,c> + ||c||^2)/(2*phi^2*K^2).
```

For `r<0`, this is a Bernoulli event with probability `exp(r)`. For `r>=0`,
the comparison against `u in [0,1)` accepts with probability one. At `r=0`,
acceptance is deterministic. This clamp follows directly from Algorithm 1’s
comparison; the paper does not separately name a `min(1,...)` operator.

The protocol supplies integer vectors, integer inner products and squared
norms. With rational `phi` and rational `K²`, `r` is rational. No Gaussian
normalization constant is involved in this Bernoulli primitive. `K` is a
positive norm bound for the shift `c`; the primitive receives `K²` or an
equivalent exact representation to avoid unnecessary square roots.

## 2. Uses in Esgin’s construction

### Protocol 1

Protocol 1 (§4, p. 15) makes two rejection decisions, sequentially. If the
first rejects, it aborts without the second call.

1. **Binary mask response:**

   ```text
   Rej(f_1, x*b_1, phi1, sqrt(k))
   ```

   Here `z=f_1`, `c=x*b_1`, and `K²=k`.

2. **Commitment-randomness response:**

   ```text
   Rej((z_b,z_c), x*(r,r_c), phi2, B*sqrt(2*m*d))
   ```

   Here `z=(z_b,z_c)`, `c=x*(r,r_c)`, and `K²=B²*2*m*d`.

The formula is the same in both calls; the input vectors, `phi`, and `K²`
change. Algorithm 1, not a floating-point approximation to it, defines the
decision.

### Protocol 2

Protocol 2 (§5, p. 17) invokes the Protocol 1 first-response/rejection part
for the digit proof, then uses a joint second rejection:

1. The embedded `P_bin` response keeps the first call on `(f_1,x*b_1)` with
   `phi1` and `K²=k`.
2. It replaces the standalone Protocol 1 second call with:

   ```text
   Rej((z,z_b,z_c), (x^k*r, x*r_b, x*r_c),
       phi2, B*sqrt(3*m*d)).
   ```

   Thus this call uses the same `min(1,exp(r))` Bernoulli rule, with a
   `3md`-coordinate concatenation and `K²=B²*3*m*d`.

The documented `r_a,r_d` versus joint-width distribution discrepancy is
recorded in [SAMPLING_DESIGN_DECISIONS.md](SAMPLING_DESIGN_DECISIONS.md) and
remains unresolved. The Bernoulli primitive can implement the displayed
probability independently, but its correctness does not resolve whether
Protocol 2’s Gaussian inputs satisfy the hypotheses needed for the claimed
rejection distribution.

### Section 6 repeated protocol

The ring-signature variant (§6, p. 19) applies rejection to concatenations
across all `r` repeated proofs: the concatenated `f_1` blocks use the first
kind of call, and the concatenated `(z,z_b,z_c)` blocks use the second kind.
The same scalar formula applies with the paper’s repeated-vector `phi` and
`K`; in particular the response concatenation has `3mdr` coordinates and
the stated `K=B*sqrt(3mdr)`. This document does not choose production
parameters or alter the Section 6 equations.

## 3. Implemented C++ path

- `cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp:74–82` declares
  `BernoulliExponentialProvider::sample_exp(log_numerator,log_denominator,
  RandomSource&)`, documented for a strictly negative rational log.
- `cpp_backend/include/lattice_lrs/proofs/bernoulli_exponential.hpp` and
  `cpp_backend/src/proofs/bernoulli_exponential.cpp` implement
  `ExactBernoulliExponentialProvider`. The provider validates a positive
  denominator and strictly negative numerator; it uses only NTL integer
  rational arithmetic for the exponential and uniform interval decisions.
- `cpp_backend/src/proofs/binary_proof.cpp:291–319` computes integer dot
  products and squared norms, forms the exponent as an exact rational using
  `NTL::ZZ`, deterministically accepts when the exponent is nonnegative, and
  calls the provider only for a negative exponent. This matches Algorithm 1's
  comparison against a uniform in `[0,1)`.
- `cpp_backend/include/lattice_lrs/sampling/random_source.hpp` exposes the
  injectable byte source. `sampling/random_source.cpp` obtains production
  bytes from the platform OS random facility and propagates failures. The
  implementation consumes the high bit first from each byte; it does not use
  floating-point thresholds, modulo conversion, or an ordinary PRNG.
- `tests/test_bernoulli_exponential.cpp` exercises deterministic interval
  decisions, invalid inputs, RNG failure propagation, very small and large
  rational inputs, and a statistical diagnostic. The statistical check is
  diagnostic only, not a proof of correctness.

### Nonnegative-exponent behavior

The provider itself accepts only `r<0`. The Protocol 1 rejection helper
handles `r>=0` before calling it, returning deterministic accept as required
by the displayed `u > p_raw` comparison. Whether other hypotheses used in
the paper's rejection-distribution analysis hold for the protocol's full
sample support remains a separate protocol question.

## 4. Numerical precision and exact decisions

### What Esgin specifies

Algorithm 1 specifies an ideal real uniform and an exponential probability.
Lemma 6, §2.3, p. 8 gives theoretical bounds of `2^-100` on the rejection
acceptance probability and conditional distribution relative to its stated
target. These are mathematical rejection-sampling bounds; the paper does not
specify machine precision, a fixed-point format, a maximum Taylor-series
length, or a numerical-error allowance for computing `exp` or the uniform
comparison. `2^-100` must not be treated as a 100-bit implementation
precision requirement or an available implementation-error budget.

### Implemented exact random-bit comparison

For `r<0`, the provider sets `x=-r>0` and writes `x=n+f`, where `n` is a
nonnegative integer and `0<=f<1`. It samples `n` independent
Bernoulli(`exp(-1)`) coins and, if all accept, samples one
Bernoulli(`exp(-f)`) coin when `f>0`. If `f=0`, there is no fractional coin.
Since `exp(-x)=exp(-1)^n * exp(-f)`, the product has the requested probability.
The decomposition and all comparisons use exact integer rational arithmetic.

For each unit-interval coin with `0<x<=1`, the implementation encloses
`exp(-x)` by successive partial sums of its alternating Taylor series:

```text
S_j = sum(k=0..j) (-x)^k/k!
S_1 <= exp(-x) <= S_0
S_3 <= exp(-x) <= S_2
S_5 <= exp(-x) <= S_4, ...
```

The terms decrease in magnitude for `0<x<=1`. The code initializes the lower
bound to `S_1=1-x` and the upper bound to `S_0=1`, then adds or subtracts one
exact rational term per refinement, maintaining the corresponding odd/even
bounds. The series terms converge to `exp(-x)`, so the enclosure width tends
to zero.

The random bits define nested rational intervals for a conceptual uniform
`U` in `[0,1)`: after each bit, the interval is bisected. If the uniform
interval's upper endpoint is at most the exponential lower bound, the coin
accepts; if its lower endpoint is at least the exponential upper bound, it
rejects. Otherwise the implementation refines both enclosures. Comparisons
are exact cross-multiplied integer comparisons, not rounded floating-point
comparisons.

Under independent unbiased random bits, the resulting Bernoulli probability
is exactly `exp(-x)`. For any fixed `x`, the uniform interval width tends to
zero and the exponential enclosure converges. A continuous uniform equals
the threshold with probability zero, so the intervals eventually separate
with probability one: termination is almost sure, not guaranteed within a
fixed number of steps. Runtime is unbounded in the worst case and depends on
the input and random bits. There is no iteration cap or constant-time claim.

This exactness statement is for the independent-unbiased-bit model. In
production, `SystemRandomSource` obtains bytes from the operating system;
the security argument then relies on the operating system source's
computational randomness assumptions, not on a proof that its output is
mathematically independent and uniform.

### Alternatives

| Method | Exact for this requirement? | Assessment |
| --- | --- | --- |
| Certified interval refinement plus unbiased bits | Yes, if bounds are rigorous and the comparison is refined to a decision | Implemented here; almost-sure termination, variable time, and careful proof of interval arithmetic required |
| A specialized exact Bernoulli-exponential / exponential-coin algorithm | Potentially; only with a proof for rational negative exponents and full input range | Could be faster or have better resource bounds. Select only after independent correctness, termination, entropy and side-channel review |
| Floating-point `exp(r)` followed by a finite-width uniform comparison | No, absent a quantified approximation proof | Rounds both threshold and uniform; does not reproduce the exact event |
| Fixed-point table or truncated series without correction | No | Produces a biased probability; finite precision alone is not a correctness argument |
| Approximate method with certified error | Not exact; possibly acceptable only after a separate security/error-budget decision | Esgin does not give a machine-sampler error allocation; no nonzero allowance is chosen here |

No numeric precision requirement can be derived from the paper. Under the
project’s current design decision, primitive-induced probability error must
be zero. If the project later permits approximation, the supervisor and
cryptographic reviewer must set and justify a bound that composes across all
calls, protocol aborts/retries, Section 6 repetitions and signatures. Do not
invent a value.

## 5. Randomness and failures

- Use unbiased bits from `SystemRandomSource` or a reviewed CSPRNG seeded with
  OS entropy. Existing `RandomSource::fill_bytes` is injectable for tests;
  deterministic sources remain test-only.
- Avoid modulo reduction and biased extraction. If the exact coin uses
  rational interval comparison, each bit must be independent and unbiased
  under the model; a CSPRNG implementation provides the computational
  randomness assumption, which should be documented.
- On entropy, arithmetic, interval-certification or internal failure, abort
  the signing attempt and emit no response. Do not substitute a threshold,
  accept/reject default, approximate fallback, or ordinary PRNG.
- Explicitly handle `r>=0` as deterministic accept according to the paper’s
  comparison. Validate denominator positive and avoid overflow using NTL
  integers for exponent arithmetic.
- A runtime cap cannot return a conditioned Bernoulli result. If a cap is
  operationally necessary, it must fail the signing attempt and be included
  in the protocol’s abort/completeness and timing analysis.

## 6. Timing and side-channel considerations

Exact interval refinement reveals how many bits were needed to decide the
threshold. That count depends on the distance between `U` and `exp(r)`, and
thus on the exponent and random tape. The exponent contains response and
center values correlated with protocol masks and witnesses. The primitive’s
timing is therefore not automatically harmless because it only handles
randomized values.

Production review must assess:

- timing, branches, cache/memory behavior and error handling as a function of
  `r` and random bits;
- whether the measured timing can reveal masks, response values or witness
  relations through public transcript equations;
- observable per-stage abort/retry behavior, especially Protocol 1’s two
  sequential rejections and the outer signature retry loop;
- whether a constant-time/fixed-work exact approach is available; and
- if variable-time exact sampling remains, whether its leakage is acceptable
  under an explicit deployment threat model reviewed by a cryptographer.

The paper supplies no side-channel model or implementation requirement. Do
not claim constant-time behavior for an adaptive-precision algorithm without
measurement and code review. Avoid logging exponents, dot products,
threshold-enclosure state, random bits or private response material.

## 7. Dependency on the discrete-Gaussian sampler

The Bernoulli-exponential function is a standalone probability primitive: for
given rational `r`, it needs only unbiased random bits and certified
exponential comparison. It does not need the Gaussian normalization factor
or sample `D_sigma` itself.

The *protocol correctness argument* does depend on both components:

1. Gaussian sampling creates the masks and response shifts with the target
   `D_sigma` laws.
2. The Bernoulli decision applies Algorithm 1 to the resulting response and
   center and produces the claimed accepted distribution/abort probability.

An exact Bernoulli primitive cannot repair a wrongly parameterized Gaussian,
the unresolved Protocol 2 heterogeneous-width issue, or incorrect integer
lift/modular-response handling. Conversely, a correct Gaussian provider does
not make an approximate Bernoulli decision exact.

For P1, `binary_proof.cpp` currently passes unreduced integer lifts into the
rejection dot products, as required to avoid changing those values before the
decision. Preserve this ordering unless a separate proof review changes it.

## 8. Implemented API and use

The primitive is behind the existing provider interface using `NTL::ZZ` and
`RandomSource`. Its contract is intentionally negative-domain:

```text
sample_exp(numerator, denominator, random):
    require denominator > 0 and numerator < 0
    return an exact Bernoulli(exp(numerator/denominator))
```

The protocol layer forms the rational exponent and handles `r>=0` as
deterministic accept; the provider handles only `r<0`. The provider performs
no vector arithmetic and does not sample a Gaussian. Deterministic
`RandomSource` implementations are used by tests; production callers should
use `SystemRandomSource`. Failures propagate so the enclosing operation can
abort rather than substitute an accept/reject decision.

## 9. Tests and verification

The root `CMakeLists.txt` builds `tests/test_bernoulli_exponential.cpp` as
`bernoulli_exponential_test` and registers that executable with CTest. The test
covers:

- negative rational exponents, including `x=1/2` and integer exponents;
- very small positive `x=2^-256`;
- `x=1`, and values immediately below and above it (`255/256` and
  `257/256`);
- `x>1`, including the integer decomposition at `x=2`;
- a very large numerator (`10^80`) and a very large denominator (`2^256`);
- invalid nonnegative numerators and nonpositive denominators;
- propagation of an injected `RandomSource` failure; and
- deterministic low/high bit streams that force accept and reject comparison
  paths.

The 2,048-trial frequency check for `exp(-1)` is a broad statistical
diagnostic only. It is not a proof of correctness, exactness, or security.

Verified from the repository root on the current build:

```sh
cmake -S . -B build
cmake --build build --parallel 4
ctest --test-dir build -R '^bernoulli_exponential_test$' --output-on-failure
ctest --test-dir build --output-on-failure
```

Configuration and build passed. The dedicated test passed **1/1**. The full
CTest suite passed **9/9**, including the Bernoulli test and both configured
Dilithium reference tests. These results validate the current build and test
cases only; they are not a security certification.

## 10. Remaining review items

1. Review variable-time behavior, data-dependent bit consumption, and
   worst-case resource use against the deployment threat model. The algorithm
   has unbounded worst-case runtime and is not claimed to be constant-time.
2. Confirm the OS-backed random source and its operational failure behavior
   for each target platform. Exactness assumes independent unbiased bits;
   production relies on computational randomness.
3. Resolve the Protocol 2 Gaussian-width issue separately; the Bernoulli
   primitive cannot determine which Gaussian width is intended.
4. Verify the surrounding protocol's parameter and distribution hypotheses
   independently. An exact Bernoulli primitive does not establish that the
   full rejection sampler or ring signature is correct or secure.

**Conclusion:** the implemented provider computes the negative-rational
Bernoulli(`exp(r)`) event by exact rational interval refinement and
exponent decomposition, under the independent-unbiased-bit model. The
algorithm terminates almost surely but has unbounded worst-case runtime.
Neither it nor the passing tests establish production readiness or
cryptographic security.
