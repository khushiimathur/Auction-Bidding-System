# Production Discrete-Gaussian Sampler Specification

**Status:** an exact-rational discrete-Gaussian provider is implemented
using the algorithm in §5 and tested. Its stated distribution follows under
independent unbiased random bits and correct exact Bernoulli-exponential
decisions. Execution is variable-time with unbounded worst-case runtime; this
is not a production-readiness or cryptographic-security claim. The Protocol 2
width conflict remains a protocol-level blocker.

**Convention:** exclusively Esgin `D_sigma`, where `sigma` is the standard
deviation. The C++ provider takes exact rational `sigma_squared`.
Do not interpret this value using the alternate `D_s` convention.

**Reference:** M. F. Esgin et al., *Short Lattice-based One-out-of-Many
Proofs and Applications to Ring Signatures*, ePrint 2018/773: §2.3 (printed
pp. 7–8), Algorithm 1 (p. 8), Protocol 1 (§4, pp. 14–15), Protocol 2 (§5,
pp. 16–17), Section 6 (pp. 19–20), and Appendix E (full-version p. 31).
[Official paper PDF](https://eprint.iacr.org/2018/773.pdf).

## 1. Target law and parameter convention

Esgin defines `D_s` with weight `exp(-pi*x^2/s^2)` and relates it to the
discrete normal `D_sigma` by `s=sigma*sqrt(2*pi)` (§2.3, p. 7). Consequently,
for a scalar coefficient the only target in this specification is

```text
P_sigma(x) = exp(-x^2/(2*sigma^2)) / Z_sigma,  x in Z,
Z_sigma = sum_{t in Z} exp(-t^2/(2*sigma^2)).
```

The support is all integers. A vector or polynomial draw written
`D_sigma^n` consists of independent scalar draws with this mass. Samples are
integer lifts; do not reduce them modulo `q` before the protocol's integer
response and rejection calculations. `r_c`, witness randomness, and other
bounded samples are not Gaussian draws.

`D_s` is not an API alias. If internal proof code uses that representation,
the exact conversion is `s^2=2*pi*sigma^2`; because `pi` is not rational, it
must not be silently approximated into this rational API.

## 2. Existing code audit

### Interfaces and available implementations

- `cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp:63–72` declares
  `DiscreteGaussianProvider::sample_coefficient(sigma_squared_numerator,
  sigma_squared_denominator, RandomSource&)`. Its contract is now explicitly
  `D_sigma`, with positive exact rational `sigma_squared` and coefficient
  mass proportional to `exp(-x^2/(2*sigma_squared))`.
- `cpp_backend/include/lattice_lrs/proofs/discrete_gaussian.hpp` and
  `cpp_backend/src/proofs/discrete_gaussian.cpp` implement
  `ExactDiscreteGaussianProvider`, which composes the existing
  Bernoulli-exponential provider and `RandomSource`.
- `cpp_backend/src/proofs/binary_proof.cpp:277–288` invokes the provider once
  per scalar coefficient and preserves the returned `NTL::ZZ` values as
  integer lifts.
- `cpp_backend/src/sampling/random_source.cpp` provides OS-backed entropy
  (`SecRandomCopyBytes` on Apple and `getrandom` on Linux) and propagates
  failure. `RandomSource` is injectable. Existing uniform/bounded samplers do
  not implement a discrete Gaussian.
- `tests/test_binary_proof.cpp:49–95` has deterministic fake Gaussian
  providers for protocol wiring. They return scripted values and do not test
  or establish any Gaussian distribution.
- `ExactBernoulliExponentialProvider` implements the rational
  Bernoulli(`exp(r)`) dependency used by the Gaussian provider; no second
  randomness implementation was added. There is no Protocol 2 C++ prover/
  provider call site. Protocol 2 distributions below are paper requirements,
  not implemented code paths.

### Protocol 1 source call sites

At `binary_proof.cpp:408–418`, the code samples the nonzero digit masks
`a_{j,i}`, with `j=0,...,k-1` and `i=1,...,beta-1`. Each such polynomial has
`d` independently requested coefficients. The provider is passed
`sigma^2=phi1^2*k`; the total number of provider calls is
`k*(beta-1)*d`. For each row, `a_{j,0}` is constructed coefficientwise as
`-sum_{i=1}^{beta-1} a_{j,i}`. It is derived and correlated, not another
independent `D_sigma` draw.

At `binary_proof.cpp:433–442`, `r_a` and `r_d` each have `m` polynomials, or
`m*d` scalar coefficients, and each scalar call receives
`sigma^2=phi2^2*B^2*2*m*d`. The code therefore makes `2*m*d` calls for those
two vectors. `r_c` is sampled separately from the bounded set `[-B,B]` and is
not Gaussian.

At `binary_proof.cpp:526–544`, Protocol 1 applies rejection, not another
Gaussian draw:

1. `Rej(f_1, x*b_1, phi1, sqrt(k))`; the Gaussian width underlying the
   corresponding response is `phi1*sqrt(k)` and the rejection vector has
   `k*(beta-1)*d` scalar coordinates.
2. `Rej((z_b,z_c), x*(r,r_c), phi2, B*sqrt(2*m*d))`; its concatenated vector
   has `2*m*d` coordinates and the corresponding base mask width is
   `phi2*B*sqrt(2*m*d)`.

These rejection calls use the separate Bernoulli-exponential primitive and do
not change the Gaussian provider's input. The code currently passes the
correct rational squares for the aligned `D_sigma` API. The new provider
implements that contract; no Protocol 1 parameter expressions were changed
for this implementation.

## 3. Distribution inventory for Protocols 1 and 2

Here a “coordinate” is one integer coefficient. `phi1`, `phi2`, `B`, `k`,
`m`, `d`, and `beta` retain the values/constraints of the cited protocol;
this document selects no cryptographic parameter.

| Protocol object | Esgin location | Per-coordinate standard deviation `sigma` | Dimensions / independence | Status |
| --- | --- | --- | --- | --- |
| `a_{j,i}`, `i>0` | Protocol 1, p. 15 | `phi1*sqrt(k)` | `d` per polynomial; `k*(beta-1)` independently sampled polynomials | Implemented call site and provider |
| `a_{j,0}` | Protocol 1, p. 15 | No independent width | Coefficientwise negative sum of the `beta-1` draws in that row | Derived, correlated |
| `r_a`, `r_d` | Protocol 1, p. 15 | `phi2*B*sqrt(2md)` | `md` each; separate coefficient draws | Implemented call site and provider |
| `r_c` | Protocol 1, p. 15 | Not Gaussian | `md` bounded coefficients in `[-B,B]` | Existing bounded sampler |
| Embedded `a_{j,i}`, `r_a`, `r_d` | Protocol 2, p. 17 | Same as P1: `phi1*sqrt(k)` and `phi2*B*sqrt(2md)` | Same dimensions as P1 | Explicit P2 reuse/note; not implemented |
| `rho_j`, `j=0,...,k-1` | Protocol 2, p. 17 | `phi2*B*sqrt(3md/k)` | `md` per vector; `k` vectors, total `kmd` coefficient draws | Explicit paper distribution; not implemented |
| P2 `z=x^k*r-sum_j x^j*rho_j` | Protocol 2, p. 17 | The `rho` terms have summed variance parameter `phi2^2*B^2*3md` | `md` output coefficients; signed monomial actions permute/sign-flip coefficients | Derived convolution, not a direct scalar Gaussian draw |
| P2 joint rejection `(z,z_b,z_c)` | Protocol 2, p. 17 | Rejection width `phi2*B*sqrt(3md)` | `3md` concatenated coordinates; `K=B*sqrt(3md)` | Rejection parameter explicit; input law conflicts with stated embedded widths |
| Repeated construction `f_{j,i}` | Section 6, p. 19 | `phi1*sqrt(kr)` | Per nonzero digit polynomial, `d` coordinates across the repeated construction | Paper-level requirement; no repeated implementation |
| Repeated response blocks | Section 6, p. 19 | `phi2*B*sqrt(3mdr)` | Each block `md`; rejection concatenates repetitions | Paper-level requirement; no repeated implementation |

### Protocol 2 width discrepancy — unresolved

The text explicitly gives all of the following (Protocol 2, p. 17):

1. The embedded `P_bin[1–8]` retains `r_a,r_d` width
   `phi2*B*sqrt(2md)` (the note below the protocol).
2. Each `rho_j` has width `phi2*B*sqrt(3md/k)`.
3. The `rho_j` terms are combined into `z`, and the joint rejection is
   `Rej((z,z_b,z_c),(...),phi2,B*sqrt(3md))`, over `3md` coordinates.
4. Appendix E's simulator describes the three response blocks using the
   common width `phi2*B*sqrt(3md)` (full-version p. 31).

Since `x^j` is a signed coefficient permutation, the sum of the `k`
independent `rho_j` variance parameters is
`k*(phi2^2*B^2*3md/k)=phi2^2*B^2*3md`. This variance-parameter calculation
does **not** make a convolution of discrete Gaussians exactly one discrete
Gaussian. More critically, the embedded `z_b,z_c` masks are explicitly
sampled at the `sqrt(2md)` width, while the joint `Rej` is parameterized at
`sqrt(3md)`. Lemma 6 (§2.3, p. 8) is stated for its specified common Gaussian
input and does not, by that statement alone, justify this heterogeneous
input. The simulator statement does not resolve the discrepancy.

The paper does not unambiguously tell an implementer to change either width.
Do not change `r_a,r_d`, `rho_j`, the joint rejection bound, or simulator
equations. Protocol 2 production sampling and its claimed output distribution
remain blocked pending author clarification or an independent proof.

## 4. Canonical C++ API recommendation

Retain the current scalar-provider shape for minimal compatibility, but name
and document the rational arguments as the exact square of Esgin's standard
deviation:

```cpp
NTL::ZZ sample_coefficient(
    const NTL::ZZ& sigma_squared_numerator,
    const NTL::ZZ& sigma_squared_denominator,
    sampling::RandomSource& random);
```

Contract: denominator and numerator are positive, the represented rational is
exact, and the result is one integer with mass
`exp(-x^2/(2*sigma_squared))/Z`. Reject malformed/nonpositive inputs. Return
the unreduced integer lift. A named rational value type may replace the pair
later, but it must preserve these semantics. Do not expose `D_s` as an
alternative API mode.

Provider use for arrays remains independent scalar calls. The caller owns
dimension checks and checked multiplication for coordinate counts. P1 already
computes exact rational squares. P2 call sites, when mathematically cleared,
should do likewise:

```text
P1 a:       phi1^2*k
P1 ra, rd:  phi2^2*B^2*2*m*d
P2 rho_j:   phi2^2*B^2*3*m*d/k
P2 joint rejection target (not a sampler call): phi2^2*B^2*3*m*d
```

The P2 entries document the printed equations only; they are not approval to
wire the inconsistent distribution.

## 5. Implemented exact integer algorithm

The provider uses rejection sampling from a two-sided discrete-Laplace
proposal generated as the difference of two independent geometric
variables. For positive rational `v=sigma^2=a/b`, it selects the exact
integer `k=max(1,ceil(sqrt(v)))` and proposal rate `tau=1/k`. The square root
and ceiling are computed with integer arithmetic; no floating-point
approximation is used. This rate is an internal efficiency rule, not an Esgin
parameter or a change to the target law.

1. Obtain `G_1,G_2` independently with
   `Pr[G_i=n]=(1-lambda)*lambda^n`, `n>=0`, where `lambda=exp(-tau)`. Generate
   each geometric variable by repeated exact Bernoulli(`lambda`) trials,
   counting successes until the first failure. Set `Y=G_1-G_2`.
2. The proposal mass is
   `q(y)=((1-lambda)/(1+lambda))*exp(-tau*abs(y))`.
3. Accept `Y=y` with probability

   ```text
   exp(R(y)),
   R(y) = -y^2/(2v) + tau*abs(y) - v*tau^2/2.
   ```

4. If rejected, restart at step 1. If accepted, return `y` as an integer.

For `v=a/b` and `tau=1/k`, the implementation passes the exact rational
acceptance log
`R(y)=-(b*k*abs(y)-a)^2/(2*a*b*k^2)` to the Bernoulli-exponential provider,
reducing the rational by its integer gcd. This equals
`-y^2/(2v)+tau*abs(y)-v*tau^2/2`. Completing the square gives
`R(y)=-(abs(y)-v*tau)^2/(2v)<=0`, so it is a valid acceptance probability.
Multiplying proposal mass by acceptance probability gives a constant times
`exp(-y^2/(2v))`; conditioning on acceptance therefore yields exactly
`D_sigma`. The rate affects efficiency only, not the target distribution.

Under independent unbiased random bits, each geometric draw terminates
almost surely because `exp(-tau)<1`. Each outer rejection attempt has
positive acceptance probability, so repeated independent attempts terminate
almost surely. Neither loop has a finite worst-case iteration bound; runtime
is unbounded and depends on sampled values and Bernoulli refinement. The
implemented path is variable-time and makes no constant-time claim.

Both proposal generation (`exp(-tau)`) and acceptance (`exp(R(y))`) require an
exact Bernoulli-exponential primitive. The project uses
`ExactBernoulliExponentialProvider`, which uses rational interval refinement
and the existing `RandomSource`. The exact-law claim is conditional on the
correctness of both implementations and the ideal independent-unbiased-bit
model. In deployment, computational randomness relies on the OS entropy
source or a reviewed CSPRNG; this is not literal information-theoretic
independence. Testing is not an independent proof or cryptographic security
review.

## 6. Tail, precision, error, and randomness contract

- **Tail:** no truncation, clipping, finite table, or coefficient cutoff in
  production. The target support is all of `Z`. A resource guard may fail the
  signing attempt without returning a coefficient; it must not return a
  conditionally truncated/biased sample. Any retry cap's effect on protocol
  abort behavior requires separate analysis.
- **Numerics:** use exact integer/rational arithmetic for `v`, `tau`, and
  `R(y)`. The ideal decision `Bernoulli(exp(r))` for rational `r<=0` must be
  exact. A practical route is certified arbitrary-precision lower/upper
  bounds for `exp(r)` plus fresh unbiased random bits, refined until the
  random threshold is separated from the interval. No fixed precision
  suffices as a general exactness claim; equality has probability zero under
  an ideal continuous uniform-bit stream, and the refinement must terminate
  almost surely. The particular Bernoulli-exponential algorithm still needs
  proof and implementation review.
- **Error budget:** sampler-induced statistical distance from the ideal
  distribution is zero under the mathematical contract. No nonzero
  approximation budget is approved or supplied by Esgin. The paper's
  `2^-100` rejection lemma is not a machine precision or sampler-error
  allowance. Floating-point rounding, finite truncation, or bounded-bit
  thresholding needs a separately quantified composition/security analysis
  and written approval; until then approximate sampling is not acceptable.
- **Randomness:** use the existing fail-closed OS-backed `RandomSource`, or a
  reviewed CSPRNG seeded from OS entropy, for unbiased random bits. Propagate
  entropy and arithmetic errors; never fall back to `std::rand`, ordinary
  distributions, clock seeds, or modulo-biased reductions. Independent
  coordinates and invocations require fresh independent random draws under
  the underlying ideal model.

The CSPRNG provides computationally secure pseudorandomness, not a literal
information-theoretic stream of independent fair bits. The implementation
claim must state this standard computational assumption separately from the
exact sampling-law proof.

## 7. Timing, failure, and sensitive data

The geometric loops, exponential coins, rejection retries, and full protocol
abort/restart behavior are variable-time. Runtime and branches may depend on
sampled masks; protocol-level aborts are observable. Esgin does not specify a
constant-time sampler or deployment side-channel model. Before production:

- identify the attacker and observable timing/cache/resource channels;
- establish whether sample-dependent runtime is acceptable or provide a
  reviewed mitigation; do not assert constant-time behavior for this
  variable-iteration implementation;
- ensure failures abort signing and never return a fallback value or emit a
  partial transcript;
- do not log Gaussian values, seeds, openings, or intermediate rejection
  values; clear temporary sensitive buffers where the NTL allocation model
  permits and document residual copies;
- analyze resource limits and retries as protocol-visible abort behavior.

## 8. Tests and remaining validation

### Separate deterministic test interface

Production accepts only the production `RandomSource` path and exact
Bernoulli-exponential implementation. Deterministic fixtures belong only in
the test target: a scripted `RandomSource` for bit-consumption/error paths and
a test-only scripted Bernoulli-exponential coin/provider for deterministic
branch coverage. Do not compile or expose deterministic providers in the
production library. Preserve the current `ZeroGaussian`/scripted providers as
protocol-wiring fixtures only; they are not sampler tests.

`tests/test_discrete_gaussian.cpp` covers nonpositive numerator/denominator
validation before randomness is consumed; deterministic geometric success and
failure, both output signs, zero acceptance-log handling, rejection and retry;
fractional and very large exact parameters; and propagation of a
`RandomSource` failure without a fallback value.

The test also runs a statistical diagnostic of 2,048 draws at
`sigma_squared=1`, checking broad bands for empirical mean, second moment,
and the `abs(x)>=2` tail frequency against a finite floating-point reference
sum over `[-12,12]`. This is a smoke diagnostic only: it is not a formal
goodness-of-fit test, proof of exactness, proof of independence, or a
cryptographic security result. The dedicated test and full CTest suite passed
after implementation.

Not covered by the current focused test: an independent mathematical proof
review; explicit Bernoulli-provider exception injection; formal confidence
intervals; multiple tail thresholds; cross-coordinate/serial independence;
resource-exhaustion behavior; and a protocol-level test of provider
integration and parameter mapping. Those remain review/validation work, not
claims established by the current test.

## 9. Readiness decision

**Protocol 1:** the mathematical target widths and rational squares are
specified, and existing calls already pass those rational squares under the
aligned `D_sigma` interface contract. A production `D_sigma` provider is now
implemented with the exact geometric-proposal/rejection method above.
Independent mathematical and security review, broader validation, and
deployment-side-channel analysis remain outstanding.

**Protocol 2:** not ready for sampler wiring. The literal `sqrt(2md)` embedded
mask widths conflict with the `sqrt(3md)` joint rejection/simulator
distribution as described in §3. Do not infer or implement a correction.

**Production:** this implementation is not a production-readiness or
cryptographic-security determination. Review the Bernoulli-exponential
primitive, exact derivation and rate policy, variable-time leakage,
failure/resource semantics, and deployment threat model. Protocol 2 remains
blocked by the issue above. No numerical precision or approximate-error
budget has been introduced; passing tests is evidence of functionality, not
a security claim.

## 10. Local related decisions

- [SAMPLING_DESIGN_DECISIONS.md](SAMPLING_DESIGN_DECISIONS.md) records the
  canonical API, exactness policy, and final design disposition.
- [SAMPLER_PARAMETER_RESOLUTION.md](SAMPLER_PARAMETER_RESOLUTION.md) records
  the prior notation/call-site audit and the unresolved P2 mismatch.
- [BERNOULLI_EXPONENTIAL_SPEC.md](BERNOULLI_EXPONENTIAL_SPEC.md) specifies the
  separate exact exponential coin required here and by rejection sampling.
- [PROTOCOL1_AUDIT_AND_PROTOCOL2_PLAN.md](PROTOCOL1_AUDIT_AND_PROTOCOL2_PLAN.md)
  records protocol code status and the P2 implementation plan.
