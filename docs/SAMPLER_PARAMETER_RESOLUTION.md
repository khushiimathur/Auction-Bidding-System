# Discrete-Gaussian Parameter Resolution

**Scope:** notation and call-site audit only. This document changes no source
code or cryptographic parameters and does not implement a sampler.

**Reference:** M. F. Esgin et al., “Short Lattice-based One-out-of-Many Proofs
and Applications to Ring Signatures,” ePrint 2018/773. See §2.3 and Algorithm
1 (printed pp. 7–8), Protocol 1 (§4, pp. 14–15), Protocol 2 (§5, pp. 16–17),
and the Protocol 2 simulation in Appendix E. [Official paper PDF](https://eprint.iacr.org/2018/773.pdf).

## 1. Esgin’s two Gaussian parameterizations

Section 2.3, p. 7 defines an ellipsoid Gaussian with parameter matrix `S`:

```text
rho_S(x) = exp(-pi * x^T (S^T S)^(-1) x)
D^n_S(x) = rho_S(x) / sum_{z in Z^n} rho_S(z).
```

For `S=s I`, the distribution is spherical `D_s^n`, and for one integer
coordinate its weight is `exp(-pi*x^2/s^2)`. Esgin separately defines
`D_sigma^n` as the discrete normal with standard deviation `sigma`, where

```text
s = sigma * sqrt(2*pi)
s^2 = 2*pi*sigma^2
exp(-pi*x^2/s^2) = exp(-x^2/(2*sigma^2)).
```

This is the exact conversion. `D_s`’s parameter is not the standard deviation.
Both distributions have support over all of `Z`; vector coordinates in the
spherical case are independent. The protocol algorithms use the paper’s
`D_sigma` notation: Algorithm 1 and Lemma 6 use `D_sigma`, and the protocol
widths are given with that notation. Lemma 4 on p. 7 also states tail and norm
bounds in terms of standard deviation `sigma`.

## 2. Trace from paper to code

### Protocol 1 (Esgin §4, Protocol 1, printed p. 15)

| Sample | Paper’s `D_sigma` width | Current source call | Result |
| --- | --- | --- | --- |
| `a_{j,i}` for each `j`, `i=1,...,beta-1` | `sigma_a=phi1*sqrt(k)`; `d` independent integer coefficients per polynomial | `binary_proof.cpp:408–418` passes `phi1^2*k` as `sigma_squared` | Matches the aligned `D_sigma` contract |
| `r_a` and `r_d` | `sigma_r=phi2*B*sqrt(2*m*d)`; each is an `md`-coordinate integer vector | `binary_proof.cpp:433–442` passes `phi2^2*B^2*2*m*d` as `sigma_squared` | Matches the aligned `D_sigma` contract |

`binary_proof.hpp:63–72` declares `DiscreteGaussianProvider` in the
`D_sigma` convention, with positive exact rational `sigma_squared` and mass
proportional to `exp(-x²/(2*sigma_squared))`. A provider implementation and
dedicated tests now exist. Their presence does not constitute independent
proof/code review or production validation; deterministic Gaussian test
providers also do not establish the distribution.

The conversion `s²=2*pi*sigma²` remains necessary only when expressing the
same target in the alternate `D_s` notation. The `D_sigma` contract avoids
introducing irrational `pi` into the rational API. Do not multiply the
existing Protocol 1 arguments by `2*pi`.

### Protocol 2 (Esgin §5, Protocol 2, printed pp. 16–17)

Protocol 2 reuses `P_bin[1–8]` from Protocol 1 (p. 17, line note), which
includes `r_a,r_d`. The Protocol 2 specification on printed p. 17 gives those
vectors the width

```text
D_sigma^(md), sigma_a = phi2 * B * sqrt(3*m*d).
```

This is the Protocol 2 width; it differs from the standalone Protocol 1 width
`phi2*B*sqrt(2md)`.

Protocol 2 separately samples `k` vectors

```text
rho_j <- D_sigma^(md), sigma_rho = phi2 * B * sqrt(3*m*d/k),
```

and sets `z=x^k*r-sum_{j=0}^{k-1}x^j*rho_j`. Since each `x^j` is a signed
monomial and therefore permutes/sign-flips coefficient coordinates, if the
`rho_j` are independent, the nominal variance parameter of the Gaussian sum
is

```text
k * sigma_rho^2 = phi2^2 * B^2 * 3*m*d.
```

This gives the common target scale `phi2*B*sqrt(3md)`, but does not make the
discrete-Gaussian convolution exactly a discrete Gaussian at that scale.
Appendix E (printed p. 30) explains why the sum of the rotated independent
samples is statistically close to the common-scale distribution used in the
Protocol 2 analysis. The approximation and its stated statistical error must
be preserved; do not replace it with an exact-convolution claim.

Protocol 2’s joint rejection call uses

```text
Rej((z,z_b,z_c), (x^k*r,x*r_b,x*r_c), phi2, B*sqrt(3*m*d)),
```

so Algorithm 1 sets the rejection target parameter to
`sigma=phi2*B*sqrt(3md)`. The `z_b,z_c` mask noises `r_a,r_d` are also sampled
at this common scale in Protocol 2. Thus the paper specifies the matching
scale for those blocks and separately justifies the `z` block by statistical
closeness in Appendix E; it does not assert an exact discrete-Gaussian
convolution.

**Resolution:** the Protocol 2 widths are `sqrt(3md)` for `r_a,r_d`,
`sqrt(3md/k)` for each `rho_j`, and `sqrt(3md)` for the joint rejection.
Appendix E, printed p. 30, explains the statistical closeness of the rotated
sum to the common-scale distribution. This resolves the prior reading that
Protocol 2 retained the standalone Protocol 1 `sqrt(2md)` width. It does not
authorize changing Protocol 1’s parameters or treating the sum as an exact
discrete Gaussian.

### Section 6 repeated ring-signature variant

Section 6, p. 19 explicitly describes rejection across concatenated
repetitions and gives widths `D_{phi1 sqrt(kr)}` for the `f_{j,i}` draws and
`D_{phi2 B sqrt(3mdr)}` for `z,z_b,z_c`. These are the widths for that repeated
construction; its repetition count depends on the security/soundness target.
No production parameters are selected here.

## 3. Rejection and Bernoulli-exponential requirements

Algorithm 1, §2.3, p. 8 takes a vector `z`, a center `c` with `||c||<K`,
`phi>0`, and sets `sigma=phi*K` and
`mu(phi)=exp(1/phi+1/(2phi²))`. It draws `u` uniformly in `[0,1)` and accepts
unless

```text
u > (1/mu(phi)) * exp((-2*<z,c> + ||c||^2) / (2*sigma^2)).
```

This is a Bernoulli decision with probability equal to the displayed
threshold. With the project’s rational `phi` and integer `K²`, the log of this
probability is rational:

```text
-1/phi - 1/(2*phi^2)
  + (-2*<z,c> + ||c||^2)/(2*phi^2*K^2).
```

`binary_proof.cpp:296–318` computes this exponent by exact integer
cross-multiplication and calls `BernoulliExponentialProvider::sample_exp`
(`binary_proof.hpp:74–82`) with a rational log numerator and denominator.
`ExactBernoulliExponentialProvider` implements the negative-rational interface
using rational interval refinement. Its dedicated test and the complete CTest
suite pass; this does not certify either sampler's production suitability or
the full protocol.

The paper’s Algorithm 1 defines an ideal real-uniform comparison and a real
exponential; it does not specify fixed-point precision, an approximation
budget for machine arithmetic, or a concrete finite-bit Bernoulli-exponential
algorithm. Lemma 6 gives a theoretical `2^-100` statistical bound for the
rejection result (p. 8). That bound is part of the paper’s mathematical
rejection-sampling analysis; it is **not** an instruction to use 100-bit
floating-point arithmetic and does not give a machine-precision or aggregate
sampler-error budget.

Accordingly:

- An exact provider must sample Bernoulli `exp(r)` for the rational negative
  input `r`, using unbiased OS-derived random bits, and must not replace it
  with floating-point `exp(r)` followed by a finite-width uniform comparison
  unless a separate error proof and budget explicitly approve that
  approximation.
- If approximation is considered, the allowed statistical-distance/error
  budget, numerical method, rounding direction, tail handling, and accumulated
  error over coefficients, abort/retry loops, repetitions and signatures must
  be specified and proven adequate. The paper does not supply those
  implementation choices.
- The rejection sampler’s scale is the standard-deviation quantity
  `sigma=phi*K` from Algorithm 1. It must be consistent with the sampler
  provider’s `D_sigma` convention.

## 4. Existing code status and reuse

- `RandomSource` and `SystemRandomSource` provide injectable bytes and the
  OS-backed entropy source (Apple `SecRandomCopyBytes`, Linux `getrandom`),
  with failure propagated. The Gaussian and Bernoulli-exponential providers
  consume this interface without fallback.
- NTL/GMP supplies integer arithmetic; project code implements the Gaussian
  and Bernoulli-exponential sampling algorithms.
- P1 and P2 retain signed integer lifts through their rejection calculations
  and convert responses to ring polynomials afterward.
- Dedicated sampler tests and deterministic protocol fixtures are registered.
  They test implementation behavior and protocol wiring, but do not alone
  establish distributional correctness or production suitability.

## 5. Confirmed versus unresolved

### Explicitly supported by the paper

1. The mathematical definitions and conversion `s=sigma*sqrt(2*pi)` (§2.3,
   p. 7).
2. Centered integer discrete Gaussian distributions, their standard-deviation
   notation, and the cited tail bounds (Lemma 4, p. 7).
3. Protocol 1’s `a`, `r_a`, and `r_d` widths and its two rejection calls
   (§4, Protocol 1, pp. 14–15).
4. Protocol 2’s `r_a,r_d` and `rho_j` widths and joint rejection width
   (§5, Protocol 2 and following note, p. 17).
5. Appendix E’s statistical-closeness analysis for the rotated `rho_j` sum
   (printed p. 30), and the Section 6 repeated widths (§6, p. 19).
6. Theoretical rejection acceptance/completeness and statistical-distance
   claims in Lemma 6. These do not define a machine precision target.

### Unresolved / not specified for this implementation

1. How the Protocol 2 implementation will preserve and account for Appendix
   E’s statistical-closeness bound, including its contribution to the total
   distribution-error budget.
2. Exact versus approximate machine sampling, finite precision, and the
   total error budget if approximate sampling is acceptable.
3. Independent review of the implemented Bernoulli-exponential algorithm's
   exactness assumptions, termination, randomness, and timing.
4. A production discrete-Gaussian algorithm and its mathematical and
   implementation validation; the `D_sigma` interface convention is now
   aligned.
5. The side-channel model and acceptable timing behavior for variable-time
   rejection sampling.

## 6. Decisions required before production sampling

1. **Implement under the aligned API:** use the positive exact rational
   `sigma_squared` for the `D_sigma` coefficient law. Preserve the existing
   Protocol 1 parameter values; do not pass them as `D_s` scale squares.
2. **Implement Protocol 2 only against the verified specification:** use
   `sqrt(3md)` for its `r_a,r_d` draws and joint rejection, and
   `sqrt(3md/k)` for each `rho_j`. Preserve Appendix E’s statistical-
   closeness analysis for the rotated sum; do not model it as an exact
   discrete-Gaussian convolution or change the parameters.
3. **Set the implementation accuracy contract:** exact output law, or a
   formally bounded statistical approximation with an explicit aggregate
   error budget. Do not infer a machine precision from the paper’s `2^-100`
   Lemma 6 bound.
4. **Review the Bernoulli-exponential implementation**, including exactness
   assumptions, unbiased entropy, termination, failure behavior and timing
   leakage.
5. **Set side-channel and operational policy:** variable-time behavior,
   resource limits and fail-closed abort semantics.
6. **Independently review the implemented Gaussian provider**, including
   parameter mapping, exactness assumptions, entropy use, statistical
   diagnostics, and the proof/code argument. Statistical tests alone do not
   prove correctness or security.

**Production sampling cannot safely begin until decisions 1–5 are settled.**
No parameter or interpretation has been selected to force the current text to
be consistent.

## 7. Final design disposition

The API-convention question above is resolved in the source interface:
the provider input is exact positive rational `sigma_squared`, meaning the
square of Esgin’s `D_sigma` standard deviation, with scalar mass proportional
to `exp(-x^2/(2*sigma_squared))`. This supersedes the earlier alternative of
retaining `D_s` as the public provider convention. The source declaration is
aligned and a Gaussian provider is implemented, but its independent
mathematical and implementation validation remains outstanding. Protocol 1's
existing numeric call arguments already represent the required
`sigma_squared` values; the Protocol 2 prover uses the documented
`sqrt(3md)` and `sqrt(3md/k)` widths.

The algorithm, no-truncation, exactness, random-source, API, and testing
specification is maintained in
[DISCRETE_GAUSSIAN_SAMPLER_SPEC.md](DISCRETE_GAUSSIAN_SAMPLER_SPEC.md).
The prior Protocol 2 width discrepancy is corrected against §5, printed p. 17:
the paper specifies `sqrt(3md)` for `r_a,r_d`, `sqrt(3md/k)` for each `rho_j`,
and `sqrt(3md)` for the joint rejection. Appendix E, printed p. 30, explains
statistical closeness of the rotated sum to the common-scale distribution;
this is not an exact-convolution claim. The implementation must preserve that
approximation and its error analysis. No source parameters are changed here.
