# Phase 3 design: Esgin et al. lattice ring signature

## Scope and status

This is a research and implementation blueprint for the **non-linkable** ring
signature in Section 6 of Esgin, Steinfeld, Sakzad, Liu, and Liu. It does not
include Wang–Chen–Ma linkability, auction logic, or executable cryptographic
code. The paper is a full version of the ACNS 2019 work and is available at
[IACR ePrint 2018/773](https://eprint.iacr.org/2018/773.pdf).

Equations and page references below refer to the paper's printed page numbers.
The CMake and source observations are from the current local workspace. Where
the paper gives several parameter instances or omits an implementation detail,
that is called out explicitly rather than filled in with an assumed choice.

## 1. Existing project audit

### Project files and build

- The root [`CMakeLists.txt`](../CMakeLists.txt) requires CMake 3.16, enables
  C++, selects C++17, includes CTest, and adds `cpp_backend/`. It defines
  `cpp_build_smoke` and `ntl_gmp_integration`. It also has the opt-in
  `LATTICE_LRS_BUILD_DILITHIUM_TESTS` block, which builds and registers the
  two upstream API tests separately.
- [`cpp_backend/CMakeLists.txt`](../cpp_backend/CMakeLists.txt) locates Homebrew
  NTL/GMP headers and libraries and exports imported targets `NTL::NTL` and
  `GMP::GMP`. NTL links GMP transitively. `lattice_lrs_backend` is currently an
  interface target exposing the backend include directory and NTL link.
- `cpp_backend/include/` and `cpp_backend/src/` currently contain no backend
  implementation files. There is no existing polynomial, matrix, sampler,
  commitment, proof, hash, or ring-signature module to reuse.
- `tests/test_cpp_build.cpp` is a minimal C++ build smoke test.
  `tests/test_ntl_gmp_integration.cpp` exercises `NTL::ZZ` and `NTL::ZZX`.
  `tests/dilithium_round2_test.c` and `tests/dilithium_round3_test.c` validate
  the respective Dilithium C APIs; these are not tests of this ring signature.
  `tests/test_python_environment.py` is a Python runtime smoke test and is not
  registered in the root CTest configuration.
- The NTL/GMP test confirms basic arbitrary-precision integer and integer
  polynomial operations. It does not establish that the paper's modular
  polynomial-ring representation, sampling distributions, or protocol
  equations are implemented.

### Dilithium repositories

Both `dilithium/upstream-round2/` and `dilithium/upstream-round3/` are retained
as separate upstream Git checkouts, each with `ref/` and `avx2/` source trees.
Their portable `ref/` APIs are exercised by distinct CTest targets when the
opt-in CMake option is enabled. They are standalone lattice signatures, not
ring signatures, and none of their implementation is a building block in
Esgin et al.'s construction. Keep their source and their tests separate from
the new PQ-LRS modules.

### Reuse versus new work

Reuse the existing CMake/CTest setup, the NTL/GMP imported targets, and the
test harness conventions. NTL `ZZ` can support exact coefficient/modulus
arithmetic; NTL containers and polynomial types may be useful after their
semantics are matched to the chosen modulus. GMP is already supplied through
NTL's link interface. Do not reuse Dilithium parameters or algorithms.

Everything cryptographic in the paper construction remains to be designed and
implemented: canonical ring elements, modular operations, commitment-key
generation, random sampling, commitment/opening checks, binary and
one-out-of-many protocols, rejection sampling, Fiat–Shamir challenge mapping,
signature encoding, and the four ring-signature algorithms.

## 2. Mathematical setting and dependencies

### Polynomial ring and representation

The paper uses

\[
 R=\mathbb Z[X]/(X^d+1),\qquad R_q=\mathbb Z_q[X]/(X^d+1),
 \quad \mathbb Z_q=\mathbb Z/q\mathbb Z.
\]

Here `d` is the polynomial degree/ring dimension, while `N` is the number of
ring members; do not confuse them. A ring element has `d` coefficients. The
paper represents residues in the centered interval
\([-(q-1)/2,(q-1)/2]\) for odd `q`. It defines Euclidean coefficient norms,
and polynomial infinity norm as the maximum absolute coefficient (Section 2.1,
pp. 5–6). Products are negacyclic because of `X^d = -1`.

The commitment is module-valued: vectors and matrices have entries in `R_q`.
An implementation must preserve the exact reduction and norm conventions;
wrapping arithmetic or silently using field-only operations would change the
construction.

### Module-LWE commitment key and commitment

For positive `n,m,v`, sample
\(G'_r\leftarrow R_q^{n\times(m-n)}\) and
\(G_m\leftarrow R_q^{n\times v}\), set
\(G_r=[I_n\mid G'_r]\), and publish
\(ck=G=[G_r\mid G_m]\in R_q^{n\times(m+v)}\). For a message
\(u\in R_q^v\), choose opening randomness \(r\leftarrow S_B^m\) and compute

\[
 \operatorname{Com}_{ck}(u;r)=G(r,u)=G_r r+G_m u.
\]

Opening verification with relaxation factor \(y\in R_q\) checks both
\(\operatorname{Com}_{ck}(u';r')=yC\) and
\(\|(r',u')\|\le T_{com}\). The paper's commitment is homomorphic:
\(\operatorname{Com}(a;r_1)+\operatorname{Com}(b;r_2)=
\operatorname{Com}(a+b;r_1+r_2)\) and
\(y\operatorname{Com}(a;r)=\operatorname{Com}(ya;yr)\). Hiding is based on
M-LWE; strong bounded binding is based on M-SIS (Section 2.2, pp. 6–7,
Lemma 1). This commitment is the foundation for keys and both proof protocols.

**Parameter detail:** Section 2 gives the generic message dimension `v`.
Appendix D, Table 4 specifies the commitment key dimensions as
`n x (m + k*beta)`, so the construction uses `v = k*beta`. Protocols 1 and 2
agree: their packed one-hot vectors have `k*beta` entries. User public keys
themselves commit to the zero vector.

### Algebraic protocol tools

Section 3 (pp. 9–13) addresses the two lattice-specific issues the design must
preserve:

1. **Witness growth under extraction.** Repeated challenges produce a
   Vandermonde system. The extracted opening uses the last row of its inverse,
   so challenge differences must be invertible and the inverse coefficients
   must have controlled norms. The paper's monomial challenge set gives
   invertibility for odd `q` and bounds on doubled inverses. Method 2 computes a
   global bound \(B_{d,k}\) by enumerating the relevant challenge subsets;
   Section 6.1 says its parameter instances use this method.
2. **Coefficient-space multiplication.** `Rot(f)` represents multiplication
   by a polynomial as a negacyclic coefficient matrix. This is useful for
   expressing M-SIS/M-LWE and norm constraints in coefficient space.
3. **Zero divisors and binary proofs.** In `R_q`, `b(b-1)=0` alone does not
   imply a binary polynomial. Lemma 7 supplies a norm-and-modulus condition
   under which such a relation forces `b` to be 0 or the stated scalar.

These are protocol and proof-analysis tools, not optional optimizations.
Method 1/2/3 bounds must not be mixed without updating the parameter analysis.

### Rejection sampling and Fiat–Shamir

The interactive protocols use a three-move form: the prover sends commitments,
gets challenge \(x\), and returns responses. Section 2.4 defines special
soundness and special honest-verifier zero knowledge. Rejection sampling hides
the witness-dependent shift in responses while preserving the target Gaussian
distribution, up to the paper's stated statistical error.

Algorithm 1 (p. 8) defines `Rej(z,c,phi,K)`: set
\(\sigma=\phi K\) and
\(\mu(\phi)=\exp(1/\phi+1/(2\phi^2))\); draw uniform `u` and accept with
probability
\[
 \mu(\phi)^{-1}\exp\left(\frac{-2\langle z,c\rangle+\|c\|^2}
                                      {2\sigma^2}\right).
\]
The exact sign convention depends on the paper's `z` argument as the shifted
response; retain its Algorithm 1 convention verbatim. It is used twice in the
binary proof and on concatenated response vectors in the one-out-of-many proof.

For the non-interactive ring signature, Section 6 replaces the challenge
generation with a random-oracle hash of the public parameters, message, ring,
and all first messages. It returns `r` monomial challenges. The paper writes
this as \(H(ck,M,L,(CMT_1,\ldots,CMT_r))\); it does not fully specify a byte
encoding or a concrete hash-to-challenge implementation. Those must be fixed
before interoperable code is written.

## 3. Protocol components

### Binary proof (Section 4, Protocol 1, pp. 13–15)

**Purpose/input/output.** Prove knowledge of a bounded opening of a commitment
to a binary vector, with the vectors used here additionally one-hot in each
digit block. Input includes `ck`, commitment `B`, and witness
\((b_{j,i},r)\), with each `b` binary and each block summing to one. Output
first-message commitments and a response; rejection may return abort.

**Prover equations.** For each block choose `a[j,i]` for `i>0`, set
\(a_{j,0}=-\sum_{i=1}^{\beta-1}a_{j,i}\). Choose commitment randomness
\(r_c\leftarrow\{-B_0,\ldots,B_0\}^{md}\) and Gaussian `r_a,r_d`. Form
\[
 A=\operatorname{Com}(a;r_a),\quad
 C=\operatorname{Com}(a\circ(1-2b);r_c),\quad
 D=\operatorname{Com}(-a^2;r_d),
\]
and obtain auxiliary challenge values \((c_a,d_a)=aCom(A,C,D)\). On
monomial challenge `x`, respond with \(f_{j,i}=xb_{j,i}+a_{j,i}\) for
`i != 0`, reconstruct \(f_{j,0}=x-\sum_{i>0}f_{j,i}\), and compute
\(z_b=xr+r_a\), \(z_c=xr_c+r_d\). Apply the specified rejection samplers.

**Verifier equations.** Check the auxiliary commitment; response norm bounds;
and
\[
 xB+A=\operatorname{Com}(f;z_b),\qquad
 xC+D=\operatorname{Com}(g;z_c),\quad
 g_{j,i}=f_{j,i}(x-f_{j,i}).
\]
The one-hot and ring-norm conditions are part of the relation and bounds.
Three-special soundness uses three distinct challenges. The paper gives the
full ordering, distributions, norm checks, and relations in Protocol 1; all
must be ported exactly. This component depends on commitments, samplers,
polynomial arithmetic, and `aCom`.

### One-out-of-many proof (Section 5, Protocol 2, pp. 15–18)

**Purpose/input/output.** Prove knowledge of an opening `r` to zero for one
member `c_ell` among the ring `L=(c_0,...,c_{N-1})`, without revealing `ell`.
The relation is \(c_\ell=\operatorname{Com}(0;r)\) with a bounded opening.
The protocol assumes \(N=\beta^k\), padding by repeating commitments if
necessary.

**Index encoding and polynomial identity.** Write `ell` in base `beta` with
digits \(\ell_j\), and let \(\delta_{\ell_j,i}\) be one-hot digit indicators.
For each ring position `i=(i_0,...,i_{k-1})`, the prover's responses satisfy
\[
 p_i(x)=\prod_{j=0}^{k-1}(x\delta_{\ell_j,i_j}+a_{j,i_j})
       =\delta_{\ell,i}x^k+\sum_{j=0}^{k-1}p_{i,j}x^j.
\]
The coefficient of degree `k` occurs only for the signer's ring member.
Choose `rho_j` and publish
\[
 E_j=\sum_{i=0}^{N-1}p_{i,j}c_i+\operatorname{Com}(0;\rho_j).
\]
The first message also contains the binary-proof commitments for the digit
indicators. After monomial challenge `x`, return binary-proof responses and
\[
 z=x^k r-\sum_{j=0}^{k-1}x^j\rho_j.
\]
Rejection sampling is applied to the combined vectors, as specified in the
Protocol 2 version used by Section 6.

**Verifier equations.** Verify the binary subproof and its auxiliary
commitment, all stated norm limits, and for every base-`beta` index tuple `i`
check
\[
 \sum_{i=0}^{N-1}c_i\prod_{j=0}^{k-1}f_{j,i_j}
 -\sum_{j=0}^{k-1}E_jx^j
 =\operatorname{Com}(0;z).
\]
The proof is `(k'+1)`-special sound with \(k'=\max\{2,k\}\), and its
single-run soundness error is \(k'/(2d)\). The extracted relation has the
paper's relaxation factor/soundness gap; it is not simply an opening of the
original commitment. This component depends on the binary proof, commitment
homomorphism, `Rot`/polynomial operations, challenge inversion bounds, and
rejection sampling.

### Ring signature algorithms (Section 6, pp. 18–20)

Let the selected parameter row determine `n,m,d,q,k,beta,r`, and let
\(\mathcal C=\{X^\omega:0\leq\omega<2d\}\subset R_q\).

1. **`RSetup(1^lambda)`**: generate commitment key `ck` with `CKeygen`; choose
   random-oracle hash `H : {0,1}* -> C^r`; publish `pp=(ck,H)`.
2. **`RKeygen(pp)`**: sample \(r\leftarrow S_B^m\), set
   \(c=\operatorname{Com}_{ck}(0;r)\), output public key `pk=c` and secret
   key `sk=r`.
3. **`RSign(pp,sk,M,L)`**: locate `ell` with `c_ell=Com(0;sk)`. Repeatedly
   generate `r` first-message packages `CMT_i` by running Protocol 2 steps
   1–7 in parallel, with the Section 6 repeated-protocol changes. Compute
   \(x=(x_1,...,x_r)=H(ck,M,L,(CMT_1,...,CMT_r))\). For each `i`, finish
   Protocol 2 steps 9–11 with challenge `x_i`. If any aborts, restart; when
   all succeed return \(\sigma=(\{CMT_i\},x,\{RSP_i\})\). The paper notes
   that `A`, `D`, and `E_0` can be omitted because they are determined by the
   remaining transmitted data and verification conditions.
4. **`RVerify(pp,M,L,sigma)`**: parse the signature; recompute the hash and
   reject unless it equals `x`; run Protocol 2 verification for each
   `(CMT_i,x_i,RSP_i)` (except its interactive challenge step); accept only if
   every run accepts.

The hash binds the message, the ordered ring, and all first messages. Signature
correctness follows from protocol completeness; anonymity is argued from its
zero-knowledge property; unforgeability is proved for insider corruption in
the random-oracle model under the stated assumptions. Functional tests do not
establish those security claims.

## 4. Parameter configuration from Section 6.1 and Appendix D

There is **no single universal parameter tuple** in the paper. Tables 3 and 4
give alternative instances by ring size. In all listed instances the target is
approximately 128-bit classical security, with root Hermite factor
\(\delta\leq1.0045\); rounded repetition counts make the listed achieved
`lambda` slightly exceed 128 in some rows. `log q` is the table's reported
logarithm, not an exact integer `q` value.

| Ring size `N` | `(n,m)` | `(d, log2 q)` | `(k,beta)` | `r` | reported `lambda` | signature KB |
|---:|---:|---:|---:|---:|---:|---:|
| 64 | (5,13) | (256,50) | (2,8) | 16 | 128.00 | 774 |
| 256 | (5,13) | (256,53) | (2,16) | 16 | 128.00 | 881 |
| 1,024 | (11,25) | (128,46) | (2,32) | 19 | 133.00 | 1,021 |
| 4,096 | (21,50) | (64,47) | (2,64) | 22 | 132.00 | 1,178 |
| approximately `2^16` | (20,51) | (64,50) | (3,41) | 24 | 129.96 | 1,487 |
| approximately `2^20` | (40,101) | (32,49) | (3,102) | 29 | 128.04 | 1,862 |
| `2^30` | (41,106) | (32,52) | (5,64) | 35 | 128.73 | 3,006 |

These values are transcribed from Section 6.1, Table 3 (printed pp. 20–21).
Appendix D, Table 4 (printed p. 24) supplies the calculation relationships.
The paper labels the ring size as `N=beta^k` (the table's approximate values
reflect rounded/target sizes in the construction); implementation must choose
and validate an exact `N` consistent with `beta^k` or pad the ring as the paper
permits.

| Symbol | Role and paper constraint |
|---|---|
| `lambda` | Security target; Section 2 sets 128 for instantiation. Table rows report achieved values after integer repetition rounding. |
| `d` | Degree in `R=Z[X]/(X^d+1)`; table choices range 32–256. Must satisfy `d >= 7` and be compatible with the paper's power-of-two ring analysis. |
| `q` | Odd modulus; table reports `log2(q)`. Section 6 requires `q > (10 phi1 d sqrt(d k r (beta-1)) + 2)^2` (Assumption 1, after the repeated-protocol tweak). Binding additionally requires the M-SIS bound in Eq. (11). |
| `n,m` | Commitment/module dimensions: `G` has `n` rows and `m+v` columns; `m` is selected using the M-LWE estimator. Require `m*d >= 86`. |
| `v` | Commitment message dimension. Not a table column; Protocol 1/2's committed indexed binary vector implies `v=k*beta` for that vector representation. Verify before coding. |
| `N` | Number of ring commitments / users. Construction uses `N=beta^k`; if padding is needed, repeat commitments as described in Section 5. |
| `k,beta` | Base-`beta` digit count and radix for `ell`; `k=log_beta(N)` where exact. These control proof size and extraction growth. |
| `C` | Challenge set \(\{X^\omega:0\leq\omega<2d\}\); cardinality `2d`. Distinct challenges have controlled doubled inverse-difference norms. |
| `k'` | `max(2,k)` in the proof soundness bound, since binary subproof needs three transcripts even at `k=1`. One-run error is `k'/(2d)`. |
| `r` | Repetition count, chosen as `ceil(lambda / log2(2d/k'))` to make the repeated soundness error at most `2^-lambda`; compare with Appendix D's formula and Table 3 rounding. |
| `B` | Coefficient bound for secrets/opening randomness, set to `1`; coefficients are uniform in `{-1,0,1}` (`S_B`). |
| `phi1,phi2` | Rejection-sampling parameters, both set to `2^2=4`; this yields expected signer retries at most 3 according to Section 6.1. |
| `T1,T'` | Required commitment binding bounds from Theorem 3 and the repeated protocol; depend on `d,k,beta,r,B,phi1,phi2` and the extraction bound `B_{d,k}`. Must use the paper's formulas, not choose independently. |
| `delta` | Root Hermite factor used in both M-SIS and M-LWE estimates; paper targets at most `1.0045`. |

**Distributions and norm bounds that the implementation must preserve:**

- `CKeygen`: independent uniform ring matrices `G'_r` and `G_m` as above.
- Key/opening randomness: `r <- S_B^m`, where each of `m*d` coefficients is
  uniform in `[-B,B]`; the concrete ring-signature setting uses `B=1`.
- Binary proof: the `a` vectors and `r_a,r_d` use the paper's discrete
  Gaussians; `r_c` is uniform in the bounded coefficient box. The response
  vectors are shifted and passed through the two `Rej` calls. Protocol 1's
  exact dimensions and Gaussian widths must be copied from its displayed
  algorithm (p. 14), including the change to the `(3md)`-dimensional rejection
  step inside Protocol 2 (p. 17).
- One-out-of-many proof: `r_b` is bounded-box randomness; `rho_j` are discrete
  Gaussian vectors; `z,z_b,z_c` have the widths and concatenated dimensions
  specified in Protocol 2 and its Section 6 repeated variant. Norm checks
  appear in Protocols 1 and 2 and are part of verification, not debugging
  aids.
- Rejection sampler: use the exact Algorithm 1 probability and its `K` bound;
  do not substitute a generic abort or resampling rule. Section 6 applies
  rejection to concatenations across all `r` runs to avoid multiplying the
  completeness loss by `r`.
- Extracted-witness bounds: use the enumerated `B_{d,k}` from Section 3 Method
  2 in the concrete parameter analysis. The paper explicitly warns about a
  soundness gap: extraction yields a relaxed multiple opening, not necessarily
  an opening of the exact original commitment.

Section 6.1 also requires the binding threshold to fit the M-SIS attack bound
and the M-LWE estimator to support the selected `m,n,q,B`. Table 3 gives
rounded `log q`, not exact modulus integers or a ready-to-use encoded parameter
file. Exact `q`, exact `N` for the approximate rows, and reproducible estimator
inputs must therefore be settled before the parameter set is approved.

## 5. Proposed C++ architecture

All new code belongs in the PQ-LRS backend; none belongs under either
`dilithium/` directory or in auction/application code. Keep parameter choices
immutable and explicit. Avoid global mutable modulus state so tests and
multiple configurations cannot silently interfere.

```text
Lattice_LRS/
├── cpp_backend/
│   ├── include/lattice_lrs/
│   │   ├── params.hpp
│   │   ├── ring_element.hpp
│   │   ├── matrix.hpp
│   │   ├── sampling.hpp
│   │   ├── commitment.hpp
│   │   ├── binary_proof.hpp
│   │   ├── one_out_of_many.hpp
│   │   ├── fiat_shamir.hpp
│   │   └── ring_signature.hpp
│   └── src/
│       ├── params.cpp
│       ├── ring_element.cpp
│       ├── matrix.cpp
│       ├── sampling.cpp
│       ├── commitment.cpp
│       ├── binary_proof.cpp
│       ├── one_out_of_many.cpp
│       ├── fiat_shamir.cpp
│       └── ring_signature.cpp
├── tests/
│   ├── test_params.cpp
│   ├── test_ring_arithmetic.cpp
│   ├── test_commitment.cpp
│   ├── test_binary_proof.cpp
│   ├── test_one_out_of_many.cpp
│   └── test_ring_signature.cpp
└── docs/
    └── PHASE3_RING_SIGNATURE_DESIGN.md
```

This is a proposal, not a set of files created by this design step.

| Module | Responsibility and dependencies |
|---|---|
| `params` | Immutable validated parameter tuple; enforce algebraic identities and inequalities; no hidden defaults. |
| `ring_element` | Canonical `d`-coefficient elements modulo `q`, negacyclic multiply, centered representatives, norms; NTL `ZZ` as exact coefficient backend. Decide `ZZ_pX` only after confirming `q` and NTL behavior for the chosen ring. |
| `matrix` | Vectors/matrices over the ring, matrix/vector products, commitment homomorphism, and `Rot` coefficient mapping. |
| `sampling` | CSPRNG-backed uniform ring/matrix/box sampling and the specified discrete Gaussian sampler, with reproducibility hooks isolated to tests. GMP/NTL provide arithmetic, not secure randomness. |
| `commitment` | `CKeygen`, `Com`, relaxed `Open`, homomorphic operations, dimensions, bounds, and commitment serialization. |
| `binary_proof` | Exact Protocol 1 prover/verifier plus all relation and range checks; depends on commitment, sampling, `aCom`, and `Rej`. |
| `one_out_of_many` | Exact Protocol 2 prover/verifier, digit encodings, `E_j`, combined rejection, and extraction-bound metadata; depends on binary proof and commitment. |
| `fiat_shamir` | Canonical byte encoding and random-oracle hash-to-`C^r`; separate from the protocol equations and versioned/tested. |
| `ring_signature` | RSetup/RKeygen/RSign/RVerify orchestration and signature serialization; depends on all lower modules. |

NTL/GMP are arithmetic dependencies only. They do not supply constant-time
cryptographic sampling, a cryptographic hash-to-challenge, secure memory
handling, or protocol proofs. The chosen polynomial class must not assume
field division if `q` is only established as an odd integer. For initial
arithmetic, an explicit coefficient vector of `NTL::ZZ` values with carefully
specified modular reduction is safer to audit than relying on unverified
`ZZ_pX` field assumptions.

## 6. Testing strategy

Functional checks support debugging; none by themselves establish anonymity,
unforgeability, zero knowledge, or post-quantum security.

| Test | Method and expected result |
|---|---|
| Parameter validation | Instantiate each approved paper row; assert `N=beta^k` (or explicit permitted padding), odd `q`, `d>=7`, `m*d>=86`, q inequality, `r`/soundness relation, and binding/security estimator constraints. Reject malformed or unsupported tuples. |
| Polynomial arithmetic | Check canonical coefficient range, addition/subtraction, negacyclic multiplication against an independent slow reference, and `X^d=-1`; check modular reduction and norm conventions at boundary coefficients. |
| Matrix/vector operations | Compare ring matrix-vector products and `Rot(f)` against direct polynomial multiplication for basis vectors and randomized small cases. |
| Commitment correctness | For generated `ck`, verify `Open(Com(u;r),(1,u,r))`; test homomorphic addition and scalar multiplication identities. |
| Commitment opening | Reject changed message, randomness, relaxation factor, out-of-bound opening, and invalid commitment; exercise exactly-at-bound and just-over-bound cases. Do not interpret a test as proof of M-SIS binding. |
| Binary proof correctness | Generate honest one-hot witnesses and verify non-aborting transcripts; check all equations independently. Repeat until accepted; record empirical abort frequency against the paper's bound. Test malformed one-hot vectors, bad commitments, challenges and norm violations. |
| One-out-of-many proof correctness | Generate a ring with an honestly committed zero opening at selected indices (first, middle, last); verify transcript and each indexed equation. Test padding/repeated-key semantics separately. |
| Ring key generation | Check `pk=Com(0;sk)` using the published key; validate key coefficient distribution statistically for test runs only. |
| Sign with different members | Sign the same message and exact ring with each member's secret key; each signature should verify. Never assert signatures must be byte-identical. |
| Valid signature verification | Verify signatures across repeated fresh keys, messages, and all supported ring sizes, including boundary sizes around powers of `beta`. |
| Modified message/signature rejection | Mutate one message byte, challenge, commitment, response, or serialized length independently; verifier must reject. |
| Incorrect ring rejection | Remove the signer key, substitute/reorder ring keys, duplicate or reorder entries, and use a key from incompatible parameters; behavior must match the finalized ordered-ring encoding and reject invalid signatures. |
| Anonymity evaluation | Implement the formal two-challenge experiment from Appendix D with an adversary distinguishing which of two ring members signed. Use many independent trials and statistical confidence intervals as a diagnostic only; passing cannot prove anonymity. Formal security rests on the paper's SHVZK proof and its assumptions. |

Add deterministic test seeds only via a test-only sampler interface; production
sampling must obtain entropy from a reviewed platform CSPRNG. Add tests to CTest
in stages as each module becomes reviewable. Existing smoke, NTL/GMP, and
Dilithium tests remain separate and must continue to pass.

## 7. Implementation milestones

1. **Parameter decision and notation review:** select one exact Table 3 row,
   resolve exact `q`, exact `N`, `v`, sampling conventions, and hash encoding;
   independently recalculate all inequalities and estimator claims.
2. **Arithmetic specification:** document canonical residues, polynomial and
   vector norms, `Rot`, and serialization; add non-cryptographic arithmetic
   unit tests.
3. **Sampling review:** choose and review CSPRNG and discrete-Gaussian
   implementations; validate distribution/norm claims independently. Do not
   use NTL/GMP randomness for secret sampling without a security design.
4. **Commitment module:** implement and review key generation, commit, open,
   homomorphism and bounds; add commitment tests.
5. **Binary proof:** equation/prover/verifier core implemented behind injected
   providers; production `aCom`, Gaussian and Bernoulli-exponential providers
   remain required and need independent review.
6. **One-out-of-many proof:** implement Protocol 2 and Section 6 repeated-run
   modifications, challenge-dependent equations, norm bounds and signature
   component representation; test all signer positions and padding.
7. **Fiat–Shamir and encoding:** freeze canonical transcript/ring encoding,
   hash-to-monomial mapping and domain separation; run mutation and
   cross-process determinism tests.
8. **Ring API:** implement RSetup/RKeygen/RSign/RVerify as a thin layer and add
   functional ring-signature tests.
9. **Independent review:** compare code line-by-line with protocols and
   Appendix E security arguments, audit randomness and side channels, and seek
   cryptography review before making security claims.
10. **Only after this construction is stable:** separately design the
    Wang–Chen–Ma linkability extension; it is outside this phase's scope.

## 8. Items to resolve before coding

1. Which ring-size row from Table 3 is the target? The paper offers alternatives,
   not one canonical setting.
2. What exact odd integer `q` corresponds to each table's rounded `log2 q`?
   Recompute and record the concrete q and all Section 6.1 M-SIS/M-LWE checks.
3. What exact `N` is used for rows marked approximately `2^16` and
   approximately `2^20`, and how are rings padded when `N != beta^k`?
4. Confirm `v=k*beta` for the commitment message representation against a
   formal type-level transcription of Protocols 1 and 2; Appendix D does not
   tabulate `v` separately.
5. Freeze the `aCom` construction and how it is instantiated in the
   non-interactive protocol. The text permits treating it as a random oracle
   but the production encoding/hash interface is not a ready-made API.
6. Specify exact canonical encoding for ring order, commitments, first
   messages, challenge vector and responses, plus hash-to-`C^r` rejection or
   modulo-bias handling. Section 6 gives the mathematical hash input but not
   an interoperable byte format.
7. Confirm every Gaussian parameterization (the paper defines `D_sigma` and
   standard deviation conventions separately), vector dimensions in each
   sampler, and exact `Rej` input sign convention from the displayed
   algorithms before implementation. No generic Gaussian or sampler is a
   drop-in replacement.
8. Decide how exact norm checks will handle centered representatives and
   wraparound. The paper's bounds are on integer coefficient vectors, not
   arbitrary modular representatives.
9. Verify NTL's selected polynomial/modulus API for the chosen `q`; avoid
   field-only operations unless primality is part of the selected parameter
   proof.
10. Determine the intended threat model, side-channel expectations, and
    security review process. The paper's stated unforgeability analysis is in
    the classical random-oracle model and is not a proof of implementation
    security.

## References

1. M. F. Esgin, R. Steinfeld, A. Sakzad, J. K. Liu, and D. Liu, “Short
   Lattice-based One-out-of-Many Proofs and Applications to Ring Signatures,”
   IACR ePrint 2018/773, full version accepted to ACNS 2019.
   [Paper PDF](https://eprint.iacr.org/2018/773.pdf). Relevant locations:
   Sections 2–3, printed pp. 5–13; Section 4, pp. 13–15; Section 5,
   pp. 15–18; Section 6 and 6.1, pp. 18–21; Appendix D, especially Table 4,
   pp. 24–26; Appendix E for proofs.
2. Current project build files and tests: [`CMakeLists.txt`](../CMakeLists.txt),
   [`cpp_backend/CMakeLists.txt`](../cpp_backend/CMakeLists.txt),
   [`tests/`](../tests/).

## Parameter Validation – N = 64

This section validates the exact `N=64` row against the original ePrint full
version, not against a prior summary. Paper locations below use printed page
numbers. Section 6.1 and Appendix D are the source of the concrete instance;
Sections 2–5 and Appendix E supply the assumptions and proof bounds.

### A. Selected Table 3 row

| Parameter | Selected value | Validation/source |
|---|---:|---|
| Ring size `N` | 64 | Table 3, p. 20, first row. |
| `n,m` | 5, 13 | Table 3, p. 20, `(n,m)` row. |
| Ring degree `d` | 256 | Table 3, p. 20, `(d, log q)` row. |
| `log2(q)` | 50 (reported rounded) | Table 3, p. 20. The table does not give an exact integer `q`; it must not be read as `q=2^50`. |
| `k,beta` | 2, 8 | Table 3, p. 20, `(k,beta)` row. |
| Repetitions `r` | 16 | Table 3, p. 20, `r` row. |
| Soundness parameter `lambda` | 128.0 | Table 3, p. 20, `lambda` row; this row is the repeated-protocol soundness exponent. It is not by itself a concrete M-LWE security estimate. |
| Signature size | 774 KB | Table 3, p. 21, rounded figure. It depends on the paper's encoding/size calculation and is not a byte-exact serialization specification. |
| `v` | 16 | Appendix D, Table 4, p. 24 gives commitment-key dimension `n x (m+k*beta)`; hence `v=k*beta=2*8=16`. |
| `B` | 1 | Section 6.1, p. 20. Fresh secret/opening coefficients are sampled uniformly from `{-1,0,1}`. |
| `phi1,phi2` | 4, 4 | Section 6.1, p. 20 states `phi1=phi2=2^2`; these are rejection-sampling controls. |

All selected row values match Table 3. The exact modulus and exact enumerated
Method 2 value `B_{d,k}` are not printed as exact numbers in Tables 3–4.

### B. Relationships and derived values

The construction-specific calculations below use `B=1`,
`phi1=phi2=4`, and the selected row.

#### Ring size and dimensions

\[
N=\beta^k=8^2=64.
\]

This is an exact identity (Section 5, p. 15; Section 6, p. 18). Appendix D,
Table 4 gives the public commitment-key shape `R_q^{n x (m+k beta)}`:

\[
v=k\beta=2\cdot8=16,\qquad
G\in R_q^{5\times(13+16)}=R_q^{5\times29}.
\]

The randomness matrix part has `m=13` columns; `G_r=[I_5 | G'_r]` has
`G'_r` with shape `5 x (13-5) = 5 x 8`; `G_m` has shape `5 x 16`. The user
public key is one commitment in `R_q^{5 x 1}` (Appendix D, Table 4). Each
ring element has `d=256` integer coefficients.

#### Challenge space and repetition count

Section 6, p. 18 uses
\[
\mathcal C=\{X^\omega:0\leq\omega<2d\},\quad |\mathcal C|=2d=512.
\]
Appendix D, Table 4 gives single-run soundness
\[
\eta=\frac{\max\{2,\log_\beta N\}}{2d}
     =\frac{\max\{2,2\}}{512}=\frac1{256}=2^{-8}.
\]
The repetition formula is
\[
r=\left\lceil\frac{\lambda}{\log_2(1/\eta)}\right\rceil
 =\left\lceil\frac{128}{8}\right\rceil=16.
\]
Thus the repeated soundness error is
\(\eta^r=(2^{-8})^{16}=2^{-128}\), matching Table 3. This calculation is
separate from computational security under M-SIS/M-LWE.

#### Norm, sampler, and commitment parameters

- `B=1`: coefficient box `[-1,1]` for fresh secret/opening randomness, as
  stated in Section 6.1, p. 20.
- `phi1=phi2=4`: Section 6.1, p. 20 sets both to `2^2` so the expected
  signing retry count is at most 3.
- The commitment key is generated as in Section 2.2, p. 6:
  `G'_r <- R_q^{n x (m-n)}`, `G_m <- R_q^{n x v}` independently uniform;
  `G=[I_n | G'_r | G_m]`. Here the shapes are `5x8`, `5x16`, and `5x29`.
- A key/opening randomness is `r <- S_B^m`, i.e. 13 ring polynomials / 3328
  coefficients uniform in `{-1,0,1}`. `Com_ck(u;r)=G(r,u)`.
- The repeated Section 6 protocol applies rejection sampling to concatenated
  `r`-run response vectors. Its stated distributions include
  `f_{j,i} <- D^d_{phi1 sqrt(k r)}` for `i != 0` and
  `z,z_b,z_c <- D^{md}_{phi2 B sqrt(3mdr)}` (Section 6, p. 19). Substitution:
  widths are `4*sqrt(32)` and `4*sqrt(3*13*256*16)`, respectively, under the
  paper's `D_s` parameter notation. Protocol 2's internal `r_a,r_d` use
  `D^{md}_{phi2 B sqrt(3md)}` because that subproof rejects a `3md`-dimensional
  concatenation (Protocol 2, p. 17). The Gaussian definition/convention is in
  Section 2.3, p. 7; do not reinterpret `s` as a standard deviation without
  converting by the paper's `sqrt(2 pi)` convention.
- The commitment hiding assumption is
  `M-LWE_{m-n,n,q,B}=M-LWE_{8,5,q,1}` (Section 2.2, Lemma 1, p. 7, and
  Section 6.1, p. 20). It is over degree-256 `R_q`, with 8 secret ring
  elements, 5 module samples, and coefficient secret/error distribution
  `S_1`.
- Commitment binding for the ring signature uses
  `M-SIS_{n,m+v,q,2T'}=M-SIS_{5,29,q,2T'}` (Lemma 1, p. 7). The scalar
  coefficient lattice rank for the paper's estimate is
  `n_L=n*d=5*256=1280`.

#### `T1`, `T'`, and `B_{d,k}`

Section 6, p. 19 (repeated-protocol tweak) and Appendix E give
\[
T_1=(2d+2)\sqrt{54\phi_1^4d^3k^3\beta(\beta-1)r^2
                  +12\phi_2^2B^2m^2d^2r}.
\]
Substitution:
\[
T_1=514\sqrt{54(4^4)(256^3)(2^3)(8)(7)(16^2)
                  +12(4^2)(1^2)(13^2)(256^2)(16)}
\approx83,829,948,035.0075.
\]
The exact binding threshold required is strict: the M-SIS shortest-vector
estimate must be **greater than** `2*T1` (Section 6.1, Eq. (11), p. 20).
Thus `2*T1 ≈ 167,659,896,070.0149`.

Theorem 3, p. 19 gives the generic witness threshold
\[
T'=\max\left\{T_1,
 \sqrt{\left(24\sqrt{3r}\,mB(k+1)d^{k+1}\right)^2+2^{2k}}\right\}.
\]
After substitution, the second term is
`24*sqrt(3*16)*13*1*(2+1)*256^(2+1)`;
numerically its dominant term is approximately `108,796,860,512.7112`, so
the generic theorem threshold is
\[
T'_{generic}\approx108,796,860,512.7112.
\]
The added `2^{2k}=16` is negligible at the shown precision. This is a
conservative calculation using Method 1's `d`-based extraction bound.

Section 6.1, Eq. (11) instead uses Method 2's enumerated global bound
`B_{d,k}` from Section 3, Lemma 10, p. 12. For `d=256,k=2`, Lemma 10 says
\[
B_{256,2}\leq d^{k-1/2}=256^{3/2}=4096,
\quad B'_{256,2}:=\sqrt d B_{256,2}\leq d^k=65,536.
\]
The exact enumeration requires
\((k-1)\binom{2d-1}{k}=\binom{511}{2}=130,305\) polynomial
multiplications (Lemma 10); the paper says it computed the exact values for
Table 3 rows but does not print the exact `B_{256,2}`. Table 2, p. 12 reports
only rounded `log2(B'_{256,2})=15.21`, implying an approximate `B'` of
`2^15.21 ≈ 37,902.36`; this is a rounded report, not an exact reproducible
value.

For an auditable conservative check, substitute `B'<=65,536` into Eq. (11)'s
extraction term:
\[
2\cdot24\sqrt{3r}\,Bmd(k+1)B'
\leq2\cdot24\sqrt{48}\cdot1\cdot13\cdot256\cdot3\cdot65,536
\approx217,593,721,025.4225.
\]
This exceeds `2*T1`, so it is the conservative required SIS length. With the
rounded Table 2 value instead, this term is about `125.8` billion and `2*T1`
dominates; the conservative calculation avoids treating rounded `B'` as exact.

### C. Modulus constraints and exact arithmetic candidates

The original paper's Section 2.1 defines `q` as an **odd positive integer**.
Section 6.1 explicitly notes that the construction does not need a special
modulus form (Introduction, p. 4); the final paper does not require `q` prime
or `q ≡ 5 mod 8`. The challenge-difference/Vandermonde argument uses odd `q`
so that 2 is invertible (Section 3, Lemma 8, p. 11). The ring is the quotient
`R_q=Z_q[X]/(X^256+1)`, not a field, and the binary proof separately handles
zero divisors. Table 3 also states the parameter search was restricted to
`log2 q <=64` (p. 20).

#### Numeric lower bounds

Theorem 2 (Protocol 2, p. 17) gives the single-run condition
\[
q>(10\phi_1d\sqrt{dk(\beta-1)}+2)^2.
\]
Substitution gives
\[
q>(10\cdot4\cdot256\sqrt{256\cdot2\cdot7}+2)^2
 \approx375,812,090,536.585,
\]
so an integer `q` must be at least `375,812,090,537` for that single-run
condition.

Section 6, Assumption 1, p. 19, strengthens this for the `r`-repeated
signature:
\[
q>(10\phi_1d\sqrt{dkr(\beta-1)}+2)^2.
\]
Substitution gives
\[
q>(10\cdot4\cdot256\sqrt{256\cdot2\cdot16\cdot7}+2)^2
 \approx6,012,964,022,934.341,
\]
so the integer condition is `q >= 6,012,964,022,935` before imposing oddness.
This also dominates the single-run condition.

The M-SIS condition from Section 6.1, Eq. (11), p. 20 and Appendix C,
Eq. (12), p. 24 is
\[
\min\left\{q,
2^{2\sqrt{n_L\log_2(q)\log_2(\delta)}}\right\}
>\max\left\{2T_1,
2\cdot24\sqrt{3r}\,Bmd(k+1)B'_{d,k}\right\}.
\]
Using the rigorous conservative `B'<=65,536`, the RHS is
`217,593,721,025.4225` (log2 ≈ `37.66285`). The `q` member of the minimum
must exceed that value; the lattice-reduction member requires
\[
\log_2(q)>\frac{(\log_2(217,593,721,025.4225))^2}
 {4(1280)\log_2(1.0045)}\approx42.77052585624,
\]
or `q > 7,502,589,985,959.78`. Combined with the repeated protocol bound,
the conservative smallest **odd** integer satisfying the explicit numerical
q/SIS inequalities is `7,502,589,985,961`. This is a mathematical floor,
not a recommended selected modulus. The row's reported `log2 q≈50` is much
larger.

For exact examples near the row's reported logarithm, these odd integers all
satisfy the explicit q and conservative M-SIS inequalities:

| Candidate (not selected) | Exact integer | Bit length | `log2(q)` | M-SIS bound at this q |
|---|---:|---:|---:|---:|
| `2^50 - 3` | 1,125,899,906,842,621 | 50 | 49.9999999999999962 | `min(...) ≈ 1.813224239260e12` |
| `2^50 - 1` | 1,125,899,906,842,623 | 50 | 49.9999999999999987 | `min(...) ≈ 1.813224239260e12` |
| `2^50 + 1` | 1,125,899,906,842,625 | 51 | 50.0000000000000013 | `min(...) ≈ 1.813224239260e12` |

For these, the SIS bound/RHS ratio using the conservative extraction bound is
about `8.33`. All are merely explicit arithmetic candidates; none is selected
or declared secure. The candidates are odd (some are composite), which is
permitted by the stated paper conditions. Since `q` is not required prime,
`R_q` may have zero divisors; algorithms must not assume field division.
Section 3's challenge inverse identities still apply for odd `q` as proved by
the authors. Ring irreducibility over `Q` is not the same as irreducibility
modulo `q` and is not required for this quotient-ring representation.

### D. M-SIS and M-LWE security check

**M-SIS, conditional numeric check.** For this row, the commitment's SIS
instance is `M-SIS_{5,29,q,2T'}` over degree `d=256`; the scalar rank used in
the paper's estimate is `n_L=1280`. At a candidate with `log2(q)≈50` and
`delta=1.0045`, Eq. (12)'s reduction-length estimate is approximately
`2^40.72 = 1.8132e12`, while the conservative Eq. (11) requirement is
`2T' <= 2.17594e11` (`2^37.66`). Thus the displayed M-SIS inequality passes
under the paper's estimate and chosen `delta`, with the conservative
`B'` bound. This verifies the arithmetic comparison, not the accuracy of the
attack model or a concrete operation-count security level.

**M-LWE, not independently verified.** Lemma 1 requires
`M-LWE_{8,5,q,1}` to make the commitment hiding. Section 6.1 says `m` is
chosen with the Albrecht–Player–Scott LWE estimator and treats the B=1
uniform-small secret/error case as the easiest case; it then uses
`delta<=1.0045` to claim 128-bit post-quantum security (pp. 20, 24). Table 3
does not provide the estimator transcript, exact q, version/commit, cost
model, or a mapping of this module-LWE instance to the estimator's input.
No estimator was run for this validation, so the M-LWE security level is **not
independently confirmed**. A reproducible check needs the authors' modeling
choice (structured module versus flattened LWE, sample count, secret and error
distribution conversion), exact q, estimator revision, attack set, and cost
model. The maintained Albrecht estimator documents attacks for LWE, but a
direct run on a flattened LWE instance does not automatically capture the
module structure of `M-LWE_{8,5,q,1}`; the reduction from this structured
instance to estimator inputs must be justified. The current Albrecht
`lattice-estimator` repository is evolving and warns that estimates depend on
the revision; record a pinned commit if used.
Do not install or run an estimator without a separate approved task.

The paper's `lambda=128` row confirms the protocol's repeated soundness error
is `2^-128`. It does **not** alone establish 128-bit computational security.
The overall security statement remains conditional on M-LWE/M-SIS, the
authors' root-Hermite-factor/cost assumptions, the classical random-oracle
model, and the proof's insider-corruption definition. Appendix E gives
reductions/proofs under those assumptions; it is not evidence that the
concrete estimator input has been independently reproduced.

### E. Implementation implications for the existing macOS environment

- Use an explicit 256-coefficient representation for each polynomial in
  `Z_q[X]/(X^256+1)`. Implement negacyclic multiplication with the defining
  reduction `X^256=-1`; validate against an independent slow reference before
  using it in protocol code.
- `q` must remain a runtime/configuration parameter until an exact value is
  reviewed. Use `NTL::ZZ` or another exact integer type for intermediate
  coefficients and modular reduction. Do not use machine integers for products
  whose bounds exceed 64 bits without a proved reduction strategy.
- Canonical centered residues for odd `q` lie in
  `[-(q-1)/2,(q-1)/2]` (Section 2.1). Norms are calculated on those specified
  integer representatives, not by treating residues as unsigned values.
- NTL/GMP provide arithmetic, not a cryptographically sound uniform/Gaussian
  sampler or rejection sampler. Sampling `S_1`, uniform matrices, discrete
  Gaussians with the paper's parameter convention, and the exact Rej acceptance
  probability need a separately selected and reviewed CSPRNG/sampler design.
  Do not use convenience randomness from NTL for secrets.
- For odd composite candidates, `ZZ_pX`/finite-field inverse routines must not
  be assumed valid as field operations. Modular polynomial inversion should
  either use a proved construction for the specific challenge differences or
  verify a unit and compute a valid inverse over `Z_q`; the paper's challenge
  identities are the correctness basis. No generic inversion of arbitrary
  ring elements is implied.
- Apple Silicon/Clang is suitable for the C++17 implementation and NTL/GMP
  exact arithmetic. No system configuration or dependency change is needed for
  this parameter-only conclusion. Arithmetic performance is not a security
  property; constant-time behavior and side-channel review remain separate.

### F. Unresolved items and recommendation

1. **Exact `q`:** the paper supplies only rounded `log2(q)=50` for this row.
   The three values above are mathematical examples, not an approved modulus.
2. **Exact Method 2 bound:** Table 2 prints `log2(B'_{256,2})=15.21` rounded;
   the paper says it enumerated the exact value but does not publish it. The
   exact conservative proof check used here is `B'<=65,536`.
3. **M-LWE estimator:** no exact q or reproducible estimator run is supplied;
   the approximately 128-bit computational claim has not been independently
   verified for `M-LWE_{8,5,q,1}`.
4. **Prime versus odd:** the final full paper requires odd `q`, not prime. Any
   implementation plan that silently assumes prime `q` changes the verified
   conditions and must be reviewed.
5. **Encoding and implementation security:** exact byte encoding/hash-to-
   challenge, sampler implementation, side-channel behavior, and measured
   signature byte length remain outside this mathematical parameter check.

**Recommendation:** the `N=64` Table 3 row is internally consistent, and its
repetition and conservative explicit M-SIS inequalities check out. The
configuration is **not ready for cryptographic implementation** until an
exact odd modulus is selected and reviewed, the authors' M-LWE estimator
model is reproduced with a pinned tool/cost model, and the exact `B_{256,2}`
enumeration and sampler conventions are fixed. No modulus is selected here.

### Parameter-validation sources

- Esgin et al., [IACR ePrint 2018/773 PDF](https://eprint.iacr.org/2018/773.pdf):
  Section 2.1 (printed pp. 5–6, centered representatives and logs), Section
  2.2 (pp. 6–7, M-SIS/M-LWE and commitments), Section 3, especially Lemmas
  8–10 (pp. 11–12, monomial inverses and `B_{d,k}`), Protocol 1 (p. 15),
  Protocol 2 (pp. 16–18), Section 6 and Assumption 1/Eq. (11)/Table 3
  (pp. 19–21), Appendix C/Eq. (12) and Appendix D/Table 4 (pp. 24–25),
  Appendix E (proofs and norm bounds).
- Albrecht, Player, and Scott, “On the concrete hardness of learning with
  errors,” cited as [2] by Esgin et al.; estimator implementation:
  [malb/lattice-estimator](https://github.com/malb/lattice-estimator).

### M-LWE Security Estimation and Final Modulus Selection

This subsection completes the estimator review for the same `N=64` row. It
supersedes the earlier note that the estimator's model had not yet been traced;
the concrete estimate itself remains unrun and no modulus is selected.

#### Exact commitment assumption and parameter mapping

Esgin et al., Section 2.2, Definition 2 (printed p. 6), defines
`M-LWE_{n,m,q,B}` over `R_q=Z_q[X]/(X^d+1)`: sample
`s <- S_B^n`, then each sample consists of `a <- R_q^n` and
`<a,s>+e`, with `e <- S_B`. The commitment key fixes
`G_r=[I_n | G'_r]` and commits with `G(r,u)`. Lemma 1 (p. 7) states hiding
under `M-LWE_{m-n,n,q,B}`. For the selected row this is exactly
`M-LWE_{8,5,q,1}` (Section 6.1, p. 20):

| Quantity | Exact construction value | Meaning |
|---|---:|---|
| Polynomial ring | `Z_q[X]/(X^256+1)` | Negacyclic quotient ring; degree 256 |
| Module secret rank | 8 | Eight ring elements in `s` |
| Module sample vector rank | 5 | Each `a` has five ring elements and produces one ring element |
| Number of module samples | 5 | The second M-LWE subscript in this paper's notation |
| Modulus | One of the candidate integers below | Odd; exact choice is unresolved |
| Secret coefficients | Uniform in `{-1,0,1}` | `S_1^8`, coefficientwise |
| Error coefficients | Uniform in `{-1,0,1}` | One degree-256 error polynomial per module sample |

The paper uses both the words “Module-LWE” and its structured ring `R_q`;
this is not ordinary unstructured LWE and it is not the assumption
`M-LWE_{5,8,...}`. For the conventional coefficient expansion, the secret has
`8*256=2048` scalar coefficients, and five module samples yield
`5*256=1280` scalar equations. Thus the natural unstructured-LWE proxy input
is `n=2048`, `m=1280`, the same `q`, and ternary secret and error
coefficients. Its expanded coefficient matrix is block-negacyclic and highly
structured; an ordinary LWE estimator instead models a random unstructured
matrix. Multiplying ranks by 256 describes dimensions, but does not prove
equivalence or preserve module-specific attacks. The proxy below is therefore
an exploratory attack calculation only; it is **not established as exact or
conservative** for this M-LWE instance.

The `B=1` secret/error distribution is justified directly by Definition 2 and
Section 6.1. It is not a Gaussian approximation: in the estimator API the
closest exact coefficient marginal is `ND.Uniform(-1,1)`. This matches the
individual coefficient distribution, but still cannot encode the module
matrix's negacyclic correlations. There is no Ring-LWE assumption in the
commitment hiding lemma; polynomial-ring structure is incorporated through
Module-LWE. Separately, the protocol's challenge algebra is carried out in
`R_q`, while commitment binding is based on M-SIS. These are different roles
and assumptions.

#### Estimator, reproducibility, and execution status

The official `malb/lattice-estimator` README describes a SageMath module and
lists LWE, NTRU, and SIS evaluators. At the pinned revision below, the extended
`LWE.estimate(...)` routine evaluates supported Arora–GB, coded-BKW, primal
uSVP, primal BDD, primal hybrid variants, dual, and dual-hybrid attacks with
the repository's default lattice-reduction cost and shape models. The
repository says these cost/shape predictions are heuristic. Its fast
`estimate.rough(...)` deliberately uses a non-default cost model and omits
attacks, so it is not the requested run. The official README identifies no
Module-LWE estimator or Module-LWE matrix model. Its default supported attack
list is not a completeness claim about all known attacks against this exact
structured instance.

The estimator revision recorded for reproducibility is commit
[`53da5982597709ba0fdf94ea37a84d822310fd84`](https://github.com/malb/lattice-estimator/commit/53da5982597709ba0fdf94ea37a84d822310fd84)
(official repository's current `main` commit observed during this review).
The estimator version is that source revision, rather than a separately
published release number. This workspace has Python 3.11.9, but no SageMath,
Docker/Podman, or isolated environment manager was available; SageMath is a
required dependency of the estimator. Consequently **no estimator calculation
was executed and there are no attack costs, security-bit outputs, or BKZ
parameters to report**. No dependency was installed and no project dependency
was changed.

When a separate SageMath environment is available, the following commands
reproduce the proposed *unstructured proxy*, not an exact M-LWE estimate. The
checkout is placed in `/tmp`; run once for each candidate, and retain the full
console output, Sage version, operating system, CPU, and estimator commit with
the research record:

```sh
git clone https://github.com/malb/lattice-estimator.git /tmp/lattice-estimator-53da598
git -C /tmp/lattice-estimator-53da598 checkout --detach 53da5982597709ba0fdf94ea37a84d822310fd84
git -C /tmp/lattice-estimator-53da598 rev-parse HEAD
sage --version
cd /tmp/lattice-estimator-53da598
sage -python - <<'PY'
from estimator import LWE, ND

qs = [2**50 - 3, 2**50 - 1, 2**50 + 1]
for q in qs:
    print(f"\nq={q}")
    p = LWE.Parameters(
        n=8*256, m=5*256, q=q,
        Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1),
        tag=f"flattened MLWE proxy q={q}",
    )
    print(LWE.estimate(p))
PY
```

The attack interface returns per-attack work factors and, where applicable,
BKZ block sizes/dimensions and auxiliary parameters. It should be recorded
without collapsing the attack set to the minimum alone. In particular, the
extended run includes coded-BKW, primal uSVP/BDD/hybrid, dual/dual-hybrid and
Arora–GB in its supported set; Arora–GB's documented bounded-noise sample
condition (`m > n^2`) is not met by this proxy (`1280 < 2048^2`), so it may be
inapplicable. Failures/unsupported attack cases must be retained and explained,
not silently interpreted as infinite security. The results would be
heuristic classical cost-model estimates for flattened ordinary LWE. They do
not validate Module-LWE security, quantum cost, module-specific attacks,
security reductions, or the paper's `delta`-based theorem claim. A separate
module-aware analysis and review of attack coverage is still needed.

#### Candidate-by-candidate arithmetic and M-SIS review

All three candidates are odd positive integers and therefore meet the paper's
stated parity condition. The paper does not require primality or a particular
congruence class; none of these candidates is rejected for being composite.
They define the requested quotient ring, but `R_q` must not be treated as a
field. Their exact bit lengths matter: `2^50+1` has bit length 51 even though
its base-2 logarithm rounds to 50. The explicit repeated protocol bound is
`q > 6,012,964,022,934.341`; each candidate is far above it and below the
paper's search cap `log2(q)<=64`.

For each candidate, recomputing Eq. (11) with `d=256`, `n_L=nd=1280`,
`delta=1.0045`, and the conservative `B'_{256,2}<=65,536` gives the M-SIS
right-hand requirement `217,593,721,025.4225`, dominated by the extraction
term rather than `2T_1=167,659,896,070.0149`. The reduction-length term
`2^(2 sqrt(n_L log2(q) log2(delta)))` is approximately
`1.813224239260e12` for all three candidates, so the displayed inequality
passes with a ratio of about 8.33. This is an arithmetic check of the paper's
stated M-SIS estimate using a conservative extraction bound; it does not
independently estimate M-SIS attack cost or establish concrete security.

| Candidate q | Arithmetic constraints | M-SIS | M-LWE estimate | Security assumptions | Recommendation |
|---|---|---|---|---|---|
| `2^50-3` = `1,125,899,906,842,621` (50 bits; `log2 q≈49.9999999999999962`) | Odd; satisfies repeated q bound and `log2 q<=64`; prime not required | Eq. (11) passes under conservative `B'<=65,536` and `delta=1.0045` | Not run; no numeric estimate. Same flattened proxy inputs as other rows | Structured `M-LWE_{8,5,q,1}` remains unverified; paper's M-SIS/delta model is conditional | Do not select yet |
| `2^50-1` = `1,125,899,906,842,623` (50 bits; `log2 q≈49.9999999999999987`) | Odd; divisible by 3; satisfies repeated q bound and `log2 q<=64`; composite allowed by paper | Eq. (11) passes under conservative `B'<=65,536` and `delta=1.0045` | Not run; no numeric estimate. Same flattened proxy inputs as other rows | Structured `M-LWE_{8,5,q,1}` remains unverified; paper's M-SIS/delta model is conditional | Do not select yet |
| `2^50+1` = `1,125,899,906,842,625` (51 bits; `log2 q≈50.0000000000000013`) | Odd; divisible by 5; satisfies repeated q bound and `log2 q<=64`; composite allowed by paper | Eq. (11) passes under conservative `B'<=65,536` and `delta=1.0045` | Not run; no numeric estimate. Same flattened proxy inputs as other rows | Structured `M-LWE_{8,5,q,1}` remains unverified; paper's M-SIS/delta model is conditional | Do not select yet |

#### Independent audit of the existing parameter calculations

- `N=beta^k=8^2=64` and `v=k beta=2*8=16` are correct for this row.
- With `|C|=2d=512`, the one-run error is
  `eta=max(2,log_beta(N))/(2d)=2/512=2^-8`; `r=ceil(128/8)=16` and
  `eta^r=2^-128`. This is protocol soundness, not a 128-bit computational
  attack estimate.
- `phi1=phi2=4`, `B=1`, and the commitment M-LWE parameters
  `M-LWE_{m-n,n,q,B}=M-LWE_{8,5,q,1}` match the paper's Section 6.1 setup.
- Re-evaluation gives `T1=83,829,948,035.00746`,
  `2T1=167,659,896,070.01492`, generic Theorem 3 `T'≈108,796,860,512.71124`,
  and conservative Method 2 `B'<=d^k=65,536`. These match the documented
  calculations. The exact enumerated Method 2 value is still not published;
  the rounded table value must not be substituted as exact.
- The single-run and repeated q lower bounds remain approximately
  `375,812,090,536.585` and `6,012,964,022,934.341`, respectively. The
  stronger repeated bound applies to the repeated construction.
- At `delta=1.0045`, solving the conservative M-SIS reduction-length side of
  Eq. (11) gives `q > 7,502,589,985,959.782`; the smallest odd integer above
  that threshold is `7,502,589,985,961`. The three candidates exceed it.
- The `lambda=128` Table 3 entry is verified as the repeated protocol
  soundness exponent (`2^-128`). It must not be presented as an independently
  verified 128-bit classical or post-quantum computational security level.

The previous candidate table described all three bit lengths as though they
were 50. That was imprecise: `2^50+1` has 51 bits, although
`log2(2^50+1)` is only about `1.28e-15` above 50. The corrected exact bit
lengths and high-precision logarithms are shown above and in the arithmetic
table in Section C.

#### Final recommendation and unresolved assumptions

**Recommendation: Not ready; further analysis required.** All three values
meet the paper's explicit odd-modulus and displayed conservative q/M-SIS
inequalities. That does not resolve M-LWE: the exact structured instance has
not received a module-aware estimate, and the flattened ordinary-LWE proxy
was not run and is not known to be conservative. There is no defensible
security-based basis here to rank or select the candidates. Before
implementation, the research review must settle an exact modulus; reproduce
or independently justify the original M-LWE security analysis and its
module-to-estimator model; record actual estimator outputs and cost assumptions
if using the proxy; and review module-specific/classical and quantum attack
coverage. The paper's `delta<=1.0045` and its cited estimator-based parameter
choice remain author assumptions until that analysis is independently
reproduced. No cryptographic implementation should begin on the strength of
these arithmetic checks alone.

Estimator source locations used in this review: official pinned
[README](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/README.rst)
(scope, heuristic cost models, and supported attack families),
[`estimator/lwe.py`](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe.py)
(`LWE.estimate` and default attack list),
[`estimator/lwe_parameters.py`](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_parameters.py)
(`LWEParameters` input definition), and
[`estimator/nd.py`](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/nd.py)
(`Uniform(-1,1)` distribution). The construction parameters and assumption
mapping are from Esgin et al., [IACR ePrint 2018/773](https://eprint.iacr.org/2018/773.pdf),
Section 2.2, Definition 2 and Lemma 1 (printed pp. 6–7), and Section 6.1
(printed p. 20).

### Alternative Module-LWE Estimators

This review evaluates tools against the commitment hiding assumption
`M-LWE_{8,5,q,1}` over `R_q=Z_q[X]/(X^256+1)`: eight secret ring elements,
five samples, and coefficientwise IID uniform secret and error coefficients
in `{-1,0,1}`. This follows Esgin et al., Section 2.2, Definition 2 and
Lemma 1, substituting `m=13`, `n=5`, and `B=1`. The candidates are the three
q values tabulated above.

| Tool | Module structure / degree 256 | q about 2^50 | Exact ternary laws? | Attack coverage and applicability |
|---|---|---|---|---|
| Krebs, [A Tool for the Estimation of Lattice Parameters](https://github.com/krebsni/a-tool-for-the-estimation-of-lattice-parameters) | Provides an MLWE-shaped API with degree, module rank, q, sample count, and distributions. Its documented attack conversion is `MLWE_{n,d,q,m} -> LWE_{n*d,q,m*n}`; it flattens and loses block-negacyclic structure. Degree 256 can be described, but not retained in the attack instance. | Sage/Python integers can hold the exact candidates. | A bounded-uniform input is available, but the LWE path represents the secret with a fixed Hamming weight and converts non-Gaussian errors to a variance-derived Gaussian parameter. Hence not the exact IID vector distributions for both sides. | Uses an Albrecht-based suite of ordinary LWE attacks, including primal, dual, BKW-coded and algebraic routines according to configuration. Flattened proxy only. README's `requirements.py` appears to be a typo; checkout contains `requirements.txt`. |
| Official [Albrecht lattice estimator](https://github.com/malb/lattice-estimator) | Supports ordinary LWE, NTRU and SIS, not direct module/ring input. Can only receive a flattened ordinary-LWE proxy. | Sage `ZZ` accepts exact candidate integers. | `ND.Uniform(-1,1)` models scalar IID ternary distributions exactly in ordinary LWE; it cannot express the module matrix structure. | Full LWE attacks include primal uSVP/BDD/hybrid, dual and dual-hybrid, coded-BKW and Arora–GB, subject to version/configuration. Heuristic BKZ cost and shape models; proxy only. |
| [PQShield estimator](https://github.com/PQShield/lattice-estimator) (prior audit) | Exposes an MLWE interface but its core simplifies the module calculation. | No: q is stored in 32-bit C++ `int`. | Does not preserve the required distributions in the estimate. | Cannot process these q candidates; not applicable. See preceding audit. |
| [mPrimal](https://github.com/FTcode/mPrimal) / [mBKZ](https://github.com/lducas/mBKZ) | Models module structure for a selected primal attack. The ring is `Phi_512`, degree 256; code can name conductor 512 in principle, but the mBKZ artifact's documented/released experimental profiles cover low conductors only through 16. | 50-bit values fit signed 64-bit integers, but end-to-end support for these q values is not documented or verified. | No: mPrimal's generator samples Gaussian noise from `sigma`, rather than ternary coefficients. | Module-primal/BKZ modeling only, not a broad attack suite. No validated conductor-512 profile; not an exact estimate. |

The Krebs conversion gives scalar LWE dimension `256*8=2048` and scalar sample
count `256*5=1280`. This dimensional flattening does not prove equivalence to
the module distribution: the original matrix consists of negacyclic
polynomial-multiplication blocks, whereas standard LWE uses an unstructured
uniform matrix. It additionally changes the secret law (IID ternary to a
fixed-weight representation) and error law (ternary to variance-matched
Gaussian). These are model substitutions and must not be silently described
as the exact assumption or as conservative.

The official Albrecht estimator is the best-supported choice here for a
transparent ordinary-LWE proxy, but it has no direct MLWE input. The mPrimal
artifact is relevant for module-aware primal-attack research, but it is
restricted in attack coverage and presently lacks demonstrated degree-256
support and the exact error distribution. The mBKZ paper describes experiments
through cyclotomic conductor 16; our ring has conductor 512. Neither currently
provides a complete exact estimate.

#### Optional isolated ordinary-LWE proxy

No reviewed tool was found that accepts the exact structure and both exact
coefficient laws while evaluating a broad attack suite. Therefore the script
below is explicitly a flattened proxy, not an exact Module-LWE estimate. It
does not touch the project environment. Install Sage into a separate conda
environment (using `conda` instead of `mamba` if needed), then pin the official
estimator revision already used in this document:

```sh
mamba create -n pq-lrs-lwe -c conda-forge sage
mamba activate pq-lrs-lwe
git clone https://github.com/malb/lattice-estimator.git lattice-estimator-pinned
git -C lattice-estimator-pinned checkout 53da5982597709ba0fdf94ea37a84d822310fd84
cd lattice-estimator-pinned
```

Save this as `estimate_flattened_proxy.sage` in the checkout and run
`sage estimate_flattened_proxy.sage`:

```python
from sage.all import ZZ
from estimator import LWE, ND

for q in (ZZ(2)**50 - 3, ZZ(2)**50 - 1, ZZ(2)**50 + 1):
    params = LWE.Parameters(
        n=2048, q=q, Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1), m=1280
    )
    print("ordinary-LWE flattened proxy; q =", q)
    print(LWE.estimate(params))
```

This script was not run; it reports no security bits in this review. Any future
run must preserve the proxy label and record Sage version, estimator commit,
attack outputs, BKZ/cost-model configuration, and host environment. A Krebs
run should likewise pin its repository commit and inspect the distribution
and reduction code; its output remains an approximation under the caveats
above. Sage's separate conda installation instructions are at
[doc.sagemath.org](https://doc.sagemath.org/html/en/installation/conda.html).

#### Finding

**No exact end-to-end estimator was identified.** Krebs accepts an MLWE-shaped
description but evaluates a flattened LWE problem with distribution changes;
Albrecht is ordinary-LWE only; mPrimal is module-aware for a restricted primal
attack but does not model the exact ternary distribution or demonstrate our
degree; and PQShield cannot represent q. No q candidate is ranked and no
computational security level is claimed. The existing arithmetic and M-SIS
checks do not close this M-LWE evidence gap. Further work needs a validated
degree-256 module-aware model, justified treatment of the exact distributions,
and broader attack coverage before a security estimate can be used to support
implementation readiness.

Sources: [Krebs estimator repository](https://github.com/krebsni/a-tool-for-the-estimation-of-lattice-parameters), its [supporting thesis](https://elib.uni-stuttgart.de/bitstreams/913a885a-24c1-4996-9cd5-29303bcb1ea1/download); pinned [Albrecht estimator README](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/README.rst), [`estimator/lwe.py`](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe.py), and [`estimator/lwe_parameters.py`](https://github.com/malb/lattice-estimator/blob/53da5982597709ba0fdf94ea37a84d822310fd84/estimator/lwe_parameters.py); [mPrimal README and source](https://github.com/FTcode/mPrimal), [`primal_MLWE.py`](https://github.com/FTcode/mPrimal/blob/main/primal_MLWE.py), [`mBKZsim.py`](https://github.com/FTcode/mPrimal/blob/main/mBKZsim.py); [mBKZ artifact](https://github.com/lducas/mBKZ) and [paper](https://eprint.iacr.org/2025/1904); [Sage conda documentation](https://doc.sagemath.org/html/en/installation/conda.html); Esgin et al., [IACR ePrint 2018/773](https://eprint.iacr.org/2018/773.pdf), Section 2.2.

### Phase 3, Step 4 — Sampling and Lattice Commitment

This implementation follows the Section 2.2 algorithms in the reference
paper. It reuses the existing `arithmetic::Polynomial` and `arithmetic::Matrix`
types; it does not introduce a second polynomial or matrix representation.

#### Sampling implementation

`lattice_lrs::sampling::RandomSource` is the injectable byte-source interface.
The production `SystemRandomSource` obtains bytes from the operating system
(`SecRandomCopyBytes` on macOS and `getrandom` on Linux) and throws on failure; the
samplers do not fall back to `std::rand` or another non-cryptographic source.
The production `CKeygen(parameters)` and `Commit(key,message)` overloads create
this OS source internally. Overloads accepting `RandomSource&` exist for test
injection; the deterministic implementation exists only in the unit-test
source.

Uniform sampling in `Z_q` draws enough random bits for `[0,q-1]`, masks excess
bits, and rejects values `>=q`. This rejection method avoids modulo bias and
works with arbitrary-precision and composite moduli. The generic arithmetic
and sampler accept any `q>1`; Esgin-specific `commitment::Parameters` further
requires odd `q`, as specified in Section 2.1. No primality or inversion is
used. Bounded coefficients are sampled uniformly from `{-B,...,B}`; for
`B=1`, this is uniform ternary sampling. Uniform and bounded coefficient
sampling are available for polynomials, polynomial vectors, and polynomial
matrices; each coefficient is sampled independently.

#### Commitment algorithms and shapes

For the project baseline, `n=5`, `m=13`, `v=16`, `d=256`, `B=1`, and q is
odd, configurable, and provisional. The generic API allows toy dimensions and
moduli for tests. The implemented equations are:

1. **CKeygen:** sample `G'_r` uniformly in `R_q^(n x (m-n))` and `G_m`
   uniformly in `R_q^(n x v)`; set `G_r=[I_n | G'_r]` and
   `G=[G_r | G_m]`. Baseline shapes are `5x8`, `5x16`, `5x13`, and `5x29`.
2. **Commit:** sample `r <- S_B^m`, with each of the `m*d` coefficients
   independently uniform in `[-B,B]`; compute `C=G_r r + G_m mu` for
   `mu in R_q^v`. The output includes C and r.
3. **Open:** for caller-supplied `y in R_q`, check
   `G_r r' + G_m mu' = y*C` and
   `||(r',mu')||_2 <= T_com`. The relaxation factor is explicit; it is not
   replaced by one. The norm is the Euclidean norm over the centered integer
   coefficients of all polynomials, consistent with Section 2.1. Polynomial
   storage remains canonical `[0,q-1]`; centered coefficients are computed
   only for norm evaluation.

To avoid floating-point comparisons, the API requires the exact positive
rational value `T_com^2 = numerator/denominator`; it compares the exact
integer squared norm by cross multiplication. Section 2.2 defines `T_com` as
a positive real bound but does not give a standalone concrete value for this
step. The ring-signature parameter selection later derives a binding threshold
from the M-SIS analysis. Therefore a production `T_com` is still a required
parameter decision, not selected here. Tests use explicit toy bounds only.

#### Files and tests

- `cpp_backend/include/lattice_lrs/sampling/random_source.hpp` and
  `cpp_backend/src/sampling/random_source.cpp`: OS entropy interface/backend.
- `cpp_backend/include/lattice_lrs/sampling/sampler.hpp` and
  `cpp_backend/src/sampling/sampler.cpp`: unbiased uniform and bounded
  coefficient, polynomial, vector, and matrix sampling.
- `cpp_backend/include/lattice_lrs/commitment/commitment.hpp` and
  `cpp_backend/src/commitment/commitment.cpp`: validated parameter/key types,
  `CKeygen`, `Commit`, and relaxed `Open`.
- `tests/test_sampling_commitment.cpp`: deterministic rejection-sampling and
  ternary cases; dimensions; CKeygen identity/block shapes; valid and relaxed
  openings; changed message/randomness and wrong-y rejection; norm-bound
  rejection; composite odd q; degree-256 operation; and entropy-failure
  propagation.

`CKeygen` and commitment tests establish functional equations and dimension
handling only. They do not establish hiding, binding, key distribution quality,
or any security property. Binary proofs, Gaussian sampling, Fiat–Shamir,
ring-signature algorithms, OTS, linkability, and application logic remain
outside this step.

Paper locations: Section 2.1 defines odd-q centered representatives and the
Euclidean vector/polynomial norms (printed p. 5); Section 2.2 gives CKeygen,
Commit, Open and Lemma 1 (printed pp. 6–7). See the [full paper](https://eprint.iacr.org/2018/773.pdf).

### Phase 3, Step 5 — Binary Proof (Protocol 1)

The component is Esgin et al.'s Protocol 1, Section 4, “Σ-protocol for
Commitment to a Sequence of Bits” (printed pp. 14–15), together with its
relations in Definition 4. The statement is `(ck,B)`. The witness is the
`v=k*beta`-entry sequence of constant ring elements `b_{j,i}` and an
`m`-polynomial randomness vector `r`, where every `b_{j,i}` is 0 or 1, each
row has Hamming weight one, `B=Com_ck(b;r)`, and
`||r||² <= B_bound²*m*d` (the coefficient-bound symbol is called `B` in the
paper and is distinct from the public commitment named `B`).

Protocol 1's first message samples `a_{j,i}` for `i>=1` from
`D^d_{phi1*sqrt(k)}`, sets `a_{j,0}=-sum_{i=1}^{beta-1}a_{j,i}`, samples
`r_c` coefficientwise uniformly from `[-B_bound,B_bound]`, and samples
`r_a,r_d` from `D^{md}_{phi2*B_bound*sqrt(2*m*d)}`. It computes:

```text
A = Com_ck((a_{j,i}); r_a)
C = Com_ck((a_{j,i}(1-2b_{j,i})); r_c)
D = Com_ck((-a_{j,i}^2); r_d)
(c_a,d_a) = aCom(A,C,D)
```

The verifier challenge is `x=X^omega` for uniformly selected
`omega in {0,...,2d-1}`. The response is `f_{j,i}=x*b_{j,i}+a_{j,i}` for
`i>=1`, `z_b=x*r+r_a`, and `z_c=x*r_c+r_d`. The verifier reconstructs
`f_{j,0}=x-sum_{i=1}^{beta-1}f_{j,i}` and
`g_{j,i}=f_{j,i}(x-f_{j,i})`, then checks:

```text
(c_a,d_a) == aCom(A,C,D)
||f_{j,i}|| <= 5*phi1*sqrt(d*k)                 for i != 0
||f_{j,0}|| <= 5*phi1*sqrt(d*k*(beta-1))       for every j
||z_b||, ||z_c|| <= 2*sqrt(2)*phi2*B_bound*m*d
x*B + A == Com_ck(f; z_b)
x*C + D == Com_ck(g; z_c)
```

Both rejection steps are part of the prover algorithm, not verifier checks:
`Rej(f_1,x*b_1,phi1,sqrt(k))` and
`Rej((z_b,z_c),x*(r,r_c),phi2,B_bound*sqrt(2*m*d))`. The paper defines
`Rej` in Algorithm 1, Section 2.3: with `sigma=phi*K` and
`mu(phi)=exp(1/phi+1/(2*phi^2))`, it accepts using the stated exponential
probability and a uniform real `u in [0,1)`. The theorem assumes
`d>=7`, `m*d>=86`, and
`q>(10*phi1*d*sqrt(k*d*(beta-1))+2)^2`; it gives 3-special soundness and
soundness error `1/d` under its commitment and M-LWE assumptions. Section 4
does not itself instantiate a concrete auxiliary commitment implementation:
`aCom` is assumed hiding and binding (or modeled as a random oracle). Also,
the project has no discrete-Gaussian or exact Bernoulli-exponential sampler.
The proof module will expose explicit provider interfaces for these primitives
and will not fake them using a normal distribution, floating-point exponential,
or an unhashed test commitment. Until production providers are supplied and
reviewed, tests can validate only the protocol equations and bounds, not
zero-knowledge or soundness.

For the project baseline, `k=2`, `beta=8`, `v=16`, `d=256`, `m=13`, and
`B_bound=1`; `phi1=phi2=4` are the previously documented provisional protocol
settings. The exact production q and commitment binding bound remain
unfinalized. Parameters and all verifier norm comparisons will be represented
with exact rational squared bounds; no field inverse is used. Subsequent
implementation uses the already existing polynomial, matrix, commitment, and
OS-random-source code. No Fiat–Shamir transform or one-out-of-many logic is
part of this step.

#### Implemented protocol core

`cpp_backend/src/proofs/binary_proof.cpp` now implements Protocol 1's prover
first-message generation, challenge response, both rejection decisions through
an injected Bernoulli-exponential provider, verification equations and norm
checks, plus monomial challenge construction/sampling. The public API is in
`cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp`. Prover state retains
integer lifts of sampled Gaussian values so rejection-sampling inner products
are not computed after reduction modulo `q`.

`BinaryProofParameters::validate` enforces Protocol 1's dimension conditions,
the exact strict modulus inequality, the `v=k*beta` shape, and a commitment
norm bound at least as large as Theorem 1's calculated `T` bound. These are
arithmetic preconditions only; validation does not estimate M-LWE or M-SIS
hardness or establish that the supplied commitment key is binding/hiding.

The sampler source currently provides OS-backed bytes, unbiased uniform values,
and bounded values. It does **not** implement Esgin's discrete Gaussian or
exact Bernoulli-exponential distribution. The proof core therefore requires
provider implementations supplied by its caller; no production provider is
included. `aCom` is also injected because the paper assumes a hiding/binding
auxiliary commitment (or random oracle), but the project has not selected a
concrete construction or transcript encoding. This is an injectable protocol
core, not a production-ready signing implementation.

`tests/test_binary_proof.cpp` exercises challenge mapping, an honest algebraic
transcript with deterministic **test-only** Gaussian/Bernoulli/auxiliary
providers, both rejection stages and abort handling, single-use prover state,
tampered responses/commitments, invalid challenges, malformed witnesses, and
the q and commitment-bound checks. The fixture providers do not sample the
specified distributions; their acceptance result cannot support a
zero-knowledge or security claim. The small test modulus is a non-production
composite odd modulus chosen to satisfy Protocol 1's arithmetic bound. The
production modulus and security estimate remain unresolved.

#### Files and verification

- Added `cpp_backend/src/proofs/binary_proof.cpp` and
  `tests/test_binary_proof.cpp`.
- Updated `cpp_backend/CMakeLists.txt` and the root `CMakeLists.txt` to build
  and register the proof core/test.
- Updated the proof header to retain integer lifts required by rejection
  sampling.

Build: `cmake --build Lattice_LRS/build -j 4` completed successfully.
CTest: **7/7 passed**, including the six pre-existing tests and
`binary_proof_test` (reported total duration 5.17 seconds on the final run). This confirms the
tested equations, bounds and API flow for fixture inputs only. It does not
validate the distribution providers, `aCom` security, production parameters,
or the complete Esgin ring signature.

#### Still required before production use

1. Implement and independently review a discrete-Gaussian provider with the
   paper's exact `D_s` mass function and scale convention.
2. Implement and review an exact Bernoulli-exponential provider for Algorithm
   1. Floating-point approximate acceptance and ordinary PRNGs are not
   substitutes.
3. Select/instantiate a hiding and binding `aCom` (or a precise random-oracle
   model) with canonical transcript serialization and domain separation.
4. Finalize the production `q`, commitment bounds and exact Esgin parameter
   profile; independently validate the associated M-LWE/M-SIS estimates.
5. Review integer-lift and centered-residue semantics against the proof
   distribution and serialized response encoding, including rare Gaussian
   tails that cross the centered interval.
6. Implement Protocol 2, the Esgin Fiat–Shamir ring-signature layer and its
   tests. WCM remains deferred due to the documented paper inconsistencies.
