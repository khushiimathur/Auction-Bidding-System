# PQ-LRS Deviations and Security Notes

## Protocol fidelity

No third-party cryptographic implementation was integrated. The audited candidates implement different constructions (including NTRU/Falcon, group-action OR proofs, threshold/structured ring signatures, and STARK-based schemes) or are incomplete. Borrowing their signing or verification equations would change the target from Esgin + WCM. Their arithmetic or proof code is not treated as equivalent merely because it uses lattices or ring signatures.

The current local arithmetic, sampler and commitment modules are experimental foundations. Their unit tests establish behavior on tested inputs; they do not establish hiding, binding, zero knowledge, soundness, anonymity, unforgeability, or linkability.

## Unresolved construction details

- **Section 6.1 rejection parameter:** use literal `phi1=phi2=22`. Earlier
  notes misread 22 as `2^2=4`; `mu(22)^2≈2.983` versus `mu(4)^2≈429.448`
  matches the paper's stated acceptance rate above `1/3` and about three
  expected RSign iterations.
- **WCM transform:** the paper’s concrete text uses `H'` in key transformation/signing and appears to use `H` in verification. The codomains/types and intended equality must be established; no silent correction is made here.
- **WCM OTS message:** signing text and verification text appear to name different OTS-authenticated values (`ovk` versus the OTS public key). Do not build a wrapper until resolved.
- **Link scope:** comparing the same `ovk` gives linkability wherever that key is reused. Scoping duplicate detection to an auction/context is not directly supplied by the paper’s basic equality tag and may require a new, analyzed construction.
- **Dilithium version/API:** local Round 2 and Round 3 test targets do not by themselves establish which historical “very high” Dilithium source/API the WCM experiment used, nor compatibility of its serialization and OTS message tuple.
- **Esgin parameters:** code-selected exact moduli now exist in named profiles, but they are not security-approved. The paper's rounded `log₂(q)` and functional tests do not establish the concrete M-SIS/M-LWE security level. Use exact parameter and estimator assumptions before claiming a level.
- **Proof implementation:** Protocol 1, Protocol 2, and RSign/RVerify batch orchestration are present. Production transcript/hash, Gaussian/rejection, and auxiliary-commitment providers remain unresolved; the presence of exact sampler primitives does not establish that the required Section 6 distributions are implemented.

## Parameter profile implementation and deviations

The code defines profiles for \(N=64,256,1024,4096\) using the corresponding
Table 3 dimensions and repetition counts, with \(B=1\),
\(\phi_1=\phi_2=22\), and \(\lambda=128\). Selected exact primes are:

| \(N\) | Paper \(\log_2(q)\) | Code-selected \(q\) |
|---:|---:|---:|
| 64 | 50 | 1125899906826241 |
| 256 | 53 | 9007199254740481 |
| 1024 | 46 | 119569584450049 |
| 4096 | 47 | 140737488355201 |

These are implementation choices because Table 3 gives only rounded
\(\log_2(q)\). The implementation additionally requires prime
\(q\equiv1\pmod{2d}\), while the paper requires odd \(q\) and does not require
this congruence. For these primes the polynomial \(X^d+1\) splits over
\(\mathbb F_q\); this changes the quotient-ring structure and needs security
review. The \(N=1024\) choice has \(\log_2(q)\approx46.765\), above the
paper's rounded 46, to meet the implemented constraints.

Profile validation uses exact integer arithmetic for the repeated Assumption
1 inequality and the q-side of Eq. (11), with ceiling-square-root bounds for
\(T_1\) and the \(T'\) term using \(B'_{d,k}\le d^k\). It does not evaluate
Eq. (11)'s lattice-reduction member, check \(\delta\le1.0045\), or re-estimate
M-SIS/M-LWE hardness. These profiles are not cryptographic security
validations. `TestOnlySetupParameters` and `*ForTesting` APIs mark the
pre-existing toy fixtures; production keygen/sign/verify entry points reject
those fixtures.

## Implemented `aCom` construction (Task 2)

The existing provider inputs specify the complete protocol-local tuples:
Protocol 1 commits to `(A,C,D)`; Protocol 2 commits to `(A,B,C,D,E)`, where
`E` is an ordered list of polynomial vectors. No commitment-key, message, ring,
or response field is added to `aCom`; those belong to other protocol
interfaces/transcripts.

The implementation is a versioned salted hash commitment:

1. Encode a distinct fixed domain label (`PQ-LRS/aCom/Protocol1/v1` or
   `PQ-LRS/aCom/Protocol2/v1`), then each ordered field with an explicit field
   tag (`0x01..0x03` for Protocol 1's `A,C,D`; `0x01..0x05` for Protocol 2's
   `A,B,C,D,E`) and 64-bit big-endian length/count prefixes. The version is
   also encoded as a 64-bit big-endian integer `1`. Encode every polynomial's
   degree, modulus, coefficient count, and canonical signed decimal ASCII
   coefficients; encode nested vectors with their outer and inner counts.
2. Obtain a fresh 32-byte opening `d_a` from the passed `RandomSource`. A
   production signer must supply the existing OS-backed `SystemRandomSource`;
   entropy errors must propagate.
3. Compute a 32-byte digest as
   `SHAKE256(encoding || 0xf0 || length(d_a) || d_a, 32)`.
   Verification requires a 32-byte digest and opening, recomputes the digest
   for the supplied protocol tuple, and compares all digest bytes without
   content-dependent early exit.

The SHAKE implementation is the vendored Round 3 `fips202.c`, whose exported
symbols use the `pqcrystals_dilithium_fips202_ref_*` namespace. CMake builds
one shared `lattice_lrs_fips202` target used by both the backend and optional
Round 3 reference tests, rather than compiling the same source into both
libraries. Round 2 uses separate unprefixed symbols. The FIPS 202 API has no
hash-error return value; allocation failures and `RandomSource` exceptions
propagate, and there is no fallback path.

This salted hash is not a perfectly hiding commitment. Its hiding argument is
computational and modeled in the random-oracle model with an unpredictable,
uniform 256-bit opening. Binding relies on collision resistance of the
256-bit-output hash (at most about 128-bit generic collision strength). These
are construction assumptions, not a proof that SHAKE256 instantiates every
assumption made by Esgin et al. The paper's abstraction permits an assumed
hiding/binding `aCom` or a random-oracle treatment; this concrete salted-hash
choice is an implementation instantiation and therefore a deviation from the
paper's unspecified concrete choice. Even if this provider is implemented
correctly, it does not establish the full Esgin proof: the transcript/hash,
Section 6 distributions and rejection, parameter hardness, and protocol
composition remain separate obligations.

## Security-sensitive integration findings

- `wang-0218/ring-signature` contains non-cryptographic randomness and non-canonical textual hashing; verification checks are commented out. It is not suitable for production or partial cryptographic reuse.
- `Sobieg/L2RS` is archived with no located license; signing is incomplete, verification is declaration-only, the demo crashes, and its profile is unrelated. Do not copy its source absent both a mathematical match and licensing clarification.
- Raptor is GPL-3.0 and a separate NTRU/Falcon construction; the inspected serialization offsets need maintainer explanation. It is not a WCM OTS/tag adapter.
- Calamari/Falafl and several other candidates have distinct relations and/or licensing and audit constraints. See the component map for each repository’s observed license and caveats.
- Neither upstream Dilithium source should be modified or treated as implementing ring membership, Esgin proofs, or WCM linkability. An adapter must keep the upstream implementation intact and use the correct historical variant and exact signed bytes.
- The latest configured full CTest run passed 22/22 tests, including optional Dilithium Round 2/3 tests. This is functional evidence only. It is not a cryptographic security evaluation and does not validate protocol composition.

## Safe status statement

The project has reusable local arithmetic/sampling/commitment groundwork and independently tested Dilithium source trees. It does **not** yet have a complete Esgin ring signature, WCM linkability extension, verified Dilithium OTS adapter, or context-scoped auction link tag. No security claim is made for the combined system.

The tests use deterministic fixture providers for protocol-flow checks. They do not establish that injected production providers have the required distributions, or that the proofs are zero knowledge/sound under the selected profile inputs. The code-selected moduli are not security-final, and lattice estimates remain unresolved.

## References

- Esgin et al., [ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [ePrint 2019/371](https://eprint.iacr.org/2019/371).
- Detailed source map: [`PQ_LRS_COMPONENT_REUSE_MAP.md`](PQ_LRS_COMPONENT_REUSE_MAP.md).
- Discovery results: [`PQ_LRS_IMPLEMENTATION_DISCOVERY_REPORT.md`](PQ_LRS_IMPLEMENTATION_DISCOVERY_REPORT.md).
