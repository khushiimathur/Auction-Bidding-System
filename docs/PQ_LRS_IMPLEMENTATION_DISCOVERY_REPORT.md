# PQ-LRS Implementation Discovery Report

**Scope:** compare inspected third-party code against Esgin et al. (ePrint 2018/773), Wang–Chen–Ma (ePrint 2019/371), and the intended Dilithium one-time-signature component. This is a source-compatibility audit, not a security evaluation.

**Outcome:** no compatible external cryptographic implementation was imported. The source map is in [`PQ_LRS_COMPONENT_REUSE_MAP.md`](PQ_LRS_COMPONENT_REUSE_MAP.md). Local code and upstream Dilithium files remain untouched.

## Target construction and compatibility test

The target is a composition: Esgin's lattice ring signature, transformed and augmented with one-time signatures/linkability as in Wang–Chen–Ma (WCM). A component is reusable only if its relation, distributions, transcript encoding, parameter assumptions and verification equations match the required component. Sharing a ring, NTT, hash, or “linkable ring signature” label is insufficient.

The WCM paper identifies Esgin as its base scheme and Dilithium as the OTS family. It describes shifting public keys by a hash of an OTS verification key and comparing the OTS verification key as a link tag. However, the paper’s concrete signing and verification text appears inconsistent about `H` versus `H'` and about whether the OTS authenticates the OTS secret-key identifier or the OTS public key. This must be reconciled against the authors’ intended equations before implementing an adapter. See the project’s existing research/design documents for the cited page/equation review.

## Newly inspected repositories

### `wang-0218/ring-signature`

The inspected `main` snapshot is commit `05bef95d8db96c0aebc68a680d9a5884ae2c0235`; the repository tracks an archive, `MyNtruSignature.zip`. The associated 2022 paper is Ye et al., “Efficient Linkable Ring Signature Scheme over NTRU Lattice with Unconditional Anonymity” ([DOI](https://doi.org/10.1155/2022/8431874)); the paper’s data-availability statement points to this repository. This is a distinct NTRU construction, not Esgin or WCM.

The archive contains Python modules such as `NtruGroupSignature.py`, `NtruVrfy.py`, `KegGen.py`, `Polynomial.py`, and `test.py`. Observed entry points include `NtruGrouSi`, `GroupSVrfy`, `NTRUEncKegGen`, `NTRUSinKegGen`, and `NtruGroupGen`. The signer does not use its `gn_sk` argument or an explicit signer index to form a single-member witness. Verification comparisons are commented out, and `GroupSVrfy` does not return an acceptance result. Randomness uses Python/NumPy non-cryptographic APIs; hashing uses Python textual representations rather than a canonical byte encoding. The included `test.py` is not a signature correctness suite. No archive-root license or dependency manifest was found.

**Decision:** do not reuse its cryptographic code. Its polynomial helpers are only an engineering reference and are superseded by the project’s local NTL implementation. The claimed scheme/code correspondence is not demonstrated by a functioning signing-and-verification test.

### `Sobieg/L2RS`

The inspected repository is archived and read-only; snapshot `main` commit is `a5c5a99036d1c802c9767850aa51ca6f4b5e17aa`. Its fetched history contains six commits, from `Initial commit` through `Little update.`. No release, README citation or license file was found in the checkout. Historical L2RS literature describes a different BLISS-related linkable scheme, but this repository does not pin its code to a particular paper revision; that mapping remains unverified.

Relevant files include `L2RS.c/.h`, `poly.c/.h`, `matrix.c/.h`, `ntt.c/.h`, `sampler.c/.h`, `entropy.c/.h`, `sha3.c/.h`, `params.h`, and `main.c`. `L2RS.h` declares `L2RS_sigVer`, but no definition was found. `L2RS_sigGen` is incomplete/pseudocode-heavy and explicitly leaves rejection sampling for later. `main.c` comments out verification and invokes the signer with a null sampler. `params.h` contains a small unrelated profile (`RINGCT_N=4`, `RINGCT_M=2`, `RINGCT_Q=1767374849`, `RINGCT_LAM=100`, `RINGCT_SIGMA=283754`).

An out-of-tree CMake build completed with Apple Clang 21, producing warnings including signed-overflow concerns in `poly.c`; executing the demo exited with status 139 (segmentation fault). There is no CTest correctness coverage. Its polynomial, matrix, NTT and Gaussian sampler code is engineering material only; distributions, parameter profile, representation and proof relation do not match the current Esgin modules. No source is copied.

## Other audited candidates

The detailed per-source module matrix, paths, APIs, licenses and local migration decisions are in [`PQ_LRS_COMPONENT_REUSE_MAP.md`](PQ_LRS_COMPONENT_REUSE_MAP.md). The overall comparison is:

| Candidate | What it provides | Relation to target | Reuse outcome |
|---|---|---|---|
| Calamari/Falafl | Complete lattice-action/isogeny ring signatures | Different OR/group-action proof and tag relation; no WCM OTS composition | Separate-scheme research reference only; license review needed before copying |
| Raptor | NTRU/Falcon linkable ring-signature prototype | Different NTRU/Falcon relation and linkability wrapper | Do not transplant components; GPL-3.0 and serialization concerns |
| LoTRS | Threshold/structured lattice ring signature with Esgin-inspired selection hiding | Its implemented selection relation and transcripts are not Esgin’s exact protocol; no WCM tag | Strong proof-flow/test engineering reference only |
| ESORICS 2024 PQ LRS | Rust hash/STARK-based signature-of-knowledge framework | Not lattice/M-LWE and not WCM | Separate-scheme reference only |
| DualRing | Demonstration lattice ring signature | Different M-LWE/M-SIS relation; no linkability | Reference only |
| LLRing | Classical DL/pairing linkable signatures | Not post-quantum | Not reusable cryptographically |
| MatRiCT / Lattice RingCT | RingCT commitments and proof code | Different statements, parameters and protocols; incomplete/toy concerns | Engineering reference only |
| Lantern / ring-zk / lattice ZK toolkits | Lattice proof/arithmetic components | Different proof relations and transcripts | Reference only; no drop-in proof component identified |
| Geometry Labs | Generic one-time-signature examples | Not the required Dilithium/WCM interface | API/testing reference only |
| Hcash RingCT | README-only checkout | Source unavailable in inspected tree | Not verified |

## Existing project modules

The local arithmetic uses NTL for configurable `Z_q[X]/(X^d+1)` polynomials and polynomial matrices. Sampling already has an OS-backed random source, unbiased uniform sampling and bounded coefficient sampling. The Esgin-inspired commitment module exposes `CKeygen`, `Com`, `Commit`, and `Open`, including its relaxed opening relation. These modules are the best baseline to retain; their passing tests establish only functional behavior for tested cases, not cryptographic security.

Esgin Protocol 1's prover/verifier core is now present in `cpp_backend/src/proofs/binary_proof.cpp`, with `binary_proof_test` exercising its equations using test-only provider fixtures. Production Gaussian, Bernoulli-exponential and auxiliary-commitment providers remain absent. No complete Esgin one-out-of-many proof, Fiat–Shamir ring signature, WCM transform/tag API, or end-to-end LRS implementation was identified. Dilithium Round 2 and Round 3 remain isolated upstream source/test integrations; no WCM-specific adapter is present. The exact historical Dilithium variant, message encoding and paper’s signed tuple still require resolution.

## Build and test observations

Before Protocol 1 was added, the existing project CTest suite reported **6/6 passed**: `cpp_build_smoke`, `ntl_gmp_integration`, `polynomial_matrix_arithmetic_test`, `sampling_commitment_test`, `dilithium_round2_test`, and `dilithium_round3_test` (3.14 seconds). The current suite reports **7/7 passed**, adding `binary_proof_test` (final run 5.17 seconds total). These are functional arithmetic, dependency, sampling/commitment, fixture proof-equation, and standalone Dilithium checks. They do not test proof soundness/zero knowledge under production distributions, anonymity, linkability, chosen-message security, or the complete LRS composition.

L2RS results are as recorded above: build succeeded with warnings; demo crashed. The NTRU archive was inspected statically and has no meaningful end-to-end signature test. Other repositories’ dependency/build limitations are detailed in the component map and earlier project audit documents.

## Recommendation

Retain the local arithmetic, sampling and commitment baseline. Use LoTRS, Falafl and other repositories only to inform engineering choices such as transcript testing, codecs, and test organization. Do not import their proof, commitment, signing, or tag equations into the target. Implement missing Esgin and WCM components in the existing local interfaces only after the unresolved paper equations, parameter/security review, and Dilithium compatibility details have been settled. A successful unit test or prototype run must not be represented as a proof of security.

## References

- Esgin et al., [ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [ePrint 2019/371](https://eprint.iacr.org/2019/371).
- Ye et al., [DOI 10.1155/2022/8431874](https://doi.org/10.1155/2022/8431874).
- Project-local detailed audit: [`PQ_LRS_COMPONENT_REUSE_MAP.md`](PQ_LRS_COMPONENT_REUSE_MAP.md).
