# External Post-Quantum Ring Signature Repository Audit

**Scope:** Read-only investigation of four external implementations against the project’s required Esgin et al. ring signature and Wang–Chen–Ma (WCM) linkability transformation. No source from these repositories was copied or integrated. No project cryptographic code, parameters, APIs, or build files were changed.

**Audit checkout location:** `/private/tmp/pqlrs_external_audit/` (outside `Lattice_LRS`). All four shallow checkouts remained clean after inspection and attempted checks.

## Executive summary

None of the four repositories implements the complete required construction: Esgin et al. 2018/773 as the base ring signature, WCM 2019/371 as its linkability extension, and the historical Dilithium one-time signature (OTS) instantiation.

LoTRS is the most useful implementation reference for the next proof work. It contains a complete one-out-of-many selection-proof/signature path, including a binary proof, Fiat–Shamir transcript construction, rejection sampling, canonical encoding, deterministic vectors, and Python/Rust cross-implementation tests. However, LoTRS is a structured **threshold** ring signature with its own two-modulus proof system and parameter profile. Its proof code is not a proven drop-in implementation of the Esgin 2018/773 Section 4–5 algorithms. It has no WCM OTS layer, Dilithium integration, or link tag.

The other repositories are less suitable for implementation reuse:

- **DualRing** is a different M-LWE/M-SIS ring signature based on a dual-ring challenge/response construction. It does not use Esgin’s binary/one-out-of-many proof or WCM linkability.
- **LLRing** implements discrete-log and pairing-based linkable ring signatures. Its prefix tag is useful as a conceptual example of context-scoped tags, but it is not post-quantum and has no Dilithium OTS.
- **Lattice RingCT v2.0** is a NewHope-parameterized RingCT/L2RS codebase. Its documented license is ISC, but the checked-out test runner only activates a commitment-homomorphism test, and its declared `ZKP_OR` function is empty. It is not Esgin or WCM.

**Recommendation:** retain the project’s existing Esgin-specific arithmetic, sampler, and commitment code. Use LoTRS as a mathematical and engineering reference, then map every relevant equation to the selected Esgin paper before writing the project’s binary proof. Do not transplant any of these complete signing schemes. No complete, exact WCM + Dilithium implementation was found.

## Audit method and repository snapshots

The repositories were cloned with `git clone --depth 1` into the temporary directory. Snapshot details:

| Repository | Branch | Checked-out commit | Commit date / subject |
|---|---|---|---|
| DualRing | `master` | `073869bcc9432fb8a5ed4edd733be205a52ded14` | 2022-01-24, `Update README.md` |
| LoTRS | `main` | `5df5658ed62cb0726beb69e15e41869fcc4b4de2` | 2026-11-07, `updated pdf's` |
| LLRing | `main` | `6131edd8292484bc22b03a890368a1f43a98b637` | 2024-07-11, `Update README.md` |
| Lattice RingCT v2.0 | `master` | `8adff2db3a53673759c2fcb96e615cdc71206644` | 2019-02-21, `Update aes_c.c` |

These are shallow checkouts; the available history is not sufficient to identify the last code-changing commit before a documentation-only HEAD commit. Snapshot dates and subjects above are confirmed; earlier activity is not inferred.

The paper sources used for construction comparison are:

- Esgin et al., [“Short Lattice-based One-out-of-Many Proofs and Applications to Ring Signatures,” ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [“Adding Linkability to Ring Signatures with One-Time Signatures,” ePrint 2019/371](https://eprint.iacr.org/2019/371).
- DualRing, [“Generic Construction of Ring Signatures with Efficient Instantiations,” ePrint 2021/1213](https://eprint.iacr.org/2021/1213).
- LoTRS, [“Practical Post-Quantum Structured Threshold Ring Signatures from Lattices,” ePrint 2026/974](https://eprint.iacr.org/2026/974).
- LLRing, [“Logarithmic Linkable Ring Signatures with Transparent Setup,” ePrint 2024/421](https://eprint.iacr.org/2024/421).
- Lattice RingCT v2.0 cites the prior [Lattice RingCT v1.0 construction, ePrint 2018/379](https://eprint.iacr.org/2018/379).

## Comparison table

| Repository | Construction | Lattice-based | Linkable | OTS/Dilithium | One-out-of-many proof | Reuse potential |
|---|---|---:|---|---|---|---|
| DualRing | Dual-ring canonical identification / challenge-response ring signature | Yes, M-LWE/M-SIS instantiation | No | No | No | **REFERENCE ONLY** for a distinct lattice ring-signature design |
| LoTRS | Structured threshold ring signature: lattice multi-signature plus selection-hiding proof | Yes | No WCM-style tag or link operation | No | Yes, complete integrated binary/selection-proof path | **ADAPTABLE** proof and testing techniques; not a drop-in Esgin proof |
| LLRing | LLRing-DL (discrete log) and LLRing-P (pairings) | No | Yes; prefix-scoped tag proof | No | Uses Bulletproofs/Dory-style inner-product proofs, not Esgin’s lattice proof | **REFERENCE ONLY** for tag scoping and protocol testing ideas |
| Lattice RingCT v2.0 | RingCT/L2RS derived from the NewHope-era ring construction | Yes, NewHope/Ring-SIS family | Paper claims one-time linkable ring signature; no separate tag-link test found in default harness | No | `ZKP_OR` is declared but empty; no completed Esgin proof | **REFERENCE ONLY**; application-specific and implementation has incomplete paths |

## Repository-by-repository findings

### 1. DualRing

#### Quality, dependencies, build, tests, and license

- **Language:** Python (`lattice.py`, `ecc.py`).
- **License:** MIT (`LICENSE`, copyright 2020). Retain the notice if code is ever copied; this audit copied none.
- **Dependencies visible in source:** NumPy, SciPy, SymPy, and PyCryptodome. There is no requirements file or reproducible build/test command in the README.
- **Source completeness:** the repository consists of the two Python scripts, README, and license. `lattice.py` runs a small test/benchmark at module execution time rather than exposing a separately packaged library or test suite.
- **Test scope:** it generates keys for ring sizes 2 and 4, signs one message, and verifies the result. It does not test tampering, malformed inputs, linkability, vectors, or protocol interoperability.
- **Activity:** the cloned HEAD changes only the README; the shallow snapshot does not reveal the previous code-change date.

#### Construction and source mapping

The paper describes DualRing as a generic ring signature made from a canonical identification scheme. Its lattice instantiation is M-LWE/M-SIS based, with a dual-ring challenge/response structure; it is explicitly a different approach from ring signatures based on a one-out-of-many proof. The lattice source exposes:

- `lattice.py:RSetup(m,n,degree)`: creates a matrix `G` with identity/zero blocks and sampled polynomial entries.
- `lattice.py:RkeyGen(m,n,degree,G)`: samples a ternary secret and computes the public key as a matrix-vector product.
- `lattice.py:RSign(message,pk_list,position,sk,G,time_restart)`: samples a response mask and non-signer challenge polynomials, hashes message/ring/commitment data with SHA-256, constructs the signer challenge, and restarts if response coefficients exceed its bound.
- `lattice.py:RVerify(...)`: reconstructs the transcript from the challenges and response and checks the hash-derived challenge relation.
- Arithmetic helpers include `G_mul`, `x_pk_mul`, `random_poly`, `random_special_poly`, and `z_check_row`.

The script uses polynomial arithmetic modulo `Q=33564673` with `DEGREE=128`, and a small test configuration `N=7`, `M=15`. Challenges and secret coefficients use ternary representations. This does not match the project’s degree-256, approximately 50-bit configurable modulus or Esgin commitment dimensions. The code’s hash inputs also include Python-rendered NumPy arrays and `ndarray.tostring()`, rather than a specified canonical wire encoding.

#### Construction match and reusable pieces

- **Esgin:** no Esgin commitment `Com_ck(μ;r)`, no binary proof, and no Section 5 one-out-of-many proof. A matrix-vector commitment-like transcript term is not the Esgin lattice commitment scheme.
- **WCM:** no link tag, OTS, Dilithium, transformed ring-key operation, or WCM verification procedure.
- **M-LWE/M-SIS and Fiat–Shamir:** the paper’s lattice instantiation uses these assumptions and the code hashes a transcript into challenges, but this is DualRing’s identification-based relation, not the Esgin relation.
- **Rejection:** the code restarts on a response norm bound. That is a distinct abort/restart check, not a drop-in implementation of the Esgin proof’s rejection-sampling procedure.
- **Classification:** **REFERENCE ONLY** for its high-level lattice ring-signature structure. Its polynomial code is not suitable for direct use with the project’s exact ring and parameter requirements.

#### Build/test result

There is no documented test command. Running `PYTHONDONTWRITEBYTECODE=1 python3 .../dualring/lattice.py` from a separate temporary working directory failed before execution with `ModuleNotFoundError: No module named 'Crypto'` (PyCryptodome). No dependency was installed. The source was not modified.

### 2. LoTRS

#### Quality, dependencies, build, tests, and license

- **Languages:** Python reference implementation, Rust performance implementation, and SageMath estimation scripts.
- **License:** top-level MIT license; Rust crate declares `MIT OR Apache-2.0`.
- **Dependencies/build:** Python 3.10+ with NumPy, PyCryptodome, and mpmath; Rust/Cargo and a C linker; SageMath for the full checks. Build and check commands are documented in the repository README and Makefiles.
- **Source completeness:** unusually complete research artifact. It includes parameter validation, signing/verification, ring arithmetic, samplers, codecs, deterministic vectors, Python/Rust interop, unit tests, benchmarks, and estimator material.
- **Test coverage documented by the repository:** Python tests for arithmetic, sampling, parameters, protocol, codec, `wtilde`, and end-to-end signing; Rust unit and interop tests compare complete objects/signatures byte-for-byte and include tampering/malformed-input cases. The README says `make check-full` runs 142 Python, 65 Rust, and five Sage tests; these counts are repository claims, not results of this audit.
- **Activity:** snapshot HEAD dated 2026-11-07 updates the paper PDFs. Because the clone is shallow, that date is not treated as the latest source-code change.

#### Construction and source mapping

LoTRS is a **structured threshold ring signature**: a two-round lattice multi-signature proves the participating rows signed, while a one-out-of-many selection proof hides the chosen column. It is not a WCM-style linkable ring signature and has no one-time verification key/tag in its public signature API.

Important implementation locations:

- Python `lotrs-py/lotrs.py`: `LoTRS.setup`, `keygen`, `kagg`, `sign1`, `sign2`, `sagg`, `sign`, `verify`, and `_sign_bin`.
- Rust `lotrs-rs/src/lotrs.rs`: corresponding setup/keygen/aggregation/sign/verify routines; `sign_bin` implements the binary proof part and `verify_impl` checks/reconstructs it.
- `lotrs-py/ring.py` / `lotrs-rs/src/ring.rs`: polynomial ring arithmetic.
- `lotrs-py/sample.py` / `lotrs-rs/src/sample.rs`: SHAKE-derived uniform/short/Gaussian samplers and `rej`/`rej_op` rejection procedures.
- `lotrs-py/codec.py` / `lotrs-rs/src/codec.rs`: canonical public parameter, key, and signature encoding.
- `lotrs-py/vectors.json`, `lotrs-rs/tests/interop.rs`, and test files: deterministic fixtures and interop checks.

The paper-to-code map in `lotrs-rs/README.md` maps its `Sign_bin` and `Vf` figures to those routines. Thus the artifact contains a complete, testable **related binary/selection proof path**. It is the best available proof implementation to study. It is not established by this audit as the exact algorithms from Esgin 2018/773 Sections 4–5; it is integrated into LoTRS’s later construction and parameter system, and must be equation-mapped before any adaptation.

#### Parameter and construction compatibility

The shipped production manifest uses `d=128`, `q=8796093022141` (`2^43−67`), `q_hat=34359737917` (`2^35−451`), `beta=100`, `T=50`, `kappa=1`, and LoTRS-specific dimensions and bounds. Its Python parameter object marks both moduli prime. This differs from the project’s target `d=256`, configurable odd q, Esgin commitment `M-LWE_{8,5,q,1}`, and ring size 64 experiment. LoTRS uses a second modulus for its binary proof, table-structured threshold signing, and its own distributions, bit dropping, transcript serialization, and rejection rules.

- **Esgin:** the artifact has a full one-out-of-many selection proof with binary-proof machinery, but exact equivalence to the target paper’s proof relations and concrete parameters is **not verified**. It is **ADAPTABLE as a study/reference implementation**, not exact-match code.
- **WCM and Dilithium:** no OTS keypair, WCM transformed public-key ring, WCM-specified OTS message, final `(base signature, OTS signature, ovk)` structure, or link operation was found.
- **Serialization/hash:** its explicit codec and Python/Rust vectors are strong engineering references, but the encodings and hash transcript belong to LoTRS and are not compatible with WCM or Esgin by default.
- **Sampling:** Gaussian and rejection-sampling implementations are useful to study for later proof work. The project must still use the target paper’s distributions and prove equivalent bounds; these are not substitutes for the current OS-random sampling abstraction.

#### Build/test result

The documented `make check` was attempted with bytecode output disabled and the Rust target directed to `/private/tmp`. It stopped in `lotrs-py/check_parameters.py` because `Crypto.Hash.SHAKE128` could not be imported (`ModuleNotFoundError: No module named 'Crypto'`). The Python test suite and Cargo tests were therefore not reached. This environment also has no `cargo` or `rustc`, and SageMath is not installed. No dependencies were installed and no source was modified.

### 3. LLRing

#### Quality, dependencies, build, tests, and license

- **Language:** Java.
- **License:** GNU GPL version 3 (`LICENSE`). Integrating GPL code would require reviewing compatibility with the project’s distribution/license obligations.
- **Dependencies:** JPBC and JNA jars are included under `src/main/resources/jars`; `pom.xml` additionally declares BouncyCastle and JMH. The compile attempt showed the required BouncyCastle `Keccak` classes are not in the bundled jars.
- **Build/test instructions:** README tells the user to compile `src/main/java/RingSignature/Test.java`, but that file does not exist in the checkout. The actual `src/main/java/Test.java` is a small `IntUtils`/`HashUtils` demo, not a ring-signature test. Ring-specific `main` methods are embedded in scheme/helper classes.
- **Source completeness:** contains LLRing-DL, LLRing-P, Omniring, Bulletproofs, Dory, and tag helper sources. These are research implementations, not production-hardened code.
- **Activity:** latest shallow snapshot updates README on 2024-07-11; earlier source activity cannot be inferred from this shallow clone.

#### Construction and source mapping

The LLRing paper explicitly focuses on the discrete-log and pairing settings. Source mapping:

- `RingSignature/LLRingDL.java`: `sign`, `single_multi_verify`; its proof uses `SegregatedBulletproofs`.
- `RingSignature/LLRingP.java`: `sign`, `verify`; its proof uses `Dory_ZK` in pairing groups.
- `RingSignature/Omniring.java`: Omniring-style discrete-log baseline with `sign`, `verify`, and `single_multi_verify`.
- `Utils/TagDL.java`: `tagGen(prefix,sk,r)` and `verify(proof,prefix)`.
- `Utils/TagP.java`: corresponding pairing-based tag generation and verification.

The tag functions derive a deterministic tag from the signer secret and `Hash(prefix)`. Reusing the same key and prefix yields the same tag; a different prefix yields a different tag. This is a useful **conceptual** example of prefix/context scoping. In the inspected LLRing classes, the ring objects initialize `prefix` to the literal `"f"`; application-level auction prefix configuration is not exposed as a constructor parameter. The tag proof is an algebraic discrete-log/pairing proof, not a lattice proof.

- **Esgin:** no Module-LWE/Module-SIS arithmetic, Esgin commitment, binary proof, or one-out-of-many lattice proof. Bulletproofs/Dory inner-product arguments are mathematically different.
- **WCM:** no OTS/Dilithium and no WCM ring-key transform. The prefix tag is not WCM’s `ovk` tag.
- **Classification:** **REFERENCE ONLY** for testing the idea of deterministic context-scoped tags and for high-level link-tag lifecycle discussion. It is not post-quantum and cannot supply PQ-LRS source.

#### Build/test result

An out-of-tree `javac` compile of all Java sources was attempted using the bundled jar directory. It failed with missing `org.bouncycastle.jcajce.provider.digest.Keccak` classes referenced by `Utils/HashUtils.java`. Maven is unavailable in this environment, and no package was downloaded. No ring signature test ran. The README’s cited `RingSignature/Test.java` path is absent; actual `Test.java` only exercises utility hashing/decomposition. The embedded `LLRingDL.main` is a positive sign/verify smoke example, but no observed test checks tampering or cross-signature tag equality.

### 4. Lattice RingCT v2.0

#### Quality, dependencies, build, tests, and license

- **Language/build:** C, distributed as a Visual Studio solution/project targeting Visual Studio toolset v141 and Windows SDK 10.0.17134.0. The checkout includes Windows build artifacts. README does not provide a portable build command.
- **License:** README states copyfree ISC; no standalone root `LICENSE` file was present in the inspected checkout.
- **Dependencies:** includes NewHope-era polynomial/NTT, SHA-2/SHA-3, AES, and `OQS_randombytes` compatibility code.
- **Source completeness:** provides core RingCT/RingCT-MIMO routines and many test helper functions, but several expected features are incomplete in the checked-out source.
- **Activity:** HEAD is dated 2019-02-21 and updates `aes_c.c`; this is the last available snapshot, not proof of current maintenance.

#### Construction and source mapping

The README says this is the MIMO extension of Lattice RingCT and cites the post-quantum one-time linkable ring signature Lattice RingCT v1.0 (2018/379). The code uses NewHope-style parameters `NEWHOPE_N=512` and `NEWHOPE_Q=12289`, not Esgin’s `d=256` and approximately 50-bit configurable q.

Key source paths and functions:

- `Ring2.0/ring.c` / `ring.h`: `LRCT_Setup`, `LRCT_KeyGen`, `LRCT_SigGen`, `LRCT_SigVer`, `LRCT_Spend`, `LRCT_Verify`; MIMO analogues `MIMO_LRCT_Setup`, `MIMO_LRCT_KeyGen`, `MIMO_LRCT_SigGen`, `MIMO_LRCT_SigVer`; polynomial/matrix commitment helpers `LRCT_Com`, `LRCT_nttCom`, and matrix operations.
- `LRCT_SigGen` and `LRCT_SigVer` construct/check a hash-chained ring transcript using SHA-256 and lifted ring values. This is not Esgin’s binary/one-out-of-many protocol or its commitment key structure.
- `ZKP_OR(poly *ck, int bit, int betaLen)` is declared and defined in `ring.c` but its body is empty.
- `LRCT_Spend` constructs the `L` list from prior inputs and an output commitment and calls `LRCT_SigGen`; no standalone `Link` API or explicit cross-signature tag comparison routine was identified.
- `Ring2.0/ring_test.c` contains setup/sign/verify and MIMO test helpers, but `Ring2.0/Ring2.0.c` has those calls commented out. The active `main` calls only `LRCT_ComHom_Test()` and then `system("pause")`.

- **Esgin:** no exact Esgin commitment/proof relation. `LRCT_Com` is a different application commitment helper, and `ZKP_OR` is unimplemented.
- **WCM:** no Dilithium OTS or WCM transformed-key wrapper. “One-time linkable” in the cited RingCT work is a property of that scheme, not evidence that it uses WCM’s generic OTS transformation.
- **Classification:** **REFERENCE ONLY** for old NewHope/RingCT engineering and protocol comparison. The source’s default test executable does not exercise the ring-signature path.

#### Build/test result

No build was attempted: the repository provides a Visual Studio solution/project, the audit host is macOS with Apple Clang and no MSVC/MSBuild, and README has no portable build instructions. Its checked-in Windows executable is not an applicable test result for this environment. The active test entry point’s only enabled test is `LRCT_ComHom_Test`; the signing tests are present as helpers but commented out in `main`. No claim is made that RingCT tests passed.

## Component reuse assessment

| Component idea | Candidate source | Classification | Reason and limits |
|---|---|---|---|
| Complete Esgin 2018/773 ring signature | None | **NOT FOUND** | None of the repositories was shown to implement the target paper’s full construction and parameterization. |
| Complete Esgin binary / one-out-of-many proof code | LoTRS `lotrs-py/lotrs.py:_sign_bin` and verification; Rust `lotrs.rs:sign_bin` / `verify_impl` | **ADAPTABLE / REFERENCE ONLY** | A complete related proof pipeline exists, but it is LoTRS’s proof inside a later two-modulus threshold scheme. Exact equation equivalence to the target Esgin 2018/773 algorithm is unverified. Do an equation-by-equation paper mapping before considering any adaptation. |
| Esgin commitment code | None exact | **NOT FOUND** | Other commitments have different message spaces, matrix layouts, relations, or proof contexts. Reuse the project’s existing Esgin-specific commitment implementation. |
| Rejection sampling and Gaussian techniques | LoTRS `sample.py` / Rust `sample.rs` | **ADAPTABLE** | Useful source for implementation/testing patterns. Distribution parameters, transcript labels, norms, and bounds are LoTRS-specific; do not transfer them without proof. |
| Polynomial ring/NTT implementation | LoTRS ring modules; DualRing `lattice.py`; RingCT NewHope code | **REFERENCE ONLY** | Degrees, moduli, representations, and transform assumptions differ. LoTRS’s CRT-NTT may inform future optimization, but the current NTL arithmetic is more aligned with the configurable target modulus. |
| Canonical serialization and cross-language tests | LoTRS codecs/vectors | **ADAPTABLE** | Good engineering pattern; its format and hashed transcript are not Esgin/WCM formats. |
| Context-scoped deterministic tag | LLRing `TagDL` / `TagP` | **REFERENCE ONLY** | Demonstrates stable tag-by-prefix behavior, but uses discrete-log/pairing groups and proof relations, not the PQ WCM construction. |
| One-time signature implementation | None | **NOT FOUND** | No repository implements the required WCM + Dilithium OTS integration. Raptor is unrelated to this audit’s four candidates; Lattice RingCT’s “one-time linkable” label is not a Dilithium OTS. |

## Compatibility and security concerns

### Esgin construction compatibility

The selected base construction is the Esgin lattice commitment plus its binary and one-out-of-many proofs and ring-signature wrapper. A repository is compatible only if the relevant equations, distributions, parameters, norm bounds, challenge construction, rejection behavior, and serialization all match—not merely because its code uses a polynomial ring or an LWE assumption.

Among these candidates, LoTRS is the only one with a complete implemented one-out-of-many/binary proof path. Its proof is tied to its own threshold protocol, `q`/`q_hat`, Gaussian and rejection parameters, table-index encoding, and transcript. The project cannot call it an exact Esgin submodule without a proof-level comparison to Esgin Sections 2–6.

DualRing also uses M-LWE/M-SIS and Fiat–Shamir, but its signature relation is a distinct canonical-identification protocol. LLRing is classical DL/pairing cryptography. RingCT uses older NewHope-scale parameters and a different challenge-chain construction; its empty `ZKP_OR` rules it out as a complete proof source.

### WCM transformation, Dilithium, and tag lifecycle

WCM’s transformation is distinct from each repository’s native linkability mechanism. Its instantiation uses an OTS keypair; public ring keys are transformed using the OTS verification key; the base ring signature is generated on the transformed ring; the OTS signs the specified base-signature/ring/verification-key tuple; and the final signature carries the base proof, OTS signature, and verification key (`ovk`). None of the four repositories implements that full combination with Dilithium.

Under the WCM construction as described in the paper, reuse of the same `ovk` makes the tag stable, which allows signatures by the same OTS key to be linked. The paper’s discussion describes this as one-time linkability bound to the signer, not a general context-bound tag. The construction does not automatically make tags auction-specific. A project that requires duplicate detection to be scoped to an auction can scope the harness’s tag set per auction, but that alone does not stop public observers from correlating a reused `ovk` across auctions. Cryptographic cross-auction unlinkability would require a carefully specified context/keying adaptation and renewed security analysis; none of these repositories supplies that WCM adaptation.

The current project’s Round 2 and Round 3 Dilithium integrations also have separate APIs and parameter histories. They should be evaluated against the exact historical Dilithium variant named by WCM before choosing the OTS backend. These repositories provide no evidence resolving that version question.

### Test evidence and research status

No candidate was tested successfully in this audit. The exact attempts and environment blockers are recorded above. Passing a demonstration test, if later achieved, would establish basic functionality only; it would not establish protocol equivalence or cryptographic security.

LoTRS’s own README explicitly states that the signer is not constant-time audited and reports estimator costs that do not substantiate 128-bit post-quantum security for its shipped profile. Those are LoTRS-specific caveats, not estimates for the project’s parameters. The other inspected repositories are research code and were not found to provide an audit-backed production security claim.

## Project comparison and migration plan

The project already has an implementation base that matches the selected Esgin architecture more closely than these candidates:

- `cpp_backend/include/lattice_lrs/arithmetic/` and `cpp_backend/src/arithmetic/`: configurable polynomial/matrix arithmetic using NTL.
- `cpp_backend/include/lattice_lrs/sampling/` and `cpp_backend/src/sampling/`: random source and bounded/uniform samplers.
- `cpp_backend/include/lattice_lrs/commitment/commitment.hpp` and `cpp_backend/src/commitment/commitment.cpp`: Esgin-style commitment key, commit, and open operations.
- `dilithium/upstream-round2/` and `dilithium/upstream-round3/`: separate official Dilithium test integrations.

The current proof layer is not complete. The workspace contains an incomplete `cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp` and a draft design note; this audit did not modify them. The report makes no claim that the project currently has a working binary proof, one-out-of-many proof, complete ring signature, WCM wrapper, or link-tag API.

Proposed next steps:

1. Review LoTRS’s `sign_bin`/verification path and paper figures against Esgin 2018/773 Sections 4–5, recording a line-by-line equation/parameter mapping. Mark any difference explicitly; do not assume equivalence from the shared terminology or authorship.
2. Implement the selected Esgin binary proof in the project’s existing arithmetic, sampling, and commitment types only after that mapping and parameter configuration are reviewed.
3. Implement the Esgin one-out-of-many proof and base ring signature as separate modules, with tests against the paper equations and tampering cases.
4. Separately specify the WCM OTS API, historical Dilithium variant, signed byte encoding, and tag lifecycle. Resolve whether tags must be globally linkable or auction-context-scoped before implementing the extension.
5. Add end-to-end WCM tests that verify the base signature and OTS before application-level duplicate detection, while keeping per-auction duplicate state in the test harness if that remains the required policy.

## Final decisions

1. **Is any repository an exact implementation of Esgin 2018/773?** No exact full implementation was identified. LoTRS has a related complete proof path, but exact Section 4–5 equivalence has not been established.
2. **Is any repository an exact implementation of Wang–Chen–Ma 2019/371?** No.
3. **Does any repository combine Esgin + WCM + Dilithium OTS?** No.
4. **Can a complete binary/one-out-of-many proof be reused?** LoTRS contains a complete related binary/selection-proof implementation. It is not a verified drop-in for the selected Esgin equations/parameters; use it as the primary reference for equation mapping, not direct reuse.
5. **Most useful repository for this project?** LoTRS, because it has the richest complete lattice proof implementation, parameter tooling, codecs, vectors, and tests. Its threshold construction is materially different.
6. **Should the project continue implementing Esgin?** Yes. Retain the current Esgin-specific arithmetic and commitment layers; implement missing proof and signature modules against the target paper.
7. **Next implementation step?** Review and document the equation-by-equation relationship between LoTRS’s binary/selection proof and Esgin 2018/773 Sections 4–5, then finalize the project binary-proof design before coding it.
