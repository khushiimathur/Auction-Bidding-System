# Extended PQ-LRS Research Audit

**Scope:** Read-only research and repository audit for the Lattice_LRS cryptographic module. This document does not alter implementation code, Dilithium sources, CMake, parameters, or dependencies, and no external source was copied into the project. External checkouts used for inspection are under `/private/tmp/pqlrs_external_audit/`, `/private/tmp/pqlrs_extended_audit/`, and `/private/tmp/pqlrs_additional_candidates/`, outside the project.

**Evidence labels:** “Observed” means present in the inspected repository snapshot or local source. “Paper states” means a claim in the cited paper, not an independently established security result. “Inference” marks a conclusion from comparing the observed code with the paper. Repository snapshots are identified by commit where recorded; links to source repositories are included so findings can be reproduced.

## Executive summary

No inspected repository provides an exact, end-to-end implementation of Esgin et al. (2018/773) plus Wang–Chen–Ma (WCM, 2019/371) plus the required historical Dilithium one-time-signature integration. LoTRS is the strongest implementation reference for binary and selection-hiding proof engineering, and its paper explicitly derives a selection-hiding component from Esgin’s one-out-of-many proof. Its deployed proof is nevertheless embedded in a later structured threshold signature with its own challenge set, two-modulus arithmetic, transcript and parameters. Its code cannot be dropped into the current Esgin implementation while claiming to preserve the Esgin relation or proof argument.

The local arithmetic, sampling and commitment modules are implemented and their functional CTest suite passes. The binary-proof header is a draft/interface, not evidence of an implemented proof. No completed one-out-of-many proof, base ring signature, WCM transformation, tag API or Dilithium-backed LRS is present. The current selected modulus remains provisional; none of the tests establishes security or the stated computational security level.

The broader search produced useful related work, but not a replacement that meets the exact construction: Calamari/Falafl, Raptor, MatRiCT, LoTRS, Triptych, an ethSTARK-based PQ LRS, and several lattice ZK/commitment toolkits. Two notable audit cautions are (1) the checked Obscura-PQ checkout omits the core source directories described by its README, and (2) WCM’s concrete instantiation text contains apparent inconsistencies between `H` and `H'` and between the OTS message described at signing and verification. These should be resolved against an authoritative corrected version or authors before implementation.

**Recommendation:** retain the project’s Esgin-specific arithmetic, sampling and commitment code; use LoTRS and other projects only as references after equation-by-equation mapping. Continue the selected Esgin + WCM construction only after the WCM ambiguities and context/tag lifecycle are specified. Do not claim auction-specific cryptographic unlinkability from application-level per-auction duplicate tracking.

## Audit method and source snapshots

The 16 named repositories/artifact were inspected at shallow/current snapshots. The earlier four-repository audit is preserved in [`EXTERNAL_REPOSITORY_AUDIT.md`](EXTERNAL_REPOSITORY_AUDIT.md); this document adds the remaining listed items, additional candidates, more precise Esgin–LoTRS comparison, WCM context analysis and current local status. A shallow commit identifies the inspected snapshot, not necessarily the last commit that changed source.

| Repository/artifact | Snapshot | Language(s) observed | License observed |
|---|---|---|---|
| DualRing | `073869bcc9432fb8a5ed4edd733be205a52ded14` | Python | MIT |
| LoTRS | `5df5658ed62cb0726beb69e15e41869fcc4b4de2` | Python, Rust, Sage scripts | MIT; Rust crate `MIT OR Apache-2.0` |
| Lattice RingCT v2.0 | `8adff2db3a53673759c2fcb96e615cdc71206644` | C | README says ISC; no separate root license file observed |
| Hcash RingCT | `e42fbff` (short hash recorded) | README only in checkout | Not ascertainable from checked source |
| Calamari and Falafl | `38a94bb` | C | No root license observed; subcomponent licenses do not automatically cover root sources |
| Raptor | `37d7815` | C | GPL-3.0 |
| ESORICS 2024 PQ LRS | `83d58ab` | Rust workspace | Inspect root license before reuse; workspace is Winterfell-derived |
| Obscura-PQ | `dc707c4` | README/tools/assets | No license conclusion established |
| LoTRS Zenodo artifact | record `22807126`, version 2 | Python, Rust, Sage; source archive | MIT (paper/artifact record) |
| LLRing | `6131edd8292484bc22b03a890368a1f43a98b637` | Java | GPL-3.0 |
| Triptych | `bf0cb42` | Rust | LGPL-family license; check repository LICENSE before any reuse |
| MatRiCT implementation | `4975ff4` | Go | No license file observed |
| Lantern | `64681a4` | Sage | No explicit repository license observed |
| ring-zk | `fd7086f` | Rust | MIT |
| Geometry Labs lattice cryptography | `f354b4a` | Python | MIT |
| Ringtail | `1e181c3` | Go | Apache-2.0 |

The additional snapshots below are also kept outside the project. They are screening candidates, not endorsements. Where the repository’s paper lineage or licensing was not independently established, that is stated explicitly.

## Repository summary

| Repository | Construction | Lattice-based | Linkable | OTS/Dilithium | Binary/OR proof | Reuse classification |
|---|---|---:|---|---|---|---|
| [DualRing](https://github.com/thyuen/dualring) | Canonical-identification ring signature with lattice instantiation | Yes | No WCM linkability | No | No Esgin one-out-of-many proof | REFERENCE ONLY |
| [LoTRS](https://github.com/lotrs-sig/lotrs) | Structured threshold ring signature; lattice multisignature plus selection-hiding proof | Yes | No WCM tag operation | No | Yes; Esgin-derived selection-proof ideas, integrated in a different protocol | ADAPTABLE / REFERENCE ONLY |
| [Lattice RingCT v2.0](https://github.com/chainchip/Lattice-RingCT-v2.0) | NewHope-era RingCT/L2RS | Yes | Paper describes one-time linkability | No | `ZKP_OR` is empty in inspected source | REFERENCE ONLY |
| [Hcash RingCT](https://github.com/HcashOrg/RingCT) | README describes RingCT MIMO | Claimed | Claimed | No evidence | Source absent from checkout | NOT RELEVANT for code reuse; UNVERIFIED claim |
| [Calamari and Falafl](https://github.com/WardBeullens/Calamari-and-Falafl) | Group-action OR-signature framework; CSIDH and MLWE group-action instantiations | Falafl: lattice-based; Calamari: isogeny-based | Yes, for the LRS variant | No Dilithium/WCM | OR proof, but not Esgin’s module proof | REFERENCE ONLY |
| [Raptor](https://github.com/zhenfeizhang/raptor) | Falcon/NTRU ring signature with chameleon-hash/OTS linkability extension | Yes | Yes | Separate OTS; not Dilithium/WCM | No Esgin proof | REFERENCE ONLY |
| [ESORICS 2024 PQ LRS](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature) | ethSTARK/signatures-of-knowledge adaptation | No lattice proof in inspected source | Yes | No | STARK/AIR proof | NOT RELEVANT to Esgin component reuse |
| [Obscura-PQ](https://github.com/n-azimi/Obscura-PQ) | README claims Ring-SIS/AOS/Borromean-style design | Claimed | Claimed serial number | No verified OTS | Core proof code unavailable | UNVERIFIED / no code reuse |
| [LoTRS artifact](https://zenodo.org/records/22807126) | Same LoTRS software artifact, packaged with paper/appendix/source | Yes | Not WCM-linkable | No | Same selection proof as LoTRS | ADAPTABLE / REFERENCE ONLY; not independent implementation |
| [LLRing](https://github.com/sidckchau/LLRing) | Discrete-log and pairing-based linkable ring signatures | No | Yes, prefix scoped | No | Bulletproof/Dory-style components, not Esgin | REFERENCE ONLY for application/tag ideas |
| [Triptych](https://github.com/tari-project/triptych) | Monero-style logarithmic linkable proof over Ristretto | No | Yes | No | OR proof, not lattice | NOT RELEVANT cryptographically; API-flow reference only |
| [MatRiCT](https://github.com/GoldSaintEagle/RingCT_Implementation) | MatRiCT / MatRiCT+ toy RingCT and one-out-of-many proof | Yes (module-LWE family) | RingCT-specific | No WCM/Dilithium | Yes, different relations | REFERENCE ONLY |
| [Lantern](https://github.com/khanhcrypto/lantern) | LNP22 lattice ZK examples/toolbox, including Sage ring-signature example | Yes | Example only; construction differs | No | Lattice ZK / example OR relations | REFERENCE ONLY |
| [ring-zk](https://github.com/AlvinHon/ring-zk) | Interactive proofs for commitments from RLWE | Yes | No ring signature/link tag | No | Linear/opening/sum proofs, not Esgin | ADAPTABLE arithmetic/proof engineering only |
| [Geometry Labs](https://github.com/geometry-labs/lattice-cryptography) | Lyubashevsky–Micciancio one-time signatures and aggregation | Yes | No ring tag | OTS, but not Dilithium or WCM | No | ADAPTABLE only for OTS engineering concepts |
| [Ringtail](https://github.com/daryakaviani/ringtail) | Two-round threshold signature from LWE | Yes | No ring anonymity/linkability | No Dilithium OTS | No Esgin proof | REFERENCE ONLY for distributed-signing engineering |

### Previously audited repositories: added findings

#### DualRing

The source is primarily `lattice.py` and `ecc.py`. `lattice.py` exposes `RSetup`, `RkeyGen`, `RSign`, and `RVerify`, with polynomial/matrix helpers and a hash-derived challenge. The experiment uses `DEGREE=128`, `Q=33564673`, and its own dimensions and coefficient limits. It implements a distinct identification-based construction, not Esgin’s commitment `Com_ck`, Protocol 1 binary proof, or Protocol 2 selection proof. The small script-level demonstration is not a robust tampering, linkability or interoperability suite. Dependencies include NumPy/SciPy/SymPy and PyCryptodome. The attempted script execution stopped at missing `Crypto`; no dependency was installed.

#### LoTRS and its artifact

The source artifact includes Python and Rust implementations, parameter validation, ring arithmetic, samplers, rejection functions, codecs, deterministic vectors, cross-language tests and estimator material. Primary code locations include `lotrs-py/lotrs.py` (`_sign_bin`, `verify`), `lotrs-py/sample.py` (XOF samplers and rejection functions), `lotrs-py/codec.py`, `lotrs-rs/src/lotrs.rs` (`sign_bin`, `verify_impl`), and corresponding Rust `sample.rs`, `ring.rs`, `codec.rs`. The artifact README documents a large test suite; these are the project’s documented test counts, not all independently rerun in this audit. In this environment, the attempted `make check` halted on missing Python crypto dependency before the complete suite. Cargo, Rust and Sage were unavailable in the earlier environment check. The separate Zenodo record packages the same LoTRS work and does not constitute a second independent implementation.

Its shipped profile uses `d=128`, `q=2^43−67`, `q_hat=2^35−451`, and LoTRS-specific dimensions, bounds and challenge weight. It uses an additional modulus in its proof machinery. This is not the project’s experimental Esgin profile (`d=256`, provisional approximately 50-bit odd `q`, `n=5`, `m=13`, `v=16`). LoTRS’s paper describes its selection proof as arising from Esgin’s one-out-of-many proof; the exact relationship is analyzed below.

#### Lattice RingCT v2.0

The C source is in `ring.c`/`ring.h`; the public routines include `LRCT_Setup`, `LRCT_KeyGen`, `LRCT_SigGen`, `LRCT_SigVer`, `LRCT_Spend`, and `LRCT_Verify`, alongside commitment helpers. The checked implementation uses NewHope-style degree 512 and modulus 12289, not the project’s Esgin parameters. The source declares `ZKP_OR`, but the inspected body is empty. Its default `main` exercises the commitment homomorphism test; the signature test calls in that harness are commented out. The repository documents ISC in README, but root-level licensing is ambiguous. Its Windows/Visual Studio project does not give a portable verified build path in the available environment. Do not treat the paper’s linkability description as verified by this test harness.

#### Hcash RingCT

The checked repository snapshot contains only a README among tracked files. It points to a RingCT MIMO implementation and describes it, but the code necessary to inspect, build or test is absent. Algorithm, source license, signature behavior and test coverage are therefore UNVERIFIED. The existence of a description is not evidence that an implementation is present.

### Remaining listed repositories

#### Calamari and Falafl

The associated paper is Beullens, Katsumata and Pintore, “Calamari and Falafl: Logarithmic (linkable) ring signatures from isogenies and lattices,” ASIACRYPT 2020 / ePrint 2020/646. The code has `lrsign.c`/`lrsign.h` (`lrsign`, `lrverify`) and `rsign.c`/`rsign.h` (`keygen`, `rsign`, `rverify`), with group-action, Merkle and cryptographic support. Its lattice Falafl instantiation is a real lattice-based LRS, but it is an OR sigma protocol over a group action, not Esgin’s commitment and one-out-of-many proof. Build documentation invokes `make test_rs_iso`, `make test_lrs_iso`, `make test_rs_lat`, `make test_lrs_lat`; the Makefile uses GMP, XKCP Keccak and OpenSSL, with an architecture-specific XKCP path. No root license was observed, so reuse rights need clarification. Not built during this audit.

#### Raptor

The associated work is Lu, Au, Zhang, “Raptor: A Practical Lattice-Based (Linkable) Ring Signature,” ePrint 2018/857 / ACNS 2019. C files `raptor.c` and `linkable_raptor.c` implement `raptor_keygen/sign/verify` and `linkable_raptor_keygen/sign/verify`. The linkability layer binds a Falcon-based signature construction to an OTS verification key/chameleon-hash mechanism. This is materially different from Esgin + WCM and its OTS is not the required Dilithium instantiation. README marks the implementation as a research prototype; GPL-3.0 applies. No portable build/test command was established in this audit; the repository includes an Eclipse-generated project. It can inform comparison of lattice-LRS and OTS layering but is not a drop-in component.

#### ESORICS 2024 PQ LRS

The paper is Xue, Lu, Au and Zhang, ePrint 2024/553. Its stated route is to adapt signatures-of-knowledge using ethSTARK; inspected Rust source lives in the Winterfell-derived workspace, including `examples/src/sigrescue/{prover,signature,air}.rs` and generic AIR/FRI modules. This is a post-quantum linkable signature design but not a lattice commitment/Module-LWE proof. Cargo was unavailable, so no build/test was run. License inheritance and compatibility should be reviewed before reuse; no reuse is proposed.

#### Obscura-PQ

README claims a Ring-SIS/Ring-LWE AOS/Borromean-style withdrawal design with deterministic serial numbers and gives illustrative parameters. The pinned checkout (`dc707c4`) has only 37 tracked files: README, scripts/tools, assets and requirements. The `core/`, `contract/` and `frontend/` directories described by the README are not in the inspected Git tree. Thus its algorithm description, parameters, tests, build and license cannot be confirmed from implementation source. It is not a verified source of reusable cryptography.

#### LLRing

Java sources include `TagDL.java` and `TagP.java` and two constructions (discrete-log and pairing). Tag construction includes a prefix/context concept. These are not post-quantum algorithms, and their tag relation is not WCM’s OTS-key transformation. The tested compile attempt failed because BouncyCastle Keccak classes were unavailable; Maven was unavailable and the README’s test path was not present. GPL-3.0. Conceptual reference only for API/testing questions about scoped tags.

#### Triptych

Triptych’s source (`src/proof.rs`, `statement.rs`, `transcript.rs`, `witness.rs`) implements a logarithmic linkable proof in the Ristretto/discrete-log setting with Merlin transcript machinery. It is not lattice-based. Rust/Cargo was unavailable, so tests were not run. Its verification order, transcript API and tampering tests can be read as general engineering examples only; not cryptographic component reuse.

#### MatRiCT

The repository is a Go toy implementation of MatRiCT and MatRiCT+ (ePrint 2019/1287 and 2021/545), with sources such as `Matrict.go`, `Matric+.go`, `Matric+_plus.go`, and `RingMatrix.go`. It demonstrates separate one-out-of-many proof ideas in a different RingCT relation and parameter system. README explicitly calls it a toy and warns against production use; it also notes a LAGO `MulPoly` issue and workaround. The Go test attempt failed before tests because `github.com/dedis/lago/{bigint,polynomial,ring}` was not available offline. No license file was found. Do not transplant its proof equations.

#### Lantern

Lantern is a Sage-based LNP22 proof toolbox and contains illustrative `ring_signature.sage`/`group_signature.sage` examples, alongside module-LWE proof and integer arithmetic scripts. It is useful for reading concrete lattice ZK examples, but is not Esgin’s construction. No explicit repository license was found; Sage was unavailable, so no tests were run. The TUG Graz lattice-ZK notebook/download is a separate educational artifact, not an exact target implementation.

#### ring-zk

The Rust MIT project implements proofs for RLWE commitments (ePrint 2016/997), including `src/commit.rs`, `src/params.rs`, and opening/linear/sum proof modules under `src/prove/`. It does not implement Esgin’s commitment relation or binary/one-out-of-many protocol. It may inform commitment-proof API boundaries, but its equations, distributions and serialization require a fresh proof mapping. Cargo was unavailable; tests not run.

#### Geometry Labs lattice cryptography

The Python MIT repository includes `lm_one_time_sigs.py` and `bklm_one_time_agg_sigs.py`, an implementation of Lyubashevsky–Micciancio one-time signatures and aggregation. This is not Dilithium, not the OTS specified by WCM, and not a linkability wrapper. `python3 -m unittest discover -s tests` failed to import tests because `pytest` was unavailable; no dependencies were installed. It is an OTS design reference only.

#### Ringtail

The README identifies Ringtail as a Go implementation of the two-round threshold signature from LWE, ePrint 2024/1113, and explicitly calls it an academic proof-of-concept, not production-ready. Source includes `sign/sign.go`, `sign/local.go`, `sign/config.go`, `primitives/{hash,shamir}.go`, and ring arithmetic helpers under `utils/`. Its license is Apache-2.0. It is not a ring-anonymous or linkable ring signature, and it is not Esgin/WCM; at most it informs threshold/distributed-signing engineering. Go test execution was not completed in this audit.

## Additional repository and artifact search

The search found at least ten additional candidates/artifacts. Several are useful lattice ZK or arithmetic systems, but none is an exact Esgin + WCM implementation.

| Candidate and snapshot | Paper / authors / year | Source, language, license | Build/tests observed | Relevance and maturity |
|---|---|---|---|---|
| [LaBRADOR](https://github.com/lattice-dogs/labrador), via Lattirust `6ce6b09` | LaBRADOR, ePrint 2022/1341; authors cited by linked paper | C implementation; Apache-2.0 in the checked toolkit | README gives Make-based AVX-512 reproduction for a newer Orthus aggregation example; several `test_*.c` programs. Not run | Succinct lattice ZK techniques; not Esgin OR proof; research toolkit |
| [Lazarus](https://github.com/lattice-complete/Lazarus), `4363e51` | Framework based on LaBRADOR/LNP and Greyhound; paper links in README; active 2026 snapshot | Rust; Apache-2.0; `Poly<D>`, `PolyVec`, `PolyMat`, samplers, rejection, proof crates | Cargo workspace and tests documented; Cargo unavailable here | Strong arithmetic/ZK engineering reference; no Esgin ring signature; active prototype, README says not production |
| [LatticeFold](https://github.com/NethermindEth/latticefold), `15cc045` | LatticeFold ePrint 2024/257; LatticeFold+ ePrint 2025/247, Boneh/Chen | Rust; dual MIT/Apache-2.0 | `cargo build --release`, `cargo bench`; requires pinned nightly; not run | Ajtai commitment/folding and ring arithmetic ideas; no LRS / Esgin proof; proof-of-concept |
| [Akita](https://github.com/f7ed/akita), `4a6897c` | Module-lattice polynomial commitment lineage identified in repository README/specs | Rust; dual MIT/Apache-2.0 | Cargo workspace, CI and tests observed; not run | Commitment machinery only; not ring signature or one-out-of-many proof; active research code |
| [lattice-zksnark](https://github.com/lattice-based-zkSNARKs/lattice-zksnark), `48cb4cd` | ISW21, “Shorter and Faster Post-Quantum Designated-Verifier zkSNARKs from Lattices,” ePrint 2021/977 | C++; MIT; depends on libsnark submodule and AES-NI | README gives CMake build and R1CS test command; not run | Different lattice SNARK/QAP relation, not Esgin proof |
| [Lattirust](https://github.com/lattirust/lattirust), `6ce6b09` | Rust lattice/ZK toolkit; repository names LaBRADOR, Lova, arithmetic and estimator work | Rust; license status not confirmed in this pass | Cargo workspace; not run | Ring/poly arithmetic, norm/challenge types and Fiat–Shamir safety patterns; no exact LRS |
| [RLWE Enterprise Cryptographic System](https://github.com/KevinWeiss1995/RLWE), `a92dd9c` | No peer-reviewed paper identified in README | C++20; license not established | CMake; tests under `tests/test_rlwe.cpp`; not run | Generic RLWE encryption/demo, not a commitment proof or ring signature; README claims need independent validation |
| [TRS MATLAB](https://github.com/Blueskysun1/TRS), `37a4b1b` | README calls it traceable ring signature; paper citation absent | MATLAB; license absent | `Main_TRS.m`; MATLAB/Octave unavailable | Toy/simulator lead only: source uses hard-coded demonstration parameters and randomized challenge in place of claimed hash; not reusable |
| [TUG lattice-ZK notebook](https://lattice-zk.isec.tugraz.at/) | Educational notebook by TUG Graz group (2023); exact paper citation not independently confirmed | Python/Sage notebook `lattice-zk.py`; license unclear | Download-and-run Sage notebook; Sage unavailable | Didactic commitment/linear proof example; not Esgin LRS |
| [LUX `ring/lattice.go`](https://github.com/crypto-luxfi/crypto-luxfi), `1665b67` | Repository source, not a paper-backed lattice LRS | Go; Lux Ecosystem License 1.2, restrictive terms (research use allowed; other uses constrained) | Go modules/tests; not run | Source comments explicitly say ring-signature anonymity uses SHA-512 and not lattice hardness, despite ML-DSA-65 key material; unsuitable as PQ LRS |
| [RLWE commitment/ZKPoK implementation paper](https://eprint.iacr.org/2023/1026) | Martínez, Morillo, Rovira, 2023 | Paper describes implementation; no independently confirmed code repository URL | Not independently reproducible from code in this audit | Relevant commitment proof literature, but not Esgin module commitment; no source reuse established |

These entries were screened at source/README level. Their tests were not all run because their languages, toolchains or dependencies were unavailable. Do not interpret inclusion as a recommendation or security endorsement.

## Esgin vs LoTRS: mathematical and source comparison

### Paper locations and relation

Esgin et al., [ePrint 2018/773](https://eprint.iacr.org/2018/773), provides the lattice commitment preliminaries in §2, algebraic tools in §3, binary proof as Protocol 1 in §4 (printed pp. 13–15), one-out-of-many proof as Protocol 2 in §5 (printed pp. 15–18), and the ring signature in §6 (printed pp. 19–20). Appendix D gives ring-signature parameter analysis; Appendix E discusses security. The protocol equations are recorded in the existing [`PHASE3_RING_SIGNATURE_DESIGN.md`](PHASE3_RING_SIGNATURE_DESIGN.md).

LoTRS, [ePrint 2026/974](https://eprint.iacr.org/2026/974), is a structured threshold ring signature. Its paper describes its selection-hiding proof as arising from Esgin’s lattice one-out-of-many proof, but the complete LoTRS protocol integrates that proof with a two-round lattice multisignature and its own parameter, arithmetic and transcript system. Thus the relationship is more than coincidental terminology, yet it does not establish that the artifact implements Esgin Protocols 1 and 2 unchanged.

**Equation reference note:** Esgin’s protocols are numbered algorithms/protocol steps; several equations are displayed without a unique equation number. The table cites protocol, step, section and printed page instead of inventing equation numbers. LoTRS’s source has implementation routines and paper figures; where the artifact did not give a one-to-one equation identifier, that mapping is deliberately described at the relation level.

| Property | Esgin et al. | LoTRS paper/source | Equivalent? |
|---|---|---|---|
| Mathematical relation | Section 4 proves a committed indexed binary/one-hot witness with the algebraic product relation; Section 5 composes digit encodings to prove one ring member’s commitment opens to the selected public key. Protocol 1 and Protocol 2, pp. 13–18. | `lotrs-py/lotrs.py:_sign_bin`; Rust `lotrs-rs/src/lotrs.rs::sign_bin` and `verify_impl`. Selection proof is integrated with threshold table signing and a verification relation involving LoTRS public-key rows and its truncated/high-low representations. | Related lineage, not identical full statement. The paper explicitly says Esgin-derived; deployed statement is LoTRS-specific. |
| Commitment construction | Esgin `Com_ck(μ;r)=G_r r+G_m μ` over its polynomial module, §2.2; commitment key structure and message/randomness dimensions feed Protocols 1–2. | LoTRS constructs structured public matrices/ring elements from seeds and uses its own commitments within the threshold and selection relations; it also uses a second modulus `q_hat` in its proof machinery. See `lotrs-py/lotrs.py`, parameter and ring modules. | No. Do not substitute one commitment key or module for the other. |
| Witness representation | Esgin uses a base-β encoding of a selected index into one-hot blocks (`N=β^k`) and committed binary vectors; Protocol 2, §5, pp. 15–18. | LoTRS encodes a selected table column in its own threshold/table representation; `_sign_bin` handles binary constraints associated with that construction. | Similar selection purpose; exact dimensions, witness and commitment relations differ. |
| Challenge space | Esgin ring-signature FS challenge uses monomials `X^ω` with `0≤ω<2d`, derived from `H(ck,M,L,(CMT_i))`, §6, pp. 19–20. Binary/one-out-of-many protocols use the prescribed challenge element and algebraic tools from §3. | LoTRS expands a seed through domain-separated XOF to a sparse signed challenge polynomial; `xof_sample_challenge` in Python `sample.py` / Rust `sample.rs`; challenge weight `w` and degree `d` are LoTRS parameters. | No. Esgin monomial challenge and LoTRS sparse challenge are distinct distributions/sets. |
| Response calculation | Protocol 1 uses `f=x b+a`, `z_b=x r+r_a`, `z_c=x r_c+r_d`, and `g=f(x−f)`; Protocol 2 has its own `z=x^k r−Σ x^jρ_j` relation. Esgin §4–5, Protocol 1/2, pp. 13–18. | `sign_bin`/`_sign_bin` computes responses for LoTRS’s table, challenge polynomial, commitment and truncated relation; `verify_impl` reconstructs the corresponding commitments. | Some algebraic shape may be related; not shown byte-for-byte or equation-for-equation identical. Transfer only after mapping every response and sign convention. |
| Norm constraints | Esgin sets explicit protocol bounds and uses its exact distributions and rejection sampler; Protocols 1–2 and §2.3 Algorithm 1. | LoTRS checks its own bounds and rejection rules, including modulus-specific/round-specific constraints; `sample.py`/`sample.rs` implement `rej` and `rej_op`. | No. Bounds and acceptance probabilities are proof-specific. |
| Rejection sampling | Esgin `Rej(z,c,φ,K)` Algorithm 1, §2.3, p. 8, and the exact calls/bounds in Protocols 1–2. | LoTRS has `rej`/`rej_op` and its own Gaussian/short distributions and packed response checks. | Same broad technique, not the same sampler inputs or distribution. Reusing the algorithm without re-derivation breaks the Esgin analysis. |
| Fiat–Shamir | Esgin hashes commitment key, message, ring and first-message commitments into the paper-defined challenge, §6. Exact byte encoding is not fully fixed in paper. | LoTRS uses domain separation, SHAKE-derived challenge seed/expansion and a canonical codec; Python/Rust cross-language fixtures enforce its wire format. | Different transcript and challenge map. Codec techniques are adaptable; transcript is not interchangeable. |
| Verification equations | Esgin checks commitment equations and norm bounds in Protocol 1, then Protocol 2 relations, and reconstructs FS challenge in §6. | LoTRS `verify`/`verify_impl` checks LoTRS multi-signature and selection proof, table/key relations, range/representation constraints, and challenge reconstruction. | No. Similar proof purpose does not establish identical acceptance relation. |
| Parameter requirements | Esgin’s own `d,q,n,m,v,β,k,r,B` and assumption/security analysis; target’s q is still provisional. | LoTRS profile includes `d=128`, `q=2^43−67`, `q_hat=2^35−451`, challenge weight and other LoTRS-only values. | No. Different ring degree, moduli and proof parameters. |
| Security assumptions | Esgin analyzes its commitments and one-out-of-many proof under its stated module-LWE/module-SIS assumptions and protocol bounds; Appendix E. | LoTRS claims are based on its threshold signature + selection proof, its own assumptions and parameter estimator. | No. LoTRS security analysis does not certify the Esgin parameter row or an adapted hybrid. |

### Adaptation conclusion

LoTRS can help engineers understand a complete binary/selection-proof implementation, including control flow, deterministic test vectors, byte encoding, malformed-input checks and cross-language testing. Its paper’s explicit Esgin lineage makes it a more relevant reference than an unrelated proof toolkit. However, replacing the Esgin binary proof with LoTRS `sign_bin` would change at least the challenge distribution, parameter system, commitment/statement integration and rejection/verification constraints. Unless each exact Esgin relation is independently implemented and proven to match, it would not preserve the Esgin construction or its security argument. Therefore: **adapt techniques and test patterns, not LoTRS proof code as an implementation substitute.**

## Component reuse matrix

| Target component | Best inspected reference | Classification | Reason / limits |
|---|---|---|---|
| Esgin binary proof | LoTRS `sign_bin` / `_sign_bin`, plus Esgin Protocol 1 | ADAPTABLE (engineering reference only) | Esgin-derived selection-proof lineage, but LoTRS relation, challenge, bounds and parameters differ. Implement target equations in project types. |
| Esgin one-out-of-many proof | LoTRS proof path; MatRiCT proof sources for contrasting construction | REFERENCE ONLY / ADAPTABLE ideas | Both solve related selection/hiding tasks, but not same proof relation, commitment or soundness argument. |
| Esgin commitment | Local `commitment.cpp`; ring-zk / Akita / LatticeFold as comparisons | Keep local implementation; external REFERENCE ONLY | No inspected implementation exactly matches Esgin Section 2.2 and current module dimensions/distributions. |
| Polynomial/matrix arithmetic | Local NTL module; Lazarus/Lattirust/LoTRS for engineering patterns | Keep local; external REFERENCE ONLY | Different language, modulus assumptions, NTT and representation. No need to replace correct configurable-q arithmetic based on name similarity. |
| Gaussian sampling | LoTRS; Lazarus/LaBRADOR | REFERENCE ONLY | Later Esgin proof distributions and rejection parameters must be sourced from target paper; do not transfer values. |
| Rejection sampling | Esgin Algorithm 1 as specification; LoTRS `sample.py`/`sample.rs` for code structure | ADAPTABLE only at control-flow/testing level | Acceptance probability and distributions must be Esgin-exact. |
| Fiat–Shamir transcript | LoTRS codec/XOF vectors; Triptych transcript as generic API pattern | ADAPTABLE engineering ideas | Neither transcript is Esgin/WCM transcript; fix domain separation, canonical encoding and hash once specification is settled. |
| Canonical serialization | LoTRS `codec.py` / `codec.rs` and cross-language fixtures | ADAPTABLE | Strong artifact pattern; do not reuse wire format or hashed bytes blindly. |
| Dilithium OTS | Local official Round 2/Round 3 sources | Keep as isolated test integrations pending WCM historical variant decision | No external LRS repository provides the exact WCM + historical Dilithium integration. Dilithium API/signature format alone does not supply LRS linkability. |
| Link-tag generation/verification | WCM paper as intended specification; LLRing/Raptor for contrasting concepts | No exact implementation found; REFERENCE ONLY | LLRing prefix tags and Raptor chameleon-hash tags are different constructions. WCM context semantics remain unresolved. |

No external code was copied or recommended for direct import. Review each repository license and upstream notices before any future reuse.

## WCM linkability and auction-context analysis

### What the paper describes

Wang, Chen and Ma, [ePrint 2019/371](https://eprint.iacr.org/2019/371), §3 gives a generic transformation and §4 gives a concrete Esgin + OTS instantiation. In the generic description, an OTS verification key `ovk` is included in the transformed ring-key construction; signing transforms the ring using the signer’s `ovk`, produces a base ring signature and OTS-signs a tuple containing the base signature, tag and `ovk`; verification reconstructs the transformed ring, verifies the base ring signature, and verifies the OTS; the link procedure first verifies both signatures then compares their `ovk` values. The concrete instantiation writes a public-key transformation using `H'(ovk)` (rather than the generic notation’s `H(ovk)`).

### Direct answers for this application

1. **Does reusing the same `ovk` produce stable tags?** Yes, in the described construction the verifier key is the link value compared by the link algorithm. Repeated valid signatures using the same `ovk` are linkable.
2. **Does a fresh OTS key per submission prevent linkability?** Yes, if independent `ovk` values are used and the base construction/OTS is otherwise correct, comparing tags no longer identifies those submissions as the same key. It also defeats the intended repeated-signature linkability across those submissions.
3. **Does reusing `ovk` across auctions permit cross-auction correlation?** Yes. A public observer can compare the same `ovk`; application-level per-auction sets do not hide that public equality.
4. **Can an auction ID be included in key derivation or transformation?** It is a possible design change, not something established as secure by WCM. The paper does not provide a context-scoped key derivation/security theorem for this application. Altering the hash input, OTS key generation or public-key transformation changes the protocol and must be specified consistently at keygen, signing, verification and link.
5. **Does the WCM proof cover that modification?** No such auction-context modification was located in the paper. Treat it as outside the stated proof.
6. **Would a new security analysis be required?** Yes. In particular, analyze linkability within context, unlinkability across contexts, key derivation/domain separation, chosen-message security of the OTS, and interactions with the base-ring-signature anonymity game.
7. **Does any inspected repository implement context-scoped WCM?** No.

The application’s duplicate set can be keyed by auction ID after signature verification. This scopes the *application’s rejection state*, not the public cryptographic tag. The requested order—verify before duplicate detection—is consistent with WCM’s described link procedure, which verifies inputs before comparing their `ovk` values. It does not by itself hide bidder identity or prevent observers from correlating tags across auctions.

### WCM paper inconsistencies requiring resolution

The concrete section should be checked against an authoritative corrected copy or author clarification before implementation. In the available paper text:

- Setup defines both `H: {0,1}* → C` and `H': {0,1}* → R_q^n`; concrete key generation and ring-key transformation use `H'(ovk)`, while the verification description appears to use `H(ovk)`. The types are not interchangeable as written.
- Concrete signing describes the OTS message as `(σ,T,ovk)` (where notation is from its base signature/tag); verification appears to check an OTS message containing `(hatσ,T,hatpk)`. Those messages are not textually the same.
- The generic construction/key-generation flow appears to retain an OTS secret key for the signer, while the security proof’s signing-oracle simulation is described using freshly generated OTS key material for a query. The paper does not clearly settle the practical key lifecycle for repeated signatures.

These are **observed textual inconsistencies**, not permission to choose an intended correction. Do not silently replace `H` by `H'`, alter the OTS message, or assume fresh/per-signature key semantics. Record author clarification or an erratum as a precondition to a production-facing protocol specification.

## Existing Lattice_LRS project status

### Current implementation inventory

| Component | Observed files | Status |
|---|---|---|
| Polynomial arithmetic | `cpp_backend/include/lattice_lrs/arithmetic/polynomial.hpp`, `cpp_backend/src/arithmetic/polynomial.cpp` | Implemented configurable-modulus polynomial operations, including negacyclic ring arithmetic and centered/canonical conversions covered by project tests. This is functional arithmetic, not a security proof. |
| Matrix arithmetic | `cpp_backend/include/lattice_lrs/arithmetic/matrix.hpp`, `cpp_backend/src/arithmetic/matrix.cpp` | Implemented polynomial matrix/vector operations used by the backend. |
| Random source and samplers | `cpp_backend/include/lattice_lrs/sampling/{random_source,sampler}.hpp`, matching `src/sampling/*.cpp` | Implemented OS-backed production source, uniform/bounded coefficient sampling and deterministic injected test source per project design. Passing tests do not prove entropy quality on every platform. |
| Esgin-style commitment | `cpp_backend/include/lattice_lrs/commitment/commitment.hpp`, `cpp_backend/src/commitment/commitment.cpp` | Setup/key construction, commit and relaxed open relation exist. This is a commitment component, not a completed proof or signature. |
| Binary proof | `cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp` | Header/draft API exists; no corresponding binary-proof implementation source was found. Treat as incomplete/untested protocol logic. |
| One-out-of-many proof | No completed source module found | Missing. |
| Base Esgin ring signature | No complete keygen/sign/verify module found | Missing. |
| WCM wrapper/tag | No WCM key transformation, OTS-bound LRS API or link operation found | Missing. |
| Dilithium Round 2 | `dilithium/upstream-round2/` plus isolated test target | Official historical source checkout, MODE=4 tests; not an LRS OTS integration and does not provide Dilithium5. |
| Dilithium Round 3 | `dilithium/upstream-round3/` plus isolated test target | Official Round 3 reference source with MODE=5 test; isolated API check only, not integrated into WCM. |
| Parameter/security validation | `docs/PHASE3_RING_SIGNATURE_DESIGN.md` | N=64 research row documented; exact production q and exact M-LWE/M-SIS security validation remain unresolved. No computational security claim is established. |

The root CMake file adds `cpp_backend`, four project arithmetic/sampling/commitment tests and optional independent Dilithium tests. `cpp_backend/CMakeLists.txt` locates NTL/GMP, defines imported targets, and builds `lattice_lrs_backend`. The upstream Dilithium sources are isolated in separate static libraries/test executables when the option is enabled.

### Test evidence

Command run against the existing configured build:

```sh
ctest --test-dir Lattice_LRS/build --output-on-failure
```

Observed result: **100% tests passed, 0 tests failed out of 6**:

```text
cpp_build_smoke
ntl_gmp_integration
polynomial_matrix_arithmetic_test
sampling_commitment_test
dilithium_round2_test
dilithium_round3_test
```

These tests exercise build integration, NTL/GMP use, arithmetic, sampler/commitment behavior, and independent Dilithium API acceptance/rejection. They do not test a binary proof, one-out-of-many proof, Esgin signing/verification, WCM linkability, auction context, anonymity, M-LWE/M-SIS security, or side-channel behavior.

Additional external test attempts and blockers:

| Attempt | Result |
|---|---|
| LoTRS `make check` | Stopped before full suite because PyCryptodome module `Crypto` was absent; no install performed. Rust/Sage toolchain unavailable in the earlier environment audit. |
| DualRing Python script | Stopped on missing `Crypto`; no tests completed. |
| Geometry Labs `python3 -m unittest discover -s tests` | Test import failed because `pytest` was unavailable. |
| MatRiCT Go test | Failed before tests: external `github.com/dedis/lago` packages unavailable offline. |
| LLRing `javac` attempt | Failed due missing BouncyCastle Keccak classes; Maven unavailable. |
| RingCT v2.0 | No portable build/test was run; checked README describes Visual Studio/Windows build and default harness does not execute full signature tests. |
| Calamari/Falafl, Raptor, ESORICS 2024, Triptych, ring-zk, Lantern, additional Rust/C++ candidates | Source reviewed; builds not run because required toolchains/dependencies were missing or not justified for this audit. |

No failed test was repaired by changing external source or installing dependencies. No result above is a security evaluation.

## Security, compatibility and specification concerns

1. **No exact implementation located.** Search results and source snapshots show related constructions, not a complete Esgin + WCM + Dilithium implementation.
2. **LoTRS equivalence is bounded.** It is Esgin-derived at the selection-proof level according to its paper, but its concrete protocol, challenge, modulus, table relation and security analysis differ. Exact proof preservation is not established.
3. **Production q is unresolved.** Do not freeze an approximately `2^50` candidate merely because arithmetic tests pass. Check all paper inequalities and the exact structured M-LWE/M-SIS assumption using a justified estimator before treating parameters as implementation-ready.
4. **Dilithium is not an LRS.** The Round 2/3 C tests validate those upstream APIs independently. The historical variant/API expected by WCM, one-time key lifecycle and OTS message must be fixed before integration.
5. **WCM context is underspecified for auction use.** Stable `ovk` supports repeated linkability but creates cross-context correlation if reused. Fresh `ovk` per submission removes that correlation and also removes linkability. Auction-scoped cryptographic tags require protocol definition and security analysis.
6. **Paper-text ambiguity.** The `H`/`H'`, OTS-message and OTS-key lifecycle inconsistencies above are unresolved. The implementation must not guess.
7. **Prototype quality varies.** Several candidate repositories explicitly identify themselves as research or toy code. Functional test suites are not proofs of security, constant-time execution, safe serialization, or parameter suitability.

## Recommendations and exact next steps

1. **Resolve WCM’s concrete notation and OTS lifecycle first.** Locate an erratum/corrected version or request author clarification for the hash types, OTS signed message and whether an OTS key is per signer or per signature. Record the chosen interpretation as a reviewed protocol specification; do not infer it from code in unrelated schemes.
2. **Freeze a reviewed Esgin proof specification, not a production modulus.** For Protocols 1 and 2, write a source-to-equation map for each witness, commitment, challenge, response, norm check and rejection-sampling call. Resolve q/security analysis independently before assigning an approved profile.
3. **Implement the Esgin binary proof in existing modules after review.** Keep arithmetic, samplers and commitment API unchanged unless an equation-level defect is demonstrated. Use LoTRS for defensive implementation patterns and test design only; add deterministic fixtures and malformed/tampering cases for the Esgin relation.
4. **Then implement the Esgin one-out-of-many proof and base ring signature.** Make verification recompute the exact paper transcript and enforce all bounds. Validate against independent vectors or a second implementation if one can be established.
5. **Integrate WCM only after base LRS passes its own tests.** Add OTS transformation and link verification according to the reviewed WCM specification. Keep Dilithium integration separate from upstream source. Explicitly decide whether the same `ovk` is expected across signatures and contexts.
6. **Treat auction context as a separate cryptographic requirement.** If cross-auction unlinkability is required, define a context-bound tag/key derivation and obtain a new security analysis; application-level per-auction storage is not a cryptographic substitute.
7. **Test in layers:** exact arithmetic properties; commitment opening/bounds; binary proof; one-out-of-many proof; base signature; WCM sign/verify/link; invalid-signature rejection before link checks; same-context duplicate; cross-context unlinkability experiment. Report functional results separately from formal/security analysis.

## Final decisions

1. **Exact implementation of Esgin 2018/773 found?** No.
2. **Exact implementation of WCM 2019/371 found?** No.
3. **Implementation combining Esgin + WCM + Dilithium OTS found?** No.
4. **Can LoTRS binary proof be adapted while preserving Esgin’s exact construction?** Its techniques can inform implementation, but directly adapting its proof code is not shown to preserve Esgin’s relation or proof. Re-implement the exact Esgin equations and use LoTRS only as a reference unless formal equivalence is established.
5. **Can MatRiCT or another repository help?** Yes, as reference for proof engineering and one-out-of-many concepts; its relation and parameters are different. LoTRS is the strongest directly related implementation reference. ring-zk, Lantern, LaBRADOR/Lazarus and LatticeFold offer narrower ZK/arithmetic patterns.
6. **Best reference by component?** LoTRS for binary/selection proof engineering and codecs; Esgin itself for proof equations; project-local code for arithmetic/sampling/commitment; Geometry Labs only for generic OTS engineering; WCM paper for transformation/tag semantics, subject to clarification; no exact source for WCM + Dilithium integration.
7. **Can WCM support auction-specific linkability without cross-auction correlation as written?** Not established. Reusing `ovk` makes stable cross-context equality; fresh `ovk` per auction would require an explicit context lifecycle and new analysis, and the paper does not prove it.
8. **Which local components should remain unchanged?** Keep current arithmetic, random source/sampler, Esgin-style commitment, and both isolated Dilithium source trees/tests unchanged during this research stage. The proof header remains a draft, not an implemented module.
9. **Safest next module?** After resolving the proof text and reviewing exact Esgin Protocol 1 semantics, implement and test the Esgin binary proof as a standalone module using the existing commitment and arithmetic APIs.
10. **Change construction or continue Esgin + WCM?** No evidence here justifies replacing the chosen construction. Continue only after the WCM specification inconsistencies and auction-context requirement are explicitly resolved; otherwise implementation would require guessing.

**Readiness conclusion:** the arithmetic/commitment foundation is functionally tested, but the cryptographic construction is not ready for full LRS implementation. It is ready for a narrowly scoped binary-proof design review once the relevant Esgin and WCM specification ambiguities and parameter/security dependencies are resolved. No security level is claimed by this report.

## References

- Esgin et al., [Short Lattice-based One-out-of-Many Proofs and Applications to Ring Signatures, ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [Adding Linkability to Ring Signatures with One-Time Signatures, ePrint 2019/371](https://eprint.iacr.org/2019/371).
- LoTRS, [Practical Post-Quantum Structured Threshold Ring Signatures from Lattices, ePrint 2026/974](https://eprint.iacr.org/2026/974), [source](https://github.com/lotrs-sig/lotrs), [artifact](https://zenodo.org/records/22807126).
- Calamari/Falafl, [ePrint 2020/646](https://eprint.iacr.org/2020/646).
- Raptor, [ePrint 2018/857](https://eprint.iacr.org/2018/857).
- MatRiCT, [ePrint 2019/1287](https://eprint.iacr.org/2019/1287), [MatRiCT+ ePrint 2021/545](https://eprint.iacr.org/2021/545).
- LLRing, [ePrint 2024/421](https://eprint.iacr.org/2024/421).
- ESORICS 2024 PQ LRS, [ePrint 2024/553](https://eprint.iacr.org/2024/553).
- ring-zk, [RLWE commitment proofs, ePrint 2016/997](https://eprint.iacr.org/2016/997).
- LaBRADOR, [ePrint 2022/1341](https://eprint.iacr.org/2022/1341); current toolkit paper [ePrint 2026/1289](https://eprint.iacr.org/2026/1289).
- LatticeFold, [ePrint 2024/257](https://eprint.iacr.org/2024/257); LatticeFold+, [ePrint 2025/247](https://eprint.iacr.org/2025/247).
- Lattice zkSNARK, [ePrint 2021/977](https://eprint.iacr.org/2021/977).
- Esgin parameter and M-LWE validation decisions remain documented in [`PHASE3_RING_SIGNATURE_DESIGN.md`](PHASE3_RING_SIGNATURE_DESIGN.md).
