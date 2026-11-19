# PQ-LRS Reuse and Adaptation Audit

**Purpose:** identify a practical implementation path for the project's anonymous, post-quantum, linkable ring-signature module. This audit compares complete schemes and reusable components without presuming that Esgin + WCM must be retained.

**Scope and evidence:** source and documentation were inspected in external checkouts under `/private/tmp`; no external code was copied into the project, and no source, header, CMake, parameter, or dependency file was changed. Repository statements are distinguished from source-observed behavior and audit inference. Passing tests establish only the exercised behavior, not cryptographic security.

## Executive recommendation

No inspected implementation is simultaneously a clearly reusable, well-supported, production-audited implementation of an auction-scoped PQ linkable ring signature. There are complete experimental candidates:

1. **Falafl is the closest complete lattice-based LRS candidate for an evaluation prototype.** Its paper and C source implement linkable and unlinkable logarithmic ring signatures from an MLWE-based group action. It has API functions and Make test targets. The root repository has no clear license file, its code is old architecture-specific C built around a Dilithium-era arithmetic implementation, and its tag is signer-stable rather than auction-scoped. It is therefore a *conditional prototype candidate*, not code to import before resolving licensing, platform/build, and context semantics.
2. **Raptor is a complete lattice-based linkable ring-signature prototype with a comparatively direct API.** It is based on NTRU/Falcon and a chameleon-hash/OTS-style linkability construction. The README explicitly calls it non-audited prototype code; it is GPL-3.0 and flags patent considerations. Its fixed parameter profile and linear ring scaling make it a poor default for a fresh C++17 production-oriented implementation.
3. **The ESORICS 2024 implementation is another full post-quantum LRS codebase**, based on signatures of knowledge and an ethSTARK/Winterfell-style proof framework. It is not lattice-based and is explicitly not production-ready. It may be the most direct alternate *PQ* codebase if the lattice requirement is relaxed, but it brings a Rust/STARK integration and security model change.
4. **LoTRS is not a complete substitute for this use case.** It is a structured threshold ring signature, with an Esgin-derived selection-hiding proof component. It is an unusually complete, well-tested artifact and the best source for proof implementation/testing patterns, but it has no WCM-style tag or ordinary single-signer linkability API.

For the current project, **Strategy E—keep the existing arithmetic/sampling/commitment foundation and implement only the missing Esgin proof/signature components—is the best preservation path**, provided the paper and parameter questions are resolved. If the objective shifts to a working LRS demonstration quickly, **evaluate Falafl in an isolated prototype first**, and compare it to Raptor; do not graft either scheme's proof into the Esgin code. A complete-scheme replacement changes the construction and needs a new parameter/security review. No candidate should be described as production-ready based on repository tests.

## Requirements and local baseline

The required user-facing properties are: anonymous signing by one key in a public eligible-bidder ring; verification against that ring; a repeatable tag for the same bidder within one auction; duplicate rejection only after signature verification; and separate auction linkability state, ideally without cross-auction correlation.

The existing local project already has:

- NTL/GMP polynomial and matrix arithmetic in `cpp_backend/include/lattice_lrs/arithmetic/` and `cpp_backend/src/arithmetic/`.
- Random-source and sampler code in `cpp_backend/include/lattice_lrs/sampling/` and `cpp_backend/src/sampling/`.
- An Esgin-style lattice commitment in `cpp_backend/include/lattice_lrs/commitment/commitment.hpp` and `cpp_backend/src/commitment/commitment.cpp`.
- Two separate official historical Dilithium checkouts and isolated API tests under `dilithium/upstream-round2/` and `dilithium/upstream-round3/`.
- A draft `cpp_backend/include/lattice_lrs/proofs/binary_proof.hpp`, but no completed binary proof source implementation; no completed one-out-of-many proof, base ring signature, WCM wrapper, or tag/link API was found.

The existing configured CTest run was recorded as 6/6 passing: smoke build, NTL/GMP integration, polynomial/matrix arithmetic, sampling/commitment, and independent Round 2 and Round 3 Dilithium API tests. This does not exercise any LRS protocol.

The N=64 Esgin design row is experimental. The production q has not been selected and the M-LWE/M-SIS security estimates remain unresolved. No candidate parameter set should be copied into this project just because it appears in another implementation.

## Whole-implementation candidates

| Candidate | Complete LRS? | PQ? | Linkable? | Main assumption/construction | Ring-size behavior | Source and test evidence | License / maturity | Project changes |
|---|---|---|---|---|---|---|---|---|
| **Falafl** ([paper](https://eprint.iacr.org/2020/646), [source](https://github.com/WardBeullens/Calamari-and-Falafl)) | Yes: source has separate linkable and unlinkable signing/verification APIs | Yes, lattice instantiation | Yes; paper defines tag-based LRS | MLWE/MSIS-based group action, OR proof | Logarithmic proof; code accepts ring sizes up to 2^32 and rounds proof tree to a power of two (source `rsign.c`, `lrsign.c`) | `lrsign.c/.h`, `rsign.c/.h`, `test.c`; README Make targets `test_lrs_lat`, `test_rs_lat`; not rebuilt in this audit | Research implementation. No root license found. README offers commands but no audited/production claim. | C integration or C++ wrapper; resolve license first; port platform-specific SIMD/assembly/dependencies; replace/parameter-review key and tag formats; define auction scope with new analysis. |
| **Raptor** ([paper](https://eprint.iacr.org/2018/857), [source](https://github.com/zhenfeizhang/raptor)) | Yes: base and linkable APIs | Yes | Yes, linkable variant | NTRU/Falcon-based ring signature plus chameleon-hash/Falcon-512 signing wrapper | Paper/code report ring-size-dependent linear costs; `param.h` has demo `NOU=50`; not an arbitrary scalable ring proof | `raptor.c`: `raptor_keygen/sign/verify`; `linkable_raptor.c`: `linkable_raptor_keygen/sign/verify`; `falcon/api.h` identifies Falcon-512; `test.c`; no standard portable build recipe verified | GPL-3.0; README calls it prototype/non-audited and lists patent/IP caveats | C or wrapper port; reconcile Falcon version/parameters and NTRU assumptions; audit side channels and wrapper flow; GPL compatibility and patent review; scope tags. |
| **ESORICS 2024 framework** ([paper](https://eprint.iacr.org/2024/553), [source](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature)) | Yes, research framework/examples for linkable signatures | Yes, hash/STARK security rather than lattice | Yes | Signatures of knowledge, ethSTARK/Winterfell AIR/FRI | Construction handles a statement/ring; practical ring-size limits and costs follow its proof encoding; do not infer arbitrary-size efficiency | Rust workspace; `examples/src/sigrescue/{prover,signature,air}.rs`, AIR/FRI/prover/verifier modules; Cargo workflow; not built here | Root LICENSE is MIT; README says not production-ready; review vendored/subcomponent notices. | Rust FFI or port; replaces lattice assumptions, proof and encoding; analyze context tag; project’s NTL/GMP/commitment become largely unused. |
| **LoTRS** ([paper](https://eprint.iacr.org/2026/974), [source](https://github.com/lotrs-sig/lotrs), [artifact](https://zenodo.org/records/22807126)) | It is a threshold ring signature; not the ordinary single-member LRS API requested | Yes | No WCM-style signer link tag | Lattice multisignature plus Esgin-derived selection-hiding proof | Structured threshold/table dimensions; own profile | Python `lotrs-py/lotrs.py` (`_sign_bin`, `verify`), Rust `lotrs-rs/src/lotrs.rs` (`sign_bin`, `verify_impl`), arithmetic/sample/codec modules and deterministic vectors; `make check` halted in this environment due missing crypto dependency | MIT; Rust crate MIT/Apache. Research artifact; not an audit certification. | Replacing entire protocol changes signer threshold semantics, commitment, moduli, FS, encoding and parameters; no WCM layer. Use as reference. |
| **Calamari** (same source/paper as Falafl) | Yes, separate isogeny instantiation | Yes, but not lattice-based | Yes | CSIDH/group action | Logarithmic | Same code family and test targets | Same root license uncertainty; research implementation | Not selected where a lattice assumption is required; different cryptographic foundation. |
| **DualRing** ([source](https://github.com/thyuen/dualring)) | Yes, basic ring signature | Yes | No | Distinct canonical-identification construction, M-LWE/M-SIS | Source’s demo rings small; no established arbitrary ring API guarantee | `lattice.py`: `RSetup`, `RkeyGen`, `RSign`, `RVerify`; script tests only basic sign/verify. Attempt stopped at missing PyCryptodome. | MIT; prototype, sparse tests | Would need a separate linkability protocol and full security/parameter review; not an Esgin replacement without changing design. |

The anonymity entries above refer to the ring-signature security goals/constructions stated in the associated papers, not to an independent proof of the checked code. LoTRS hides the selected signer/column under its structured threshold model; it is not equivalent to a conventional single-signer LRS API. Falafl and Calamari are distinct instantiations in one repository, with different hardness assumptions.

Falafl’s observed lattice parameters are tied to its included Dilithium-era implementation: `LatticeAction/params.h` sets `N=256`, `Q=8380417`; MODE 4 sets `K=6`, `L=5`, `ETA=3`. The LRS profile in root `parameters.h` uses `EXECUTIONS=1749` and `ZEROS=16`. These are Falafl’s own instantiation values, not values to transplant into the Esgin configuration. The paper calls its lattice instantiation MLWE/MSIS-based and reports using cSHAKE; neither the embedded arithmetic nor use of Dilithium-origin code makes this the WCM Dilithium OTS construction.

### Other relevant candidates

- **MatRiCT / MatRiCT+** ([2019/1287](https://eprint.iacr.org/2019/1287), [2021/545](https://eprint.iacr.org/2021/545)): RingCT systems with binary and one-out-of-many proof components in a different commitment/transaction relation. The inspected Go repository `GoldSaintEagle/RingCT_Implementation` contains `Matrict.go`, `Matric+.go`, `Matric+_plus.go`, `RingMatrix.go`; its README calls it toy code and warns about a LAGO polynomial multiplication bug/workaround. Go test failed before execution because `github.com/dedis/lago` packages were unavailable offline. No license file was found. Useful for proof ideas and witness-management contrasts, not reusable proof equations.
- **SPRING** (Ruiteng Zhang, Pingbin Luo, Qiong Huang; 2026 journal article, [DOI 10.1016/j.csi.2025.104084](https://doi.org/10.1016/j.csi.2025.104084)): a module-lattice sign-then-prove ring signature derived from SMILE, with a modular LNP/ZK proof layer and an accountable-ring-signature example. The article reports Lazer as its ZK instantiation and describes Gaussian-convolution optimizations. No author-hosted SPRING implementation repository was located in this audit; Lazer is a separate library, not the SPRING protocol implementation. Accountability/traceability is not the same as auction duplicate linkability. Treat it as a promising construction to evaluate, not a source-code reuse target.
- **SMILE** (Lyubashevsky, Nguyen, Seiler, CRYPTO 2021, [ePrint 2021/564](https://eprint.iacr.org/2021/564)): lattice set-membership proof and ring-signature transformation, not linkable by itself. A code artifact is included in [Valeh2012/voting-from-lattices](https://github.com/Valeh2012/voting-from-lattices), described as an academic proof of concept in the related e-voting paper ([Journal of Cryptology article](https://doi.org/10.1007/s00145-024-09530-5)). Its code is C and uses SHAKE challenges/COSAC sampling according to the paper; do not assume the voting-specific proof is a complete compatible LRS or that its license permits reuse. This is a separate candidate from the MatRiCT toy repository.
- **Lattice RingCT v2.0:** NewHope-style C implementation with `LRCT_Setup`, `LRCT_KeyGen`, `LRCT_SigGen`, `LRCT_SigVer`, `LRCT_Spend`, and `LRCT_Verify`. Degree/modulus profile differs; the inspected `ZKP_OR` body is empty and default harness does not exercise complete signature/tampering/linkability. Not a complete usable replacement.
- **LLRing:** classical discrete-log/pairing constructions with prefix tags. Not post-quantum; useful only as an application-level tag-scope design example.
- **Triptych:** Ristretto/discrete-log linkable proof; not post-quantum.
- **Lantern, ring-zk, LaBRADOR/Lazarus, LatticeFold and Akita:** proof-system, commitment, arithmetic or folding toolkits, not complete LRS implementations. Their protocols, assumptions and data formats cannot be combined with Esgin/WCM by importing a few functions.
- **Obscura-PQ:** the inspected checkout `dc707c4` lacks the `core/`, `contract/`, and `frontend/` source directories its README describes. Treat its claimed Ring-SIS LRS implementation as unverified until those sources and tests are available.
- **LUX `ring/lattice.go`:** source explicitly says the ring-signature anonymity/linkability construction is hash-based (SHA-512), and ML-DSA is used only as key material. Its custom Lux Ecosystem License 1.2 also restricts uses. It is not a lattice-hardness LRS.

## Actual source reuse and component analysis

| Component | Candidate and exact location | Mathematical relation/dependencies | Reuse decision |
|---|---|---|---|
| Complete linkable signing/verification | Falafl `lrsign.c/.h`: `lrsign`, `lrverify`; `lrsign.c` derives tag, salt, commitments, challenge, responses and Merkle paths | MLWE/MSIS group action using the repository’s Dilithium-derived lattice arithmetic, cSHAKE/SHAKE expansion, seed tree and challenge repetitions. Paper’s linkable scheme has `T=s_I ⋆ T_0`; code calls `derive_tag(tag,s)` and `do_tag_action`. Tag is deterministic from signer secret. | Best complete *lattice LRS prototype to evaluate*. Do not mix its proof code with Esgin. License, architecture, parameter/security profile and scoped-linkability requirement block direct import today. |
| Complete base ring signature | Falafl `rsign.c/.h`: `keygen`, `rsign`, `rverify` | Same group-action OR proof without link tag; binary challenges, repeated executions and hash commitments. | Complete base scheme but not Esgin’s commitment/one-out-of-many relation. |
| Raptor sign/verify | `raptor.c`, `linkable_raptor.c`, corresponding `raptor.h`; functions named above | NTRU/Falcon-512 signature plus chameleon-hash/Falcon signing wrapper; `falcon/api.h` identifies Falcon-512. Wrapper keygen hashes `ots_pk` into a mask for `data.h`; signing authenticates a serialized ring-signature structure plus OTS key with `crypto_sign`; verification checks base Raptor then calls Falcon `crypto_sign_open`. | Use only as a whole-scheme comparison after license/IP and source review. In `linkable_raptor.c`, the buffer copies for adjacent `int64_t[DIM]` vectors use byte offsets `+1`, `+2`, `+3` after a block base, causing overlapping fields. Treat this as a source-quality issue requiring maintainer clarification, not a validated integration target. Do not port its tag alone into Falafl or Esgin. |
| ESORICS 2024 proof | `examples/src/sigrescue/{prover,signature,air}.rs`, plus workspace `air`, `fri`, `prover`, `verifier` | STARK/AIR and Fiat–Shamir, not lattice commitments. Rust dependencies and Winterfell-derived modules. | Complete alternate experimental PQ architecture; combining its proof with Esgin arithmetic is mathematically inappropriate. |
| Esgin binary proof | Esgin §4 Protocol 1; LoTRS `lotrs-py/lotrs.py::_sign_bin`, `lotrs-rs/src/lotrs.rs::sign_bin` as comparison only | Esgin relation has committed one-hot/binary witnesses, `f=xb+a`, `g=f(x-f)`, commitment-response and exact norm/rejection checks. LoTRS uses its own relation, modulus profile, sparse challenge and proof integration. | Implement from Esgin specification. Reuse LoTRS control-flow, defensive parsing and test methodology only. |
| Esgin one-out-of-many proof | Esgin §5 Protocol 2; LoTRS selection-proof path | Esgin base-β one-hot index and its commitment algebra; LoTRS table-selection relation in threshold signature. MatRiCT has one-out-of-many relations for RingCT. | No exact code found. Keep equations and types local; references only. |
| Lattice commitment | Local `commitment.cpp`; ring-zk `src/commit.rs`; Akita PCS crates; LatticeFold Ajtai commitments | Different dimensions, ring, message spaces, distributions, commitment binding/hiding assumptions and opening proofs. | Retain local Esgin-specific commitment unless a mathematical defect is found. Generic commitment code is not plug-compatible. |
| Polynomial/matrix arithmetic | Local NTL/GMP modules; LoTRS Python/Rust ring modules; Falafl `LatticeAction/poly.c`, `polyvec.c`, `ntt.c` | Falafl profile is Dilithium-era `N=256`, `q=8380417` and fixed modes; LoTRS profile uses `d=128`, q and qhat; local code supports configurable q. | Retain local arithmetic for Esgin. Falafl can be built as a separate complete prototype but not silently use its arithmetic for the current q. |
| Rejection sampling | Esgin §2.3 Algorithm 1; LoTRS `lotrs-py/sample.py`, Rust `sample.rs`; Falafl `LatticeAction/rejsample.c` | Distribution, challenge, bounds and abort behavior are scheme-specific. SPRING claims Gaussian convolution to avoid rejection in its own design. | No drop-in sampler reuse. Implement exactly from selected construction and test distribution/bounds. |
| Fiat–Shamir/hash-to-challenge | LoTRS `sample.py`/`codec.py`, Rust `sample.rs`/`codec.rs`; Falafl `parameters.h` and `rsign.c/lrsign.c` | Domain separation, transcript object, challenge set and wire bytes differ. LoTRS uses sparse signed polynomial challenges; Falafl derives binary repetition challenges; Esgin uses its paper-defined challenge mapping. | Reuse transcript API/testing patterns only. Specify canonical serialization and challenge derivation from the selected paper. |
| OTS | WCM §3–4; Geometry Labs `lm_one_time_sigs.py`; Raptor’s OTS/chameleon-hash code | Geometry Labs OTS is not Dilithium/WCM. Raptor’s tag framework differs. Local Dilithium round sources have standalone signature APIs only. | No exact WCM+Dilithium integration code located. Resolve WCM’s paper inconsistencies and historical Dilithium variant before implementation. |
| Link tag | Falafl `derive_tag` macro/function in `lattice_BG_instantiation.h` and LRS `lrsign.c`; Raptor `linkable_raptor.c`; WCM paper | Falafl tag is derived from signer secret and public group-action context; Raptor tag uses its own link mechanism; WCM compares OTS verification keys. None is auction scoped by default. | Do not transplant tag generators across schemes. Per-auction cryptographic scope requires a specified protocol and security argument. |

### Compatibility matrix

| Pairing | Ring/dimension/modulus | Assumption and relation | Challenge/norm/encoding | Safe to combine directly? |
|---|---|---|---|---|
| Local Esgin foundation + Esgin proof to be implemented | Same project ring and commitment dimensions once q is reviewed | Intended match: Esgin Section 2–6 | Must still implement Esgin challenge, norm checks, rejection, and serialization | Yes by design, subject to resolving exact q/security/proof details. |
| Local Esgin + LoTRS proof source | Esgin’s configurable ring vs LoTRS `d=128`, `q=2^43−67`, `qhat=2^35−451` profile | Related proof lineage, but threshold/table relation and commitments differ | Esgin monomial challenge vs LoTRS sparse signed challenge; different bounds/codecs | **No.** Use as reference, not code-level combination. |
| Local Esgin + Falafl components | Esgin target d=256, provisional ~50-bit q vs Falafl’s Dilithium-derived N=256, q=8380417 and mode parameters | Esgin Module-LWE/Module-SIS commitments vs Falafl MLWE/MSIS group action | Different secret/witness, group action, challenge repetitions, rejection bounds and signature wire format | **No component transplant.** Could replace the entire LRS construction with Falafl after review. |
| Falafl + its included Dilithium-derived arithmetic | Same repository profile | Arithmetic is intentionally part of Falafl’s own MLWE group-action instantiation | Its own packing, NTT, cSHAKE and rejection | Internally coupled; possible isolated whole-scheme build, not compatible with local Round 2/3 APIs by assumption. |
| Raptor + WCM OTS | NTRU/Falcon system vs Esgin/WCM’s base ring signature and historical OTS assumptions | Distinct chameleon hash/OTS linkability construction | Different keys, hash transcript, signature encoding and tag rule | No. Would be a new construction with new proof/security analysis. |
| ESORICS 2024 + local lattice backend | STARK/AIR over hash-based assumptions vs module-lattice commitment backend | Distinct security foundation and proof language | Rust/Winterfell transcript and AIR encodings | No component-level cryptographic combination; whole-system replacement only. |
| MatRiCT / SMILE / ring-zk / LatticeFold + Esgin | Different module/ring and statement shapes | Related ZK, commitment or set-membership ideas, not identical relation | Different challenge distributions, Gaussian/rejection bounds and serialization | No direct combination; conceptual reference only. |

## Auction-specific linkability

### Which candidate supports it natively?

Falafl, Raptor, and ESORICS 2024 describe linkable signature variants. Their linkability semantics are construction-specific. In Falafl, `lrsign` computes a deterministic tag from the signing secret in `derive_tag`; repeated use makes the tag stable and thus publicly correlatable. The observed function is not passed an auction identifier. Raptor’s linkable layer has its own tag/chameleon-hash semantics. The ESORICS implementation needs a separate protocol-level inspection before claiming exact scoped-tag behavior. None of these inspected sources establishes the required combination “same bidder linkable within each auction, unlinkable across auctions.”

WCM 2019/371 uses the OTS verification key `ovk` as the stable link value: reuse makes signatures linkable; new OTS keys per submission remove that equality and therefore defeat repeated-submission detection. Reuse across auctions exposes a stable public equality. Application state keyed by auction ID scopes a duplicate set but cannot hide that public tag correlation.

### What would context scoping require?

Using `auction_id` in a hash/key derivation or tag relation changes key generation, signing, verification and Link semantics. The original WCM proof does not establish a context-scoped variant. Any such design must define at minimum:

- canonical, unambiguous auction-context encoding and domain separation;
- how the tag is bound to the signer secret without revealing the signer;
- how a verifier proves tag/key consistency while checking the ring signature;
- which keys are long-lived, per-auction, or per-signature;
- within-auction linkability and cross-auction unlinkability games;
- chosen-ring and chosen-context attacks, tag collisions and replay behavior.

This is a new security requirement, not a harmless hash tweak. Preserve verify-before-link in the harness: verify the full signature against the exact auction ring and message first, then check the verified tag in that auction’s state.

## Strategy comparison

Estimates are qualitative engineering assessments (Low/Medium/High), not measured person-days or security metrics.

| Strategy | Reusable code | New code | Porting difficulty | Integration complexity | Security-analysis effort | Build/test effort | Fit with current project |
|---|---|---|---|---|---|---|---|
| **A. Reuse one complete PQ-LRS** | High if Falafl/Raptor/ESORICS chosen | Low for a wrapper; medium/high for auction context | Medium–High (C/old SIMD or Rust/STARK) | Medium | High: validate third-party construction, exact parameters, tag scope and source quality | Medium–High; dependencies and target architectures | Low–Medium; most local Esgin foundation becomes unused |
| **B. Reuse a complete ring signature and adapt its linkability layer** | Medium–High (e.g. a base RS) | Medium–High: prove tag-binding and link security | High | High | Very high: changing linkability transformation changes the security game/proof | High | Low; no candidate has a compatible base relation and WCM layer ready |
| **C. Reuse an existing linkable RS and adapt its cryptographic foundation** | Medium (whole Falafl/Raptor code) | High if changing the underlying assumption/key system | Very High | Very High | Very high: cannot swap arithmetic/keys and retain original proof | Very High | Low. Replace whole scheme instead of changing its foundation in place. |
| **D. Combine proof components from multiple implementations** | Some arithmetic/testing patterns | High | High | Very High | Highest: hybrid proof has no inherited security theorem | Very High | Very low. Component relations, challenge sets, distributions and codecs are incompatible. |
| **E. Keep local arithmetic/commitment and implement missing Esgin components** | Existing arithmetic/sampler/commitment and Dilithium tests | High: binary proof, one-out-of-many, base LRS, WCM/OTS, tag | Medium | Medium–High | High, but tractable as a single construction if parameter and paper issues resolve | High and incremental | Highest; preserves work and intended construction |

## Ranked recommendation

### 1. Best fit while preserving current project: Strategy E

Keep the current arithmetic, sampler, commitment and isolated Dilithium tests. Implement the missing Esgin modules as a coherent protocol, not as a mix of external proof code. This minimizes rewrite and maintains a single mathematical relation. Its drawback is substantial implementation and validation effort, and Esgin/WCM’s remaining parameter/specification questions must be resolved first.

### 2. Best whole-scheme candidate for a short lattice-LRS prototype: Falafl, conditional

Falafl offers actual linkable and unlinkable APIs, lattice assumptions, logarithmic ring-size behavior and documented C tests. Before selecting it, confirm source licensing with maintainers, obtain a reproducible build on current Apple Silicon/macOS, audit the exact parameter profile and tag relation, and decide whether public cross-auction tag equality is acceptable. It is the best complete implementation candidate found for a *lattice LRS prototype*, not a ready production foundation.

### 3. Best alternative complete linkable lattice prototype: Raptor

Raptor has clear `linkable_raptor_*` APIs and a complete implementation. It is useful as an alternate benchmark or if its NTRU/Falcon construction is preferred. GPL-3.0, explicit non-audited status, patent notes, fixed demonstration profile and source age make it less attractive than Falafl absent a project-specific reason.

### 4. If the project allows a non-lattice PQ construction: ESORICS 2024

This could provide a complete PQ LRS framework, but it changes the cryptographic foundation to a STARK/hash-based SoK and Rust. It is not a component-level replacement for the current code. Confirm license, example completeness, ring scaling, and tag semantics before even a prototype fork.

### Not recommended as a direct base

- LoTRS: threshold semantics and no WCM tag; use as the strongest implementation/test reference for proof engineering.
- DualRing: complete but unrelated relation and lacks linkability.
- MatRiCT, SMILE, SPRING, ring-zk, Lantern and proof toolkits: valuable source/paper material, but not a complete compatible linkable scheme or drop-in proof component.
- Mixing proof equations from multiple repositories: avoid; it has the greatest unproven security and integration burden.

## Licensing, patents and supply-chain notes

| Candidate | License/reuse warning |
|---|---|
| Falafl / Calamari | No root LICENSE was found in the inspected checkout. Do not copy or distribute code until license is clarified. Bundled XKCP/Dilithium-derived files can have distinct notices; audit each subtree. |
| Raptor | GPL-3.0 and README patent/IP discussion. GPL obligations and any patent permission need project/legal review before adoption. |
| LoTRS | MIT root; Rust `MIT OR Apache-2.0`; preserve notices if later used. |
| ESORICS 2024 | Root LICENSE is MIT. Review vendored Winterfell/subcomponent notices. README says prototype/not production. |
| MatRiCT toy code | No license file located in checked repository; no reuse until permission is clear. |
| SPRING | No standalone implementation located, so no implementation license assessed. Lazer’s license does not automatically license SPRING protocol code. |
| SMILE/e-voting artifact | Inspect each source subtree license; research artifact warns it is not production-ready. |
| LUX crypto | Lux Ecosystem License 1.2 is not a permissive open-source grant for general commercial reuse; source itself disclaims lattice-based anonymity security. |

This is a technical audit, not legal advice. Keep third-party notices and provenance if adoption is later approved; perform patent and license review before copying or shipping code.

## Step-by-step roadmap

### Path 1 — continue existing Esgin/WCM design

1. Resolve the exact Esgin parameter row, production modulus candidate and structured M-LWE/M-SIS estimates. Keep security claims separate from protocol soundness.
2. Obtain authoritative clarification of WCM’s concrete `H`/`H'` type use, OTS-signed message and OTS key lifecycle. Do not silently correct the paper.
3. Write a reviewed equation-to-type specification for Esgin Protocol 1 and Protocol 2, including all distributions, bounds, rejection calls, challenge spaces and transcript bytes.
4. Implement the Esgin binary proof as a standalone prover/verifier using the local commitment and arithmetic APIs; test valid witnesses, malformed transcripts, tampering, bounds and deterministic fixtures.
5. Implement and test the one-out-of-many proof; then implement Esgin RSetup/RKeygen/RSign/RVerify and only then benchmark ring sizes.
6. Integrate the reviewed WCM OTS transformation with the historically correct Dilithium API. Keep upstream source isolated and do not treat ordinary Dilithium tests as WCM tests.
7. Specify auction-scoped linkability as a separate cryptographic property; obtain a security review before introducing context-dependent tag derivation.
8. Add a minimal harness that verifies signatures before auction-local duplicate checks. Test cross-auction link behavior explicitly.

### Path 2 — evaluate Falafl as a replacement candidate

1. Ask maintainers for an explicit license grant or find an authoritative license statement; inspect notices in `LatticeAction/` and `XKCP/` separately.
2. Build and run `make test_lrs_lat` in a disposable copy on supported hardware/toolchain; capture compiler flags and dependencies. Do not alter upstream files to make it build.
3. Read the Falafl paper’s security game, exact lattice-group-action relation, link algorithm and parameter analysis; independently review the current source’s tag and verification flow.
4. Assess whether one stable tag across auctions is acceptable. If not, design and prove a scoped-tag variant before modifying code.
5. Prototype as an isolated alternative executable/library with its own serialized types and tests. Compare correctness, signature size, performance, ring-size support and auditability against Esgin path.
6. Decide on full replacement only after parameter security, source quality, license and application link semantics are reviewed. Do not mix Falafl internals into the Esgin commitment/proof layer.

## Open questions / go-no-go conditions

- What is the approved target: exact Esgin + WCM, or any PQ LRS meeting application semantics?
- Is a lattice hardness assumption mandatory, or is the ESORICS 2024 STARK-based LRS acceptable?
- Can Falafl be used under a clear license, and can its older build be reproduced on supported target hardware?
- Is public same-bidder correlation across auctions acceptable? If not, which formal scoped-linkability/unlinkability definition is required?
- Which Dilithium historical variant does WCM require, and how are one-time OTS keys safely consumed across multiple bids?
- What production parameter/security target is approved? The current approximate q and 128-bit claim remain unverified.
- Is the team able to fund independent cryptographic review and a side-channel/build audit for any research implementation?

## Final decision table

| Question | Finding |
|---|---|
| Closest complete lattice PQ-LRS source? | Falafl, conditionally; actual linkable C code and test targets exist, but root license and modern build/review status are blockers. |
| Most direct alternative with a simple linkable API? | Raptor’s `linkable_raptor_keygen/sign/verify`, but GPL-3.0, non-audited prototype, NTRU/Falcon profile and patent concerns. |
| Strongest codebase for proof implementation patterns? | LoTRS artifact, but it is threshold and not WCM-linkable. |
| Exact WCM + Dilithium source found? | No. |
| Can external proof modules be safely mixed? | No, absent a proof that witness relation, commitment, challenge, distributions, bounds, transcript and soundness theorem all match. |
| Best current-project strategy? | Retain arithmetic/sampling/commitment and implement the missing Esgin pieces after specification/parameter review. |
| Best replacement path if speed of prototype dominates? | Isolated Falafl evaluation first; compare Raptor and ESORICS 2024 if the assumption family may change. No production adoption yet. |
| Ready to implement auction-scoped link tags? | No. Existing constructions do not establish cross-auction unlinkability; a scoped variant requires a formal definition and new security analysis. |

**Conclusion:** Do not force Esgin + WCM solely because work has started, but do not replace it with a codebase that fails licensing, parameter, context or audit requirements. The rational next decision is a short isolated Falafl feasibility review alongside resolution of Esgin/WCM specification questions. Preserve all current local components until that comparison is complete.

## Sources

- Esgin et al., [ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [ePrint 2019/371](https://eprint.iacr.org/2019/371).
- Raptor, [ePrint 2018/857](https://eprint.iacr.org/2018/857), [source](https://github.com/zhenfeizhang/raptor).
- Calamari/Falafl, [ePrint 2020/646](https://eprint.iacr.org/2020/646), [source](https://github.com/WardBeullens/Calamari-and-Falafl).
- ESORICS 2024 LRS, [ePrint 2024/553](https://eprint.iacr.org/2024/553), [source](https://github.com/yuxi16/Post-Quantum-Linkable-Ring-Signature).
- LoTRS, [ePrint 2026/974](https://eprint.iacr.org/2026/974), [source](https://github.com/lotrs-sig/lotrs), [artifact](https://zenodo.org/records/22807126).
- DualRing, [source](https://github.com/thyuen/dualring), [ePrint 2021/1213](https://eprint.iacr.org/2021/1213).
- MatRiCT, [ePrint 2019/1287](https://eprint.iacr.org/2019/1287); MatRiCT+, [ePrint 2021/545](https://eprint.iacr.org/2021/545); [toy code](https://github.com/GoldSaintEagle/RingCT_Implementation).
- SMILE, [ePrint 2021/564](https://eprint.iacr.org/2021/564), [voting artifact](https://github.com/Valeh2012/voting-from-lattices).
- SPRING, Zhang, Luo and Huang, [DOI 10.1016/j.csi.2025.104084](https://doi.org/10.1016/j.csi.2025.104084).
- Existing local audits: [`EXTERNAL_REPOSITORY_AUDIT.md`](EXTERNAL_REPOSITORY_AUDIT.md), [`EXTENDED_PQ_LRS_RESEARCH.md`](EXTENDED_PQ_LRS_RESEARCH.md), [`PHASE3_RING_SIGNATURE_DESIGN.md`](PHASE3_RING_SIGNATURE_DESIGN.md), [`DILITHIUM_IMPLEMENTATIONS.md`](DILITHIUM_IMPLEMENTATIONS.md).
