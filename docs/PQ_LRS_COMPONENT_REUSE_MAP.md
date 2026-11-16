# PQ-LRS Component Reuse Map

**Status:** source discovery and compatibility review complete for the named candidates; no external code is approved for import. The map was written before project implementation changes. During that external-source audit, no C++, header, CMake, parameter, dependency, or upstream Dilithium files were changed. A subsequent local Esgin Protocol 1 implementation is now recorded below. External checkouts and the extracted archive remain under `/private/tmp`, outside `Lattice_LRS`.

## Classifications

- **EXACT REUSE:** same algorithm and compatible parameter/data model. None found for Esgin + WCM.
- **ADAPTABLE REUSE:** same mathematical component, with bounded, reviewable changes required.
- **ENGINEERING REUSE:** coding/test/API patterns only; not cryptographic substitution.
- **NOT REUSABLE:** different statement, assumption, primitive, or relation.
- **NOT VERIFIED:** code absent or not enough evidence to establish behavior.

`ER`, `AR`, `ENG`, `NR`, and `NV` in the matrix abbreviate these classifications. “No source” means no implementation was found in the inspected checkout. Test success or buildability is not a security assertion.

## Local baseline inspected

| Section | Existing local source / API | State |
|---|---|---|
| Polynomial arithmetic | `cpp_backend/include/lattice_lrs/arithmetic/polynomial.hpp`: `Polynomial::{operator+,operator-,operator*,centered_coefficient}`; `cpp_backend/src/arithmetic/polynomial.cpp` | Implemented for configurable `Z_q[X]/(X^d+1)` using NTL; no field inversion assumption. |
| Matrix arithmetic | `cpp_backend/include/lattice_lrs/arithmetic/matrix.hpp`: `Matrix::{operator+,operator-,operator*}`; matching `src/arithmetic/matrix.cpp` | Implemented for dense polynomial matrices/vectors. |
| Sampling | `sampling/random_source.hpp`, `sampling/sampler.hpp` and matching `.cpp` files | OS-backed byte source, unbiased uniform coefficient sampler, bounded sampler, polynomial/vector/matrix sampling. Gaussian distributions used by proofs are not yet implemented. |
| Commitment | `commitment/commitment.hpp/.cpp`: `CKeygen`, `Com`, `Commit`, `Open` | Esgin-inspired Section 2.2 module; configurable q and relaxed `Com_ck(message; randomness)=y*C`. Functional tests do not prove hiding/binding. |
| Binary proof | `proofs/binary_proof.hpp/.cpp`: `BeginBinaryProof`, `RespondBinaryProof`, `VerifyBinaryProof`, monomial challenge mapping/sampling | Protocol 1 core and equations implemented. Gaussian, Bernoulli-exponential, and auxiliary-commitment providers remain injectable interfaces with no production implementations; tests use test-only fixtures. |
| Dilithium OTS | `dilithium/upstream-round2/ref/` and `dilithium/upstream-round3/ref/`, isolated CMake test targets | Standalone upstream APIs only; no WCM wrapper or tag. Round 2 Mode 4 and Round 3 Mode 5 tests are distinct. |

Current local CTest result: 7/7 pass, including `binary_proof_test`. This test uses deterministic test-only Gaussian/Bernoulli/auxiliary providers. Protocol 2, full Esgin LRS, WCM, tag, and auction tests are not registered. q and lattice security estimates remain provisional/unresolved.

## 13-section candidate matrix

| Candidate (checked source) | 1 Poly | 2 Matrix | 3 Sampling | 4 Commitment | 5 Binary | 6 One-out-of-many | 7 FS | 8 Base RS | 9 Dilithium OTS | 10 WCM transform | 11 Link tag | 12 Final API | 13 Harness |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `wang-0218/ring-signature` (zip at `05bef95d8db96c0aebc68a680d9a5884ae2c0235`) | ENG | NR | NR | NR | NR | NR | ENG | NV | NR | NR | NV | NV | NR |
| `Sobieg/L2RS` (archived C source, `a5c5a99036d1c802c9767850aa51ca6f4b5e17aa`) | ENG | ENG | ENG | NR | NR | NV | ENG | NV | NR | NR | NV | NV | NV |
| Raptor (`raptor.c`, `linkable_raptor.c`) | ENG | NR | ENG | NR | NR | NR | ENG | NR | NR | NR | ENG | ENG | ENG |
| Calamari/Falafl (`lrsign.c`, `rsign.c`, lattice action) | ENG | ENG | ENG | NR | ENG | NR | ENG | NR | NR | NR | ENG | ENG | ENG |
| ESORICS 2024 (`examples/src/sigrescue/`, AIR/FRI workspace) | NR | NR | NR | NR | NR | NR | ENG | NR | NR | NR | ENG | ENG | ENG |
| LoTRS (`lotrs-py/lotrs.py`, `lotrs-rs/src/lotrs.rs`) | ENG | ENG | ENG | NR | ENG | ENG | ENG | NR | NR | NR | NR | NR | ENG |
| DualRing (`lattice.py`, `ecc.py`) | ENG | ENG | ENG | NR | NR | NR | ENG | NR | NR | NR | NR | ENG | ENG |
| LLRing (`TagDL.java`, `TagP.java`, Java scheme sources) | NR | NR | NR | NR | NR | NR | ENG | NR | NR | NR | ENG | NR | ENG |
| MatRiCT toy (`Matrict.go`, `Matric+.go`, `RingMatrix.go`) | ENG | ENG | ENG | ENG | ENG | ENG | ENG | NR | NR | NR | ENG | ENG | ENG |
| Hcash RingCT (tracked README only) | NV | NV | NV | NV | NV | NV | NV | NV | NV | NV | NV | NV | NV |
| Lattice RingCT v2.0 (`ring.c`, `ring.h`; separate from `Sobieg/L2RS`) | ENG | ENG | ENG | ENG | NV | NV | ENG | NV | NR | NR | ENG | NV | NV |
| Lantern (`ring_signature.sage`, proof examples) | ENG | ENG | ENG | ENG | ENG | ENG | ENG | ENG | NR | NR | NR | ENG | ENG |
| ring-zk (`src/commit.rs`, `src/prove/*`) | ENG | ENG | ENG | ENG | ENG | NR | ENG | NR | NR | NR | NR | NR | ENG |
| Geometry Labs (`lm_one_time_sigs.py`) | NR | NR | ENG | NR | NR | NR | ENG | NR | ENG | NR | NR | NR | ENG |

The matrix indicates only that a repository contains code of a broadly related category. The detailed mapping below explains why none of those labels authorizes combining it with local Esgin code. In particular, all external entries in columns 4–6 are non-exact for the local Esgin commitment/proof relations.

## Candidate source, algorithm, dependencies, license and integration notes

### 1. `wang-0218/ring-signature`

- **Snapshot:** branch `main`, commit `05bef95d8db96c0aebc68a680d9a5884ae2c0235`; one tracked file, `MyNtruSignature.zip`; GitHub reports one commit, no releases and no forks in the inspected repository view. No repository or archive-root license was present.
- **Paper identified:** Qing Ye, Mengyao Wang, Hui Meng, Feifei Xia, Xixi Yan, “Efficient Linkable Ring Signature Scheme over NTRU Lattice with Unconditional Anonymity,” 2022, DOI [10.1155/2022/8431874](https://doi.org/10.1155/2022/8431874). The paper’s data-availability statement points to this repository.
- **Extracted files:** `MyNtruSignature/{NtruGroupSignature.py,NtruVrfy.py,KegGen.py,Polynomial.py,R.py,fftPolynomialMult.py,test.py,hsnf/*}` plus a separate `zk-master/` Sudoku project and Python bytecode. No requirements/build manifest for the LRS code.
- **Functions observed:** `NtruGroupSignature.py::HashFun`, `NtruGrouSi`; `NtruVrfy.py::GroupSVrfy`; `KegGen.py::NTRUEncKegGen`, `NTRUSinKegGen`, `NtruGroupGen`; polynomial helpers in `Polynomial.py` (`Add`, `PoyMod`, `Multiplication`, `Multiplication2`, `Division`, `Invser`).
- **Math / status:** NTRU-lattice LRS is the associated paper claim. The extracted implementation is not a faithful, complete runnable verifier as checked: `NtruGrouSi` does not use `gn_sk` or a signer index to form a one-member witness; verification comparisons are commented out in both signer/verifier paths; `GroupSVrfy` returns no acceptance result. Randomness uses Python `random`/NumPy rather than an OS CSPRNG. Hash-to-vector code hashes Python string representations, not canonical encoding. `test.py` is a plotting/number-theory script, not an LRS test suite. No Esgin or WCM construction is present.
- **Reuse decision:** polynomial helpers are at most ENGINEERING and inferior to local NTL arithmetic; sampler, commitment, proof, OTS and link components are NOT REUSABLE. Claimed whole LRS is NOT VERIFIED by this source. Cannot be ported safely as a cryptographic module.

### 2. `Sobieg/L2RS`

- **Snapshot:** archived GitHub repository, branch `main`, commit `a5c5a99036d1c802c9767850aa51ca6f4b5e17aa`. Full history was fetched into the temporary checkout: six commits (`Initial commit` through `Little update.`). GitHub shows archive/read-only, zero forks and no releases. No README citation or license file in the checkout.
- **Construction identity:** name/implementation comments point to lattice RingCT/L2RS. The historical L2RS family is a BLISS extension in Torres et al. (2018/379); however the repository does not identify a precise source paper/revision, so its exact paper-to-code relation remains **UNVERIFIED**. It is a different construction from Esgin + WCM.
- **Files/functions:** `L2RS.c/.h` (`L2RS_setup`, `L2RS_keyGen`, `L2RS_lift`, `L2RS_sigGen`, declaration `L2RS_sigVer`); `poly.c/.h`, `matrix.c/.h`, `ntt.c/.h`, `sampler.c/.h`, `entropy.c/.h`, `sha3.c/.h`, `params.h`, `main.c`.
- **Observed profile:** current `params.h` sets `RINGCT_N=4`, `RINGCT_M=2`, `RINGCT_Q=1767374849`, `RINGCT_2Q=3534749698`, `RINGCT_LAM=100`, `RINGCT_SIGMA=283754` with comments retaining another illustrative parameter block. These are toy/rework constants, not transferable. `CMakeLists.txt` requests C23 and creates only a demo executable; no CTest tests.
- **Implementation status:** `L2RS_sigGen` is pseudocode-heavy and stops after allocating/lifting values and sampling; comments explicitly say rejection sampling “should use” and the routine has no completed signature output. `L2RS_sigVer` is declared but no definition was found. `main.c` comments out the verification call and passes `NULL` for the sampler to `L2RS_sigGen`. It builds under Apple Clang 21, with warnings including integer overflow in `poly.c`; executing the built demo exited 139 (segmentation fault). No signature correctness is demonstrated.
- **Reuse decision:** polynomial/matrix/NTT and Gaussian sampler code are ENGINEERING only. They use a different parameter profile, custom representation and sampler distribution; local NTL arithmetic is preferable. No exact commitment, Esgin binary proof, Esgin selection proof, complete signer, verifier, or tested tag is reusable. No license means no copying until clarified.

### 3. Raptor

- **Sources:** `raptor.c`, `linkable_raptor.c`, `raptor.h`, `param.h`, Falcon subdirectory. Functions include `raptor_keygen`, `raptor_sign`, `raptor_verify`, `linkable_raptor_keygen`, `linkable_raptor_sign`, `linkable_raptor_verify`.
- **Construction:** NTRU/Falcon ring signature with a distinct chameleon-hash / Falcon signing linkability wrapper, not WCM or Esgin. `linkable_raptor.c` derives a mask from `SHA512(ots_pk)`, modifies the base public relation, signs the serialized signature/ring data plus OTS public key using included Falcon `crypto_sign`, then verifies both base ring signature and Falcon signature. `falcon/api.h` identifies Falcon-512. `param.h`: `DIM=512`, `PARAM_Q=12289`, `NOU=50` demonstration profile.
- **Dependencies/license:** C, embedded Falcon sources, SHA-512/Salsa20-related RNG; GPL-3.0. README calls it non-audited prototype and includes patent/IP caveats. Eclipse project/make artifacts exist but no portable supported build recipe was verified.
- **Decision:** whole-scheme REFERENCE/ENGINEERING only; adapting the OTS or link tag alone would change security relations. Source review also found apparent byte-offset overlap in `linkable_raptor.c` message-buffer copies (`+1/+2/+3` bytes for full adjacent `int64_t[DIM]` vectors); clarify with maintainer before any use.

### 4. Calamari and Falafl

- **Sources/functions:** root `lrsign.c/.h` (`lrsign`, `lrverify`) and `rsign.c/.h` (`keygen`, `rsign`, `rverify`); `lattice_BG_instantiation.h`; `LatticeAction/{poly,polyvec,ntt,rejsample,rng,symmetric}.*`; `parameters.h`; `test.c`.
- **Construction:** group-action OR sigma proof. Falafl is the MLWE/MSIS-based lattice instantiation; Calamari is CSIDH/isogeny-based. The paper gives a linkable variant with tag relation `T=s_I ⋆ T_0`; source derives a deterministic tag via `derive_tag` and uses `do_tag_action`. The lattice action borrows Dilithium-era arithmetic but does **not** use Dilithium as WCM OTS. Root profile includes `N=256`, `Q=8380417`, `K=6`, `L=5`, `ETA=3`, `EXECUTIONS=1749`, `ZEROS=16`; this is not the Esgin profile. Ring support is logarithmic in proof size and source accepts ring size up to 2^32, padding the proof tree.
- **Dependencies/tests/license:** C, GMP, OpenSSL RAND, XKCP Keccak/cSHAKE; Make targets `test_rs_iso`, `test_lrs_iso`, `test_rs_lat`, `test_lrs_lat`. Not built here. No root LICENSE observed; audit licenses/notices in bundled subtrees before any copying.
- **Decision:** complete alternative LRS candidate; ENGINEERING as a separate whole-scheme prototype, NOT REUSABLE as partial Esgin proof/commitment. Link tag has no auction context input and so does not supply cross-auction unlinkability.

### 5. ESORICS 2024 PQ LRS

- **Source:** Rust workspace; `examples/src/sigrescue/{prover,signature,air}.rs` plus AIR/FRI/prover/verifier modules. The repo implements the ESORICS 2024 signatures-of-knowledge / ethSTARK framework. README says not production-ready. Root LICENSE is MIT; inspect vendored notices. Cargo workflow documented; Cargo unavailable during prior audit.
- **Decision:** complete experimental PQ LRS framework, but hash/STARK-based rather than lattice-based. No Esgin commitment, NTT, Module-LWE proof, Dilithium OTS or WCM transformation. A whole-system alternative only.

### 6. LoTRS

- **Sources/functions:** `lotrs-py/lotrs.py` (`setup`, `keygen`, signing/aggregation, `verify`, `_sign_bin`); `lotrs-py/{ring,sample,codec}.py`; Rust `lotrs-rs/src/lotrs.rs` (`sign_bin`, `verify_impl`) and corresponding ring/sample/codec modules; deterministic vectors and Python/Rust interoperability tests.
- **Construction:** structured threshold ring signature combining lattice multisignature with selection hiding. Its paper says the selection proof arises from Esgin’s one-out-of-many proof; deployed code integrates a different table/threshold relation. Uses own `d=128`, `q=2^43−67`, `qhat=2^35−451` profile, sparse challenge, Gaussian/rejection, encoding and transcripts. MIT (Rust crate MIT/Apache). Build/check attempted earlier and halted on missing PyCryptodome before the suite.
- **Decision:** strongest engineering reference for proof flow, validation, codecs and cross-language tests. Not an exact Esgin Protocol 1/2 implementation, not a standard single-signer LRS, and no OTS/WCM tag. No proof-source import.

### 7. DualRing

- **Sources/functions:** `lattice.py` (`RSetup`, `RkeyGen`, `RSign`, `RVerify`, matrix/polynomial helpers), `ecc.py`; Python, MIT. Uses its own M-LWE/M-SIS canonical-identification ring signature, SHA-256 challenge and small demonstration parameters. Basic script-level sign/verify; no link tag or Esgin proof. Test attempt previously stopped on missing PyCryptodome.
- **Decision:** ENGINEERING/REFERENCE for a different base ring signature only; cannot graft linkability without a new construction and proof.

### 8. LLRing

- **Sources:** Java `TagDL.java`, `TagP.java`, DL/pairing schemes. GPL-3.0; BouncyCastle/Maven dependencies. Classical discrete-log/pairing tags; not PQ. Compile attempt failed on missing BouncyCastle Keccak classes.
- **Decision:** tag API/context concept only; cryptographic modules NOT REUSABLE.

### 9. MatRiCT

- **Sources:** Go `Matrict.go`, `Matric+.go`, `Matric+_plus.go`, `RingMatrix.go`; depends on `github.com/dedis/lago`; no license found. Toy project README explicitly cautions against production use and describes a polynomial multiplication workaround. RingCT proof statements and one-out-of-many components are not Esgin’s relation. Go test stopped before execution because dependency unavailable offline.
- **Decision:** proof engineering/reference only; no equations or modules can safely be substituted.

### 10. Hcash RingCT

- Checked Git tree contains only README. Implementation, tests, license, assumptions and algorithm behavior are NOT VERIFIED. No code to reuse.

### 11. Other repositories reviewed in earlier audits

| Candidate | Exact source observed | Classification / reason |
|---|---|---|
| Lattice RingCT v2.0 (`chainchip/Lattice-RingCT-v2.0`) | C `ring.c/.h`: `LRCT_Setup`, `LRCT_KeyGen`, `LRCT_SigGen`, `LRCT_SigVer`, `LRCT_Spend`, `LRCT_Verify`; empty `ZKP_OR`; default harness tests commitment only | ENGINEERING/NOT VERIFIED; NewHope degree 512 / q 12289, different relation; paper/README license status needs review. |
| Lantern | Sage `ring_signature.sage`, `group_signature.sage` and LNP examples | ENGINEERING; educational lattice ZK, not linkable Esgin/WCM; no explicit license located. |
| ring-zk | Rust `src/commit.rs`, `src/params.rs`, `src/prove/{open,linear,sum}.rs` | ENGINEERING; RLWE commitment proofs, not the Esgin module commitment/proof. MIT. |
| Geometry Labs | Python `lm_one_time_sigs.py`, `bklm_one_time_agg_sigs.py` | ENGINEERING for generic OTS only; not Dilithium/WCM. MIT. |
| Triptych | Rust `src/{proof,statement,transcript,witness}.rs` | NOT REUSABLE; Ristretto/discrete-log linkability. |
| LaBRADOR/Lazarus/Lattirust/LatticeFold/Akita/lattice-zksnark | Their arithmetic, commitment and lattice-ZK crates | ENGINEERING/reference; distinct proof relations, dimensions, languages and assumptions; no integrated Esgin/WCM LRS. |
| Obscura-PQ | README describes Ring-SIS AOS; checked checkout omits `core/`, `contract/`, `frontend/` it describes | NOT VERIFIED; no source implementation available for reuse. |

## Module-by-module selection

| Local section | Best existing source to retain/use | Classification | Modification needed | Preserves Esgin + WCM? | Still to implement |
|---|---|---|---|---|---|
| 1. Polynomial arithmetic | Local NTL `Polynomial` | Existing; no external reuse | None based on this audit | Yes, if paper’s ring/modulus are obeyed | Property tests/parameter checks already exist; later optimize only with proof-compatible backend. |
| 2. Matrix arithmetic | Local NTL `Matrix` | Existing | None | Yes | Additional vector/matrix helpers only when a paper equation requires them. |
| 3. Sampling | Local OS source and bounded/uniform sampler | Existing; external Gaussian sources only ENG | Implement paper-specified Gaussian and rejection providers with exact distributions only after parameter choices | Yes if exact distributions are used | Esgin Gaussian/Algorithm 1 implementation and statistical validation. |
| 4. Commitment | Local Section 2.2 `CKeygen/Com/Commit/Open` | Existing | Do not replace; re-audit dimensions/security bound when parameters are finalized | Yes, intended | Independent mathematical review; prove/validate operational bounds. |
| 5. Binary proof | Local Esgin §4 Protocol 1 core; LoTRS only as reference | Protocol equations implemented behind provider interfaces | No third-party proof imported; production samplers and `aCom` still need reviewed implementations | Yes by intended equations; production fidelity awaits provider review | Independently validate exact distributions, serialization/lifts, and parameter/security profile. |
| 6. One-out-of-many | Esgin §5 Protocol 2; LoTRS/MatRiCT as reference | Original implementation required | None can be ported directly | Yes only if exact Esgin relation is implemented | Complete selection prover/verifier and bounds/abort handling. |
| 7. Fiat–Shamir | Esgin §6 transcript specification; LoTRS codec/tests are ENG patterns | Original construction required | Specify canonical bytes, domains, challenge distribution; no external transcript import | Yes only if exact challenge transform | Hash wrapper and deterministic vectors. |
| 8. Base ring signature | Esgin §6 Algorithms; no complete source found | Original implementation required | Implement via verified Esgin proofs | Yes | RSetup, RKeygen, RSign, RVerify. |
| 9. Dilithium OTS | Existing isolated official Round 3 MODE=5 is the closest local candidate; Round 2 MODE=4 is not Dilithium5 | Existing primitive source, but variant compatibility unresolved | Adapter only after confirming the historical specification, API/message encoding and WCM signed tuple | Potentially, but not yet validated | WCM-conformant one-time key lifecycle and wrapper/API after ambiguities are resolved. |
| 10. WCM transformation | WCM paper only; no matching code | Original implementation required | No safe transformation can be coded until paper inconsistencies resolved | Not yet | Key transform, shifted ring, exact OTS message, verify flow. |
| 11. Link tags | WCM’s `ovk` comparison is the specified tag; external tags differ | Original implementation required | Context scoping would be a new analyzed variant | WCM base semantics yes; auction-scoped variant not proven | `Link` validates both signatures then compares tag; formal context requirement. |
| 12. Final API | Local project | Original implementation required | None yet | Yes if composition follows reviewed specifications | C++ keygen/sign/verify/link API and canonical serialization. |
| 13. Test harness | Existing CTest; later minimal isolated harness | Existing test framework | Add LRS tests after APIs exist | Not cryptographic itself | verify-before-link, tampering, ring mismatch, auction-scoped duplicate atomicity tests. |

## Integration decision

No candidate is classified EXACT REUSE for any missing cryptographic section. The only existing source that directly matches the current intended construction is the project’s own Esgin-inspired arithmetic/commitment foundation and isolated Dilithium integrations. The closest full implementation candidates (Falafl, Raptor, ESORICS 2024) are different constructions; the most proof-related artifact (LoTRS) has a different threshold/selection relation and no WCM transformation. The two newly inspected repositories are incomplete or incompatible.

**No external cryptographic source was imported.** This is a deliberate compatibility decision, not a claim that no code was requested: importing those code paths would silently replace proof relations, assumptions or tag semantics. The appropriate next implementation is original Esgin Protocol 1/2 code in the existing APIs only after the precise parameter/security review and WCM ambiguity review are complete.

## References

- Esgin et al., [ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [ePrint 2019/371](https://eprint.iacr.org/2019/371).
- Ye et al., [Efficient Linkable Ring Signature Scheme over NTRU Lattice with Unconditional Anonymity (2022)](https://doi.org/10.1155/2022/8431874).
- Torres et al., [Post-Quantum One-Time Linkable Ring Signature (ePrint 2018/379)](https://eprint.iacr.org/2018/379).
- Existing audits: [`EXTERNAL_REPOSITORY_AUDIT.md`](EXTERNAL_REPOSITORY_AUDIT.md), [`EXTENDED_PQ_LRS_RESEARCH.md`](EXTENDED_PQ_LRS_RESEARCH.md), [`PQ_LRS_REUSE_AND_ADAPTATION_AUDIT.md`](PQ_LRS_REUSE_AND_ADAPTATION_AUDIT.md), [`PHASE3_RING_SIGNATURE_DESIGN.md`](PHASE3_RING_SIGNATURE_DESIGN.md), [`DILITHIUM_IMPLEMENTATIONS.md`](DILITHIUM_IMPLEMENTATIONS.md).
