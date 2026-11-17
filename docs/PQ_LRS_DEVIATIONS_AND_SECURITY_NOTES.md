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
- **Esgin parameters:** q is not finalized or security-approved. A paper’s rounded `log₂(q)` and functional tests do not establish the concrete M-SIS/M-LWE security level. Use exact parameter and estimator assumptions before claiming a level.
- **Proof implementation:** Esgin Protocol 1's equation/prover/verifier core is implemented behind provider interfaces. The source tree still has no production discrete-Gaussian sampler, exact Bernoulli-exponential sampler, or selected `aCom` implementation. Protocol 2, Fiat–Shamir and the base Esgin ring signature are absent.

## Security-sensitive integration findings

- `wang-0218/ring-signature` contains non-cryptographic randomness and non-canonical textual hashing; verification checks are commented out. It is not suitable for production or partial cryptographic reuse.
- `Sobieg/L2RS` is archived with no located license; signing is incomplete, verification is declaration-only, the demo crashes, and its profile is unrelated. Do not copy its source absent both a mathematical match and licensing clarification.
- Raptor is GPL-3.0 and a separate NTRU/Falcon construction; the inspected serialization offsets need maintainer explanation. It is not a WCM OTS/tag adapter.
- Calamari/Falafl and several other candidates have distinct relations and/or licensing and audit constraints. See the component map for each repository’s observed license and caveats.
- Neither upstream Dilithium source should be modified or treated as implementing ring membership, Esgin proofs, or WCM linkability. An adapter must keep the upstream implementation intact and use the correct historical variant and exact signed bytes.
- The current 7/7 CTest result, including the Protocol 1 fixture test, is functional evidence only. It is not a cryptographic security evaluation and does not validate protocol composition.

## Safe status statement

The project has reusable local arithmetic/sampling/commitment groundwork and independently tested Dilithium source trees. It does **not** yet have a complete Esgin ring signature, WCM linkability extension, verified Dilithium OTS adapter, or context-scoped auction link tag. No security claim is made for the combined system.

The Protocol 1 test uses deterministic fixture providers only. It checks equations and validation logic for specific toy inputs; it does not establish that any implementation of the provider interfaces has the required distributions, or that the proof is zero knowledge/sound under chosen production parameters. The selected production modulus and lattice estimates remain unresolved.

## References

- Esgin et al., [ePrint 2018/773](https://eprint.iacr.org/2018/773).
- Wang, Chen, Ma, [ePrint 2019/371](https://eprint.iacr.org/2019/371).
- Detailed source map: [`PQ_LRS_COMPONENT_REUSE_MAP.md`](PQ_LRS_COMPONENT_REUSE_MAP.md).
- Discovery results: [`PQ_LRS_IMPLEMENTATION_DISCOVERY_REPORT.md`](PQ_LRS_IMPLEMENTATION_DISCOVERY_REPORT.md).
