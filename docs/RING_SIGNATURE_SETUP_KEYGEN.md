# Esgin ring-signature setup and key generation

This module implements only `RSetup` and `RKeygen` from Section 6, printed
page 19 of Esgin et al. (ePrint 2018/773).

- `RSetup` reuses `commitment::CKeygen` to create `ck`. Its challenge set is
  ordered as \(X^0,\ldots,X^{2d-1}\) in
  \(\mathbb Z_q[X]/(X^d+1)\); the existing Protocol 1 challenge conversion
  supplies the correct negacyclic representatives for exponents at least `d`.
- The paper's hash \(H:\{0,1\}^*\to C^r\) is represented by an injected
  `HashToChallenges` interface. No concrete hash, transcript encoding, or
  Fiat–Shamir construction is selected here. The public-parameter wrapper
  checks the returned vector length and that every output belongs to `C`.
- `hash_output_count` and the commitment parameters are caller-supplied. No
  production parameter profile is embedded in the implementation.
- `RKeygen` reuses `sample_bounded_vector` for the paper's \(S_B^m\) support
  and computes `Com_ck(0; r)` with the existing commitment API. Setup
  requires `q > 2B`, ensuring sampled signed coefficients have unambiguous
  centered representatives in the polynomial ring.

The implementation does not include `RSign`, `RVerify`, a concrete
Fiat–Shamir hash, WCM linkability, or `aCom`, and makes no production-security
claim.
