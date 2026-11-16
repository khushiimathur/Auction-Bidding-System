# PQ-LRS Protocol Resolution: Esgin + Wang–Chen–Ma

**Status:** paper-level reconstruction only. No equations have been repaired, no parameters selected, and no cryptographic source changed. This document distinguishes what the papers state from type-level inconsistencies and questions requiring author clarification or independent review.

## 1. Source versions and reference convention

This review uses the original ePrint PDFs: Esgin et al., [2018/773](https://eprint.iacr.org/2018/773.pdf) (the ePrint version notes a major revision and ACNS 2019 publication), and Wang, Chen and Ma, [2019/371](https://eprint.iacr.org/2019/371.pdf) (ISC 2019). Page references below are the printed page numbers in those PDFs, not browser line numbers. WCM cites Esgin et al. as reference [13] and Dilithium as [12] (WCM §4, printed p. 5; references pp. 6–7).

## 2. WCM generic construction (§3.1)

WCM composes an existing ring signature `RS` with an OTS. Let the underlying RS public-key space be `PK̂`, with group operation `⊙` and inverses; let `OVK` be the OTS verification-key space. WCM requires that the RS key space has this group structure and that generated RS public keys are statistically close to uniform (WCM §1.1, printed pp. 1–2). Generic setup chooses

\[
H: OVK \longrightarrow PK̂.
\]

The construction is stated as follows (WCM §3.1, printed pp. 4–5):

1. **KeyGen:** Generate `(p̂k, ŝk) ← RS.KeyGen`, `(ovk, osk) ← OTS.KeyGen`; publish `pk = p̂k ⊙ H(ovk)`, and retain `sk=(ŝk, osk, ovk)`.
2. **Sign:** Given signer `s`, message `m`, ring `T={pki}`, transform each ring key as `p̂k′i = pki ⊙ H(ovks)^{-1}`, obtaining `T̂′`. Run `σ̂ ← RS.Sign(ŝks,m,T̂′)`. Then run `σ̃ ← OTS.Sign(osks,(σ̂,T,ovks))`. Output `σ=(σ̂,σ̃,ovks)`.
3. **Verify:** Parse `σ=(σ̂,σ̃,ovk)`, form `p̂k′i=pki ⊙ H(ovk)^{-1}`, verify `RS.Vrfy(T̂′,m,σ̂)`, and verify `OTS.Vrfy(ovk,(σ̂,T,ovk),σ̃)`. Accept iff both accept.
4. **Link:** Verify both complete signatures; if either fails, abort/reject. Otherwise compare `ovk1` and `ovk2`; equal means linked, unequal means unlinked.

The generic transformation is internally consistent about the public-key shift: KeyGen multiplies by `H(ovk)`, while both Sign and Verify multiply by its inverse. The OTS input is also consistent in the generic construction: both Sign and Verify use `(σ̂,T,ovk)`. The generic `H` is a map from OTS public keys to elements of the *underlying ring-signature public-key group*, not necessarily a map to a polynomial vector unless the underlying RS specifies that type.

There are two smaller notation/API omissions in §3.1: Setup says it chooses `H` but writes the returned public parameter as `pp= p̂p` without explicitly including `H`; and Link describes calls to `Vrfy` with argument ordering that does not match the earlier `Vrfy(T,m,σ)` declaration. These may be shorthand/typographical omissions, but implementations need the public hash and one canonical call signature.

## 3. WCM concrete instantiation (§4)

WCM says it instantiates the generic transform with Esgin’s ring signature and Dilithium as OTS (WCM §4, printed p. 5; §5.2 calls the selected OTS version “very high,” printed p. 6). Its concrete setup declares a commitment key `ck=G ∈ Rq^{n×(m+kβ)}` and two hashes:

\[
H:\{0,1\}^*\to C,\qquad H':\{0,1\}^*\to R_q^n,
\quad C=\{X^\omega:0\leq\omega<2d\}.
\]

The index length is `k=log_β N`. The concrete public keys are vectors/commitments in `R_q^n` with additive operation, so the intended key-mask type for the transformation is `R_q^n`.

### 3.1 Public-key transformation and hash types

| Stage | WCM concrete text | Type implied by the expression | Review |
|---|---|---|---|
| Setup | `H : {0,1}* → C`; `H′ : {0,1}* → Rq^n` (§4, p. 5) | `C` is a monomial challenge subset of `Rq`; `Rq^n` is a vector public-key space | Two codomains are declared. |
| KeyGen | `pk = p̂k + H′(ovk)` (§4, p. 5) | `p̂k, pk, H′(ovk) ∈ Rq^n` | Type-consistent with declared `H′`. |
| Sign, ring transform | `p̂k′i = pki − H′(ovks)` (§4, p. 5) | Both terms must lie in `Rq^n` | Type-consistent with KeyGen and the declared `H′`; signer’s transformed key equals its underlying key if the same member key and OTS key are used. |
| Sign, Fiat–Shamir challenge | `x = H′(ck,m,T̂′,A,B,C,D,{Ej})` (§4, p. 5) | `x` is used as a challenge in `C` (indeed Esgin uses `C^L`) | This call requires output in challenge space, but declared `H′` returns `Rq^n`. The declared `H` returns `C`, but the concrete algorithm writes `H′`. The input is also structured while setup only gives an untyped bit-string domain; serialization/domain separation are not specified. |
| Verify, ring transform | `p̂k′i = pki − H(ovk)` (§4, p. 5) | The subtrahend must be in `Rq^n` | Under the setup declaration `H(ovk)∈C`, not `Rq^n`; this is generally type-incompatible with subtracting from a vector public key. It also differs from Sign’s `H′`. |

Thus the KeyGen and Sign public-key masks agree with each other in using `H′`, but concrete Verify writes `H`, whose declared output is the challenge space `C`. Meanwhile concrete Sign uses `H′` for the Fiat–Shamir challenge, although its declared codomain is the public-key vector space. In the generic construction there is only one typed map `H: OVK→PK̂`; in the concrete section, two hashes are declared but their names/codomains are not used consistently. These expressions may be more than an innocuous spelling issue: the vector `Rq^n` and challenge subset `C⊂Rq` have different shapes and roles, so the two Verify/Sign expressions need not even be addable/subtractable under the stated types.

**No correction is selected here.** Plausible editorial explanations (such as an `H`/`H′` swap in one or more locations) are interpretations only and cannot be implemented without an erratum, author clarification, or independently reviewed derivation.

### 3.2 OTS message passed to Sign and Verify

The concrete Sign algorithm states:

\[
\tilde\sigma\leftarrow Dilithium.Sign(osk,(\hat\sigma,T,ovk_s))
\]

(WCM §4, printed p. 5). The concrete Verify algorithm instead states:

\[
Dilithium.Vrfy(ovk,(\hat\sigma,T,\hat{pk}),\tilde\sigma)
\]

(same section/page). These are different messages: `ovk` versus `p̂k`. The generic construction uses `(σ̂,T,ovk)` on both sides (§3.1, p. 5), matching concrete Sign but not concrete Verify.

The difference is operationally significant. An OTS verifier normally checks the exact bytes supplied to the signer; if these tuples encode different values, a signature created on the Sign tuple will not generally verify on the Verify tuple. Also, `p̂k` is not part of the concrete output signature `(σ̂,σ̃,ovk)` and is not explicitly defined as a field recoverable from it. The paper does not state whether `p̂k` here means the underlying public key, a transformed ring member, or is a typo. This report records the discrepancy without choosing a correction.

## 4. OTS key lifecycle and one-time security

### Confirmed algorithm text

- WCM `KeyGen` creates `(ovk,osk)` together with the underlying RS key pair and stores them in the long-term LRS secret key (generic §3.1, p. 5; concrete §4, p. 5).
- WCM `Sign` accepts this secret key and invokes `OTS.Sign(osk,...)`; it does not invoke `OTS.KeyGen`, rotate the OTS key, or take a one-time-use state/counter (generic §3.1 and concrete §4, p. 5).
- Every output includes `ovk` as its tag, and `Link` declares signatures linked exactly when the verified signatures contain equal `ovk` values (generic §3.1, p. 5; concrete §4, p. 5).
- Therefore, as the written API stands, multiple calls to `Sign` for the same LRS key reuse the same OTS key and same tag. This is what makes repeated signatures linkable.

### Relation to the OTS assumption

Theorem 3 says nonslanderability follows if the underlying OTS is unforgeable (WCM §3.2, printed p. 4). Its brief proof sketch embeds one challenge `ovk`, obtains an OTS signature on `(σ̂,T,ovk)`, and treats a newly produced linked signature as an OTS forgery (WCM §3.2, p. 4). The nonslanderability game’s challenge condition excludes the challenge signer public key from prior corruption and from use as a ring member in signing-oracle queries (WCM §2.3, printed p. 3). That setup may give the reduction only one OTS signing use under the embedded challenge key.

However, the construction’s normal `Sign` API reuses the same `osk` for repeated signatures, while a strict one-time signature guarantee only covers its stated one-signature security experiment. The text does not specify a per-signature OTS key-generation lifecycle, key rotation, bounded-use OTS notion, or stateful OTS protocol. It also does not explain how fresh `ovk` values per signature would preserve the public-key transform and same-signer link tag. This leaves a gap between (a) the stated repeated-signing/linkability behavior and (b) what is justified solely by ordinary one-time unforgeability. The proof-game restriction may be enough for its stated nonslanderability theorem, but it does not by itself define or validate a practical multi-signature key lifecycle. This point requires cryptographic review; it is not concluded here that the theorem is false.

WCM’s introduction describes LRS as allowing the same signer to sign twice and be linked (printed p. 1); §6 says the tag is only signer-bound (p. 7). Thus reusing the long-term `ovk` is the apparent intended linkability mechanism, but reuse of an OTS private key for multiple distinct signed transcripts must be justified beyond the label “one-time.”

## 5. What linkability means in WCM

The `Link` algorithm first validates both signatures, then compares their `ovk` values. WCM explicitly states that the construction’s linkability is “one-time linkability”: the tag is **not** bound to the signer ring or message, only to the signer (WCM §6, printed p. 7). Consequently:

- Same `ovk` across different messages: linked.
- Same `ovk` across different rings: linked.
- Same `ovk` across different application contexts: linked; there is no context argument in `KeyGen`, `Sign`, `Vrfy`, or the tag comparison.
- Fresh independent `ovk` values: not linked by the specified equality test, even if the same underlying signer secret is used, unless an additional mechanism links them.
- A valid signature is checked before its tag participates in Link; malformed/invalid signatures should not be classified as linked by the algorithm.

The scheme’s linkability game asks for `N+1` valid, pairwise unlinked signatures on a common ring of `N` joined keys (WCM Definition 3, §2.3, pp. 3–4). The algorithmic Link input allows two rings/messages and does not require equality of either. The §6 discussion explains this signer-global scope as useful for preventing repeated spending across transactions, and cautions that it may not fit applications such as e-voting (p. 7).

The statement “the tag is not bound to a context” is about the cryptographic tag and Link procedure. An application may keep separate duplicate databases per auction, but that only scopes the application’s rejection rule; public signatures still expose the same `ovk` and remain correlatable across auctions.

## 6. What auction-scoped linkability would change

An auction-scoped requirement means signatures should link when they use the same signer and the same auction context, while not exposing a stable equality tag across auctions. WCM’s construction does not provide this property as written. Merely keying a database by `auction_id` changes application behavior but not signature-level correlation.

Cryptographically scoping a tag would change at least the protocol input/key lifecycle and security statement. For example, a context-dependent OTS key or tag would affect the `pk=p̂k+H(ovk)` relation: the ring’s registered public key must still be transformed so that the signer can prove knowledge of its corresponding underlying RS secret. It would also affect the value signed by the OTS, verification and `Link` inputs, and the nonslanderability/linkability games. A context value must be canonical, authenticated, and included consistently; different-context unlinkability would become a new privacy goal. The paper supplies no construction or proof for this variant. These are implications to analyze, not a proposed protocol or a claim that any particular derivation is secure.

Before implementation, decide whether requirements are (i) WCM’s global signer-level correlation, or (ii) auction-scoped correlation with cross-auction unlinkability. If (ii), design/review a protocol extension and its public-key registration/lifecycle; do not silently insert an auction identifier into the OTS message or hash.

## 7. Esgin base protocol WCM instantiates

WCM’s concrete §4 is based on Esgin et al.’s Section 6 ring signature, which in turn uses the Section 2 commitment, Section 4 Protocol 1, and Section 5 Protocol 2. The following are dependencies of that specific construction, not interchangeable implementation suggestions.

### 7.1 Algebra, commitment, and distributions

- **Ring:** `R=Z[X]/(X^d+1)`, `Rq=Zq[X]/(X^d+1)`; multiplication is negacyclic. Esgin uses coefficient representatives/norms as defined in §2.1 (printed pp. 5–6).
- **Commitment key:** Section 2.2, Definition 1/2 (printed pp. 6–7): sample `G′r ← Rq^{n×(m−n)}` and `Gm ← Rq^{n×v}` uniformly; let `Gr=[In | G′r]` and `G=[Gr | Gm]`; `ck=G`. For `u∈Rq^v` and `r∈S_B^m`, `Com_ck(u;r)=Gr r+Gm u`. In the ring signature `v=kβ` (Protocol 1 digit-vector length; Appendix D Table 4, printed p. 25). Key generation samples each secret/opening coefficient uniformly from `{-B,…,B}` as specified in the relevant algorithm/profile; selected paper analysis uses `B=1` (§6.1, p. 20).
- **Commitment relations:** commitments are homomorphic. Lemma 1 (p. 7) bases hiding on `M-LWE_{m−n,n,q,B}` and bounded strong binding on `M-SIS_{n,m+v,q,2Tcom}`. `q` is specified as an odd positive integer in Esgin’s setup/commitment definitions; primality is not asserted as a generic requirement. Exact norm and relaxation semantics must match the source definitions.
- **Gaussian distributions:** use Esgin’s discrete Gaussian `D^t_σ` convention (§2.1, pp. 5–6), not an arbitrary normal sampler. Rejection sampling is exactly Algorithm 1, §2.3, p. 8: `σ=φK`, `μ(φ)=exp(1/φ+1/(2φ²))`, and the stated acceptance probability involving `−2〈z,c〉+||c||²`. Distribution dimension, shift, `φ`, `K`, norm, and abort behavior are part of the proof.
- **Auxiliary commitment `aCom`:** Protocol 1 and 2 use an auxiliary commitment/hash `aCom` to bind the auxiliary challenge and support the proof’s simulation argument (§4, p. 14; §5, pp. 16–17). Its required hiding/binding properties and transcript input order must be preserved; the paper notes that in the noninteractive ring-signature application explicit abort simulation is unnecessary (footnote in §4, p. 14).

### 7.2 Protocol 1: one-hot binary proof (Section 4, Protocol 1, pp. 14–15)

For `N=β^k`, the witness is a `k×β` binary array `b_{j,i}` with each row summing to one and a bounded opening `r` of commitment `B`. Definition 4 gives relation `Rbin(T)` and relaxed extracted relation `R′bin(T̂)`; the extracted opening is to `2B` and has a separate norm bound. The norm bounds are security-critical, not decorative (Remark 1, p. 14).

For each proof run, Protocol 1 samples the nonzero-position masks `a_{j,i}` from `D^d_{φ1√k}`; computes `a_{j,0}=−Σ_{i=1}^{β−1}a_{j,i}`; samples `rc←{-B,…,B}^{md}` and `ra,rd←D^{md}_{φ2 B√(2md)}`. It forms commitments `A=Com(a;ra)`, `C=Com({a_{j,i}(1−2b_{j,i})};rc)`, and `D=Com(−a_{j,i}²;rd)`, then obtains `(ca,da)=aCom(A,C,D)`. For challenge `x∈C={X^ω:0≤ω<2d}`, the responses use `f_{j,i}=x b_{j,i}+a_{j,i}`, `zb=xr+ra`, and `zc=xrc+rd`; both specified Rej calls can abort (Protocol 1, p. 15; Algorithm 1, p. 8).

The verifier reconstructs `f_{j,0}=x−Σ_{i=1}^{β−1}f_{j,i}`, checks `aCom`, the exact stated response norm bounds, and

\[
xB+A=Com(f;z_b),\qquad xC+D=Com(g;z_c),\quad g_{j,i}=f_{j,i}(x-f_{j,i}).
\]

The norm/modulus conditions in Theorem 1 are what let the polynomial relation imply bitness; do not replace them with field arithmetic or just check `b(b−1)=0` in a quotient ring. Theorem 1 states three-special soundness, soundness error `1/d`, M-LWE hiding, T-binding, and explicit lower bounds on `d`, `md`, and `q` (§4, pp. 14–15).

### 7.3 Protocol 2: one-out-of-many proof (Section 5, Protocol 2, pp. 16–18)

The public input is the list `L=(c0,…,c_{N−1})`, where only the signer’s selected `cℓ` needs to be a commitment to zero; other members need not be well-formed commitments (§5, p. 16). Encode `ℓ` in base `β`; its `k` digits define one-hot rows `δ_{ℓj,i}`. The protocol commits to these rows as `B=Com(δ;rb)`, invokes Protocol 1 on that opening, and samples Gaussian vectors `ρj` with the Protocol 2 distribution. It expands the product polynomial for every ring index `i=(i0,…,i_{k−1})`:

\[
p_i(x)=\prod_{j=0}^{k-1}(x\delta_{\ell_j,i_j}+a_{j,i_j})
=\delta_{\ell,i}x^k+\sum_{j=0}^{k-1}p_{i,j}x^j,
\]

then publishes `Ej=Σ_i p_{i,j} c_i + Com(0;ρj)`. On challenge `x`, responses include `z=x^k r−Σ_{j=0}^{k−1}x^jρj` and the binary-proof responses; rejection sampling is applied jointly to the concatenated `(z,zb,zc)` vector (Protocol 2, p. 17; its note explains the `3md`-dimensional sampling).

Verification checks the embedded Protocol 1 conditions, auxiliary commitment, all exact norm bounds, and for each base-β index tuple the polynomial commitment equation printed in Protocol 2, p. 17. Theorem 2 requires `d≥7`, `md≥86`, the paper’s q lower bound, the commitment’s hiding/binding assumptions, and yields `(k′+1)`-special soundness with `k′=max{2,k}` and single-run soundness error `k′/(2d)` (§5, pp. 17–18). Do not substitute a simplified membership proof.

### 7.4 Repeated proof and Esgin ring signature (Section 6, pp. 18–21)

Set `N=β^k`. Challenge set `C={X^ω:ω∈[0,2d−1]}`; hash the commitment key, message, ordered ring, and all first messages to a vector in `C^r`. Section 6 changes rejection sampling: sample the `r` first-message response vectors and the `r` tuples `(z,zb,zc)` at the prescribed concatenated Gaussian widths, perform rejection jointly, and restart if any of the `r` responses abort. This changes the q and binding requirements (Section 6, pp. 18–19; Assumption 1 and Theorem 3, pp. 19–20).

The four algorithms are:

1. **RSetup:** Esgin commitment keygen; publish `ck` and random-oracle hash to `C^r`.
2. **RKeygen:** sample `r←S_B^m`; publish `pk=Com_ck(0;r)` and retain `sk=r`.
3. **RSign:** locate signer index `ℓ` with `cℓ=Com(0;sk)`; run Protocol 2 first-message steps `1–7` for `r` transcripts; hash `(ck,M,L,CMT_1,…,CMT_r)` to challenges; finish all responses; restart on any abort; output the commitment packages, challenge vector and responses. The paper permits omission of determined fields `A,D,E0` only because the verifier reconstructs/checks them (§6, pp. 19–20).
4. **RVerify:** recompute exactly that hash and reject if unequal; verify every Protocol 2 transcript and all bounds/equations (§6, p. 20).

Parameter dependencies to carry through together:

| Parameter/choice | Role and paper dependency |
|---|---|
| `d,q` | Ring degree/modulus; odd `q`; challenge inverses and binary-relation bounds; q lower bound in Assumption 1 and M-SIS bound Eq. (11), §6.1. Table gives rounded `log₂q`, not a full integer modulus. |
| `N,β,k` | `N=β^k`, index digit representation, proof dimensions and challenge/soundness; `k=log_βN`. |
| `n,m,v` | Commitment dimensions `G∈Rq^{n×(m+v)}` and M-LWE sample/module dimensions; in the LRS `v=kβ`; `md≥86`; `m` must satisfy the cited estimator/security condition. |
| `B` | Small opening-secret coefficient bound/distribution; Section 6.1 chooses `B=1`. It affects M-LWE, norm bounds, rejection widths and M-SIS binding. |
| `φ1,φ2` | Rejection parameters for the bit-proof and commitment-randomness layers; Section 6.1 sets both to 4 (the paper’s notation is `2²`) for its reported acceptance-rate analysis. |
| `r,λ` | Repetition and protocol soundness. Per-run error is `η=max{2,k}/(2d)`; Appendix D uses `r=⌈−λ/log₂η⌉`, with Table 3 rounding. This λ is the repetition soundness exponent, not a standalone computational-security estimate. |
| `Tcom,T1,T′` | Commitment bounded-binding radii from Lemma 1, Protocol theorems and repeated-protocol extraction; depend on Gaussian widths, `B,m,d,k,β,r` and the extraction method. |
| `B_{d,k}` | Method-2 extraction bound from §3 / Lemma 10; exact values in parameter calculations are obtained by enumerating challenge subsets for selected `(d,k)`. It affects the M-SIS inequality in Eq. (11). |
| Distributions and transcript | Uniform setup matrices, bounded small vectors, discrete Gaussians with specified standard deviations, exact Rej acceptance probability, challenge sampling from monomials, random-oracle transcript binding and ordered serialization. Each affects proof arguments and cannot be substituted independently. |

Section 6.1 sets `φ1=φ2=4`, selects `B=1`, cites Albrecht et al.’s estimator for M-LWE and targets root-Hermite factor `δ≤1.0045` for M-SIS and M-LWE (printed p. 20). Eq. (11) is an additional M-SIS bound; Assumption 1 is the protocol q bound. Appendix D, Table 4 (printed p. 25) gives the repetition, proof-size, and key-size formulas. For the N=64 Table 3 row, the authors report `(n,m)=(5,13)`, `(d,log₂q)=(256,50)`, `(k,β)=(2,8)`, `r=16`, `λ=128.0`, 774 KB signature (printed pp. 20–21). That row does not specify an exact integer q, and its λ entry is the repeated soundness exponent. This document does not select q or claim that current local estimates independently validate the paper’s computational-security claim.

## 8. Confirmed statements, apparent errors, unresolved points, interpretations

### Confirmed by the papers

1. WCM’s generic construction uses `H:OVK→PK̂`, applies the inverse mask in both Sign and Verify, signs `(σ̂,T,ovk)` in both generic Sign and Verify, and links by equality of valid signatures’ OTS verification keys (§3.1, p. 5).
2. WCM’s concrete instantiation declares different hash codomains, uses `H′` for key generation and signing’s ring transform, uses `H` for Verify’s ring transform, and prints differing OTS message tuples (§4, p. 5).
3. WCM explicitly characterizes its tag as signer-bound, not bound to ring or message (§6, p. 7); `Link` has no explicit application-context argument (§3.1 and §4).
4. WCM generates an OTS key pair in its LRS KeyGen and reuses that `osk,ovk` in Sign as written (§3.1 and §4, p. 5).
5. Esgin’s selected ring-signature protocol is a repeated Protocol 2 construction with a monomial challenge set, exact rejection sampling, Esgin’s commitment, and bounds/assumptions in §§2–6 and Appendix D.

### Apparent paper typos / type mismatches (not repaired)

1. In concrete Sign, the transcript challenge call is written `H′(ck,m,T̂′,A,B,C,D,{Ej})`, but declared `H′` has public-key vector codomain `Rq^n`; the challenge must be in the monomial challenge space (and in the repeated construction a vector of such challenges). The separately declared `H` has the challenge codomain. This is an apparent hash-name/type mismatch (§4, p. 5).
2. Concrete Verify’s ring transformation subtracts `H(ovk)`, while Setup says `H` returns an element of `C`, not a vector in `Rq^n`; this is potentially ill-typed and differs from Sign (§4, p. 5).
3. Concrete OTS Verify names `p̂k` in the authenticated tuple where Sign names `ovk`; this disagrees both with generic Verify and with the concrete Sign tuple. The paper does not define a recovered `p̂k` field in the output signature (§3.1 and §4, p. 5).
4. The WCM `Link` prose/pseudocode does not consistently preserve the previously declared argument order for `Vrfy`; generic Setup also does not explicitly include its chosen `H` in `pp` (§3.1, p. 5). These are API-specification omissions in addition to the concrete cryptographic type mismatches.

“Apparent typo” is a diagnostic label, not a decision about intended equations. The source text could reflect notation overloading, transcription/OCR, or an omitted definition; the printed formulas still require resolution.

### Unresolved questions

- Are concrete `H` and `H′` intended as separate functions with precisely the declared domains/codomains, or is one/both hash name/codomain wrong? What exact function maps serialized OTS public keys to `Rq^n`, and what function maps the full Esgin transcript to `C^r`?
- Does WCM Setup intend to publish the generic hash `H` as part of `pp`, and what is the normative argument ordering for `Vrfy` when called by Link?
- Is Verify intended to transform ring keys using `H′(ovk)` as in KeyGen/Sign, or is a separately typed `H(ovk)` defined elsewhere?
- Is concrete OTS Verify intended to authenticate `(σ̂,T,ovk)` (matching generic construction and concrete Sign), or another tuple? If the latter, where does that value come from and how is it canonically encoded?
- Does the proof of Theorem 3 intend one OTS signing use per registered key, repeated uses under a one-time key, a stateful key lifecycle, or a stronger OTS security notion? How is the reduction valid under the number of signatures allowed by the system’s API?
- Is one `ovk` deliberately permanent per ring public key, making the tag globally stable, or should there be per-event/context key material? If context scope is required, what registration and transformed-ring relation preserves the signer witness?
- What exact Dilithium version/parameter set, key-generation randomness, OTS message encoding and signature encoding did the authors’ implementation use? “Dilithium”/“very high” is insufficient to determine an interoperable historical implementation.
- Which exact Esgin parameter profile/modulus and encoding are intended in a new implementation, and can the M-LWE/M-SIS estimates be independently reproduced for those exact assumptions?

### Proposed interpretations (not normative decisions)

The most direct way to make the concrete transform match the generic transform would be to use one consistently typed OTS-key-to-RS-key hash in KeyGen/Sign/Verify, a separately typed transcript-to-challenge hash for Fiat–Shamir, and the same canonical OTS message in Sign and Verify. This is only an interpretation of the generic/concrete structure; the document does **not** instantiate it as a correction. Likewise, an auction context could be included in a new tag/key-generation design, but the paper does not give or prove that design.

## 9. Precise questions for author clarification / independent review

1. Please confirm the exact concrete hash functions and types: `H_tag : OVK→Rq^n` and `H_FS : encoded transcript→C^r` (or provide the intended alternatives). Which occurrences of `H`/`H′` in WCM §4 are typographical errors, if any?
2. In concrete WCM Verify, should the transformed ring be `pki−H′(ovk)`? If not, define the domain/codomain of `H` that makes the printed subtraction valid and explain why it differs from Sign.
3. What exact byte string does the OTS sign, and what exact byte string does Verify check? Is the printed `p̂k` in concrete Verify intended to be `ovk`, a particular base public key, or another value? How is it available to the verifier?
4. Is the OTS key pair generated once per long-term LRS public key and reused for all signatures? If yes, state and prove the needed security notion for multiple distinct OTS messages, or explain why the one-time unforgeability theorem’s game permits this use. If no, specify the key rotation/fresh-key and ring-registration mechanism that preserves linkability.
5. Does nonslanderability hold after an adversary has observed multiple honest signatures carrying the same `ovk`? The current game/proof sketch should be checked against this multi-signature exposure and the OTS’s actual one-time definition.
6. Is the desired functionality global signer-level linking across all rings/messages, as WCM §6 says, or context-limited linking? If context-limited, provide a formal definition and reviewed construction/proof, including cross-context unlinkability and public-key transformation.
7. Confirm that Esgin’s exact Protocol 1/2 equations, distributions, repeated rejection procedure, norm bounds and Table 3 profile are the intended base; identify any corrected version/erratum and provide the exact modulus and encoding only if explicitly specified by the authors.
8. Independently verify the composition proof: Esgin’s random-oracle challenge transcript, WCM’s key-mask hash, OTS-authenticated message, tag equality, and the stated anonymity/linkability/nonslanderability games must use mutually consistent domains, encodings, key lifecycle, and adversary capabilities.

Until those answers are resolved, the papers provide enough information to document the intended high-level composition, but not a fully unambiguous concrete WCM protocol specification suitable for implementation. No security claim is made by this review.
