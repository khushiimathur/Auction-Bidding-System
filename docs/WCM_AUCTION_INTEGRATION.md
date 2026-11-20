# WCM Linkable Ring Signature Integration and Sealed-Bid Auction Demo

This document covers the WCM linkability layer built on top of the validated
Esgin RSign/RVerify pipeline, the sealed-bid auction demonstration built on
top of that, and how to run it. It assumes the reader has already seen (or
can refer to) the earlier RSign/RVerify bug-fix reports; it does not repeat
the derivations there, only restates the conclusions where relevant.

## 1. Cryptographic call flow

### 1.1 Base layer (Esgin et al., 2018/773) — unchanged by this work except
for the three bug fixes documented separately

```
RSetup(profile) -> PublicParameters
RKeygen(pp)      -> KeyPair { public_key, secret_key }
RSign(pp, proof_params, ring, witness, message, ...) -> RSignSignature
RVerify(pp, proof_params, ring, message, signature, ...) -> bool
```

### 1.2 WCM linkability layer (Wang, Chen, Ma, ISC 2019) — pure composition
over 1.1, implemented in `cpp_backend/src/lrs/linkable_ring_signature.cpp`
and `link.cpp`, unmodified by this task:

```
LRKeygen(pp):
    (p̂k, ŝk)  <- RKeygen(pp)                     # base Esgin key pair
    (ovk, osk) <- ots::GenerateKeyPair()           # Dilithium5 OTS key pair
    pk = p̂k + H'(ovk)                             # H' = SHAKE256-XOF mask
    return LinkableKeyPair{ pk, secret_key = (ŝk, osk, ovk) }

LRSign(ring T, signer_index, guard, message):
    guard.consume_for_signing()                    # one-time-use enforcement
    T̂' = { pk_i - H'(ovk_signer) : pk_i in T }     # unmask every ring entry
    σ̂  <- RSign(pp, proof_params, T̂', witness, message, ...)
    σ̃  <- ots::Sign(osk, encode(σ̂, T, ovk))        # OTS binds (σ̂, T, ovk)
    return LinkableSignature{ σ̂, σ̃, ovk }

LRVerify(ring T, message, σ = (σ̂, σ̃, ovk)):
    T̂' = { pk_i - H'(ovk) : pk_i in T }
    return RVerify(pp, proof_params, T̂', message, σ̂, ...)
           AND ots::Verify(ovk, encode(σ̂, T, ovk), σ̃)

Link(m1, σ1, T1, m2, σ2, T2):
    if not LRVerify(T1, m1, σ1) or not LRVerify(T2, m2, σ2): return Rejected
    return Linked if σ1.ovk == σ2.ovk else Unlinked
```

### 1.3 Production integration layer (this task's Phase 1)

`cpp_backend/include/lattice_lrs/lrs/production_lrsign.hpp` /
`production_lrsign.cpp` — `ProductionLRSignContext`, mirroring the existing
`ProductionRSignContext` exactly: owns the real providers
(`SigmaSection6GaussianProviderBundle`, `Section6BatchRejectionProvider`,
`Shake256AuxiliaryCommitmentProvider`, `ExactBernoulliExponentialProvider`,
`CanonicalRSignTranscriptEncoder`), calls `RSetup` (never
`RSetupForTesting`) and `LRKeygen`/`LRSign`/`LRVerify`/`Link` (never their
`ForTesting` counterparts). No new cryptographic algorithm; composition and
lifetime management only.

### 1.4 Auction layer (this task's Phase 3)

`cpp_backend/include/lattice_lrs/auction/sealed_bid_auction.hpp` /
`sealed_bid_auction.cpp` — `SealedBidAuction`, built on the SAME real
algorithms as 1.3, but via `RSetupForTesting`/`LRKeygenForTesting`/
`LRSignForTesting`/`LRVerifyForTesting`/`LinkForTesting` at a smaller,
explicitly demo-scale parameter set (see §3).

## 2. Validation performed (in order)

1. **Focused WCM integration test** —
   `tests/test_production_lrsign_integration.cpp` (ctest target
   `production_lrsign_integration_test`): real `ProductionLRSignContext` at
   `ParameterProfile::N64()` (ring size 64). Generates all 64 ring members
   (real `LRKeygen`, ~34s), performs three real `LRSign` operations (two
   sharing an OTS key pair, one with an independent key pair), verifies all
   three, confirms `Link` reports `Linked` for the shared-key pair and
   `Unlinked` for the others, confirms rejection of a tampered message,
   ring, and signature, confirms `OneTimeKeyReuseError` on guard reuse, and
   confirms `Link` is deterministic across repeated calls (no hidden
   state). **Result: PASS** (`production_lrsign_n64_full_flow`). The three
   real signings took 493s, 980s, and 654s respectively on the machine this
   was run on.
2. **Full CMake build** — clean, no warnings introduced.
3. **Full CTest suite** — 27/27 passing (the two multi-minute end-to-end
   integration tests, `production_rsign_integration_test` and
   `production_lrsign_integration_test`, are excluded from the default fast
   run via `ctest -E`, but both have been run to completion and pass; see
   above and the separate RSign bug-fix report).
4. **Auction integration tests** — `tests/test_sealed_bid_auction.cpp`
   (ctest target `sealed_bid_auction_test`): a valid bid is accepted; a
   second submission from the same ring member (even with a different
   amount and a freshly produced, independently valid signature) is
   rejected as a duplicate, specifically via `Link` returning `Linked`
   (confirmed by comparing ovk fingerprints, not by inspecting internal
   state); two different ring members can both submit; the same ring
   index in two *different* `SealedBidAuction` instances is accepted in
   both, with different ovk fingerprints (no shared linkability state); an
   out-of-range bidder index is rejected before reaching any duplicate
   check; the public submission log never contains the plaintext bid
   amount or the bidder's ring index. **Result: PASS**, all 6 cases, ~12-14s
   total.
5. **Manual demo walkthrough** — exercised via Streamlit's
   `streamlit.testing.v1.AppTest` harness (headless, no browser needed):
   loaded `python/demo/app.py`, confirmed all sections (including the new
   "Sealed-Bid Auction" section) render with zero exceptions, clicked
   "Create auction" and "Submit bid" programmatically, confirmed "Bid
   accepted." with zero exceptions end-to-end through the real subprocess
   server. Also run manually against the raw `lrs_auction_cli` line
   protocol (see §4) to confirm `CREATE`/`BID`/`LIST`/`AUCTIONS` all behave
   as documented, including a live duplicate rejection.

## 3. Demo-scale parameters — why, and exactly what they are

`ParameterProfile::N64()` (the only validated, named profile small enough to
be a candidate) has a **fixed ring size of exactly 64** and real
sign/verify times on the order of minutes (confirmed above). That is
unusable for a page a person clicks through interactively.

The auction instead uses `RSetupForTesting` with an explicit, small
`commitment::Parameters`/`Protocol2Parameters` configuration:

| Parameter | Value | Why |
|---|---|---|
| degree (d) | 64 | `2*d` must be a power of two for `Shake256CToChallenges`; 64 is the smallest convenient choice above the floor implied by `m*d >= 86`. |
| n | 1 | Smallest valid commitment row count. |
| m | 2 | `m*d = 128 >= 86` (Protocol 1's own minimum). |
| k, beta | 3, 2 | ring_size = beta^k = 8 — enough bidders for a legible demo while staying fast. |
| repetitions (r) | 3 | Chosen empirically for speed, **not** derived from `ComputeRSignRepetitionCount(128, d, k)` — this does **not** target 128-bit soundness. |
| phi1, phi2 | 22, 22 | Same as the paper's own Section 6.1 choice (kept for consistency, not re-derived for this dimension). |
| q | 1099511627791 (a 41-bit prime) | Empirically large enough to satisfy `BinaryProofParameters::validate`'s q-lower-bound check at these phi1/d/k values; **not** derived from Assumption 1's closed form the way the named profiles are. |
| B | 1 | Same as the named profiles. |

Empirically measured sign/verify times at this configuration: ~0.8-1.1s to
sign, ~0.05-0.1s to verify (vs. minutes at N64). **This is not a mock** —
every provider is the identical real implementation
`ProductionLRSignContext` uses; only the dimensions differ, and this is
disclosed prominently in the Streamlit UI, in the header comment of
`sealed_bid_auction.hpp`, and here.

## 4. How auction-level duplicate detection actually works

The auction does **not** use a username, bidder ID, or session token to
detect a repeat submission. Concretely, in `SealedBidAuction::SubmitBid`:

1. A **fresh** `OneTimeOtsKeyGuard` is constructed wrapping a **copy** of
   the bidder's `LinkableSecretKey` on every call — including a second,
   third, etc. call for the same ring index. This is deliberate: it is
   exactly how a party could, in principle, reuse an OTS key pair to sign
   twice (per WCM's own documented one-time-linkability model), and it is
   what lets a repeat submission succeed at the *signing* level at all, so
   that the detection logic described below is actually exercised rather
   than short-circuited by the guard's own reuse check.
2. The new signature is produced (`LRSignForTesting`) and verified
   (`LRVerifyForTesting`) — an invalid signature is rejected here, **before**
   any duplicate check runs.
3. Only once verified, the auction calls `LinkForTesting` between the new
   submission and **every previously accepted submission in the same
   auction**. If any comparison returns `Linked` (same OTS key pair), the
   new submission is rejected as a duplicate — the rejection reason
   explicitly says so, and is distinguishable from every other rejection
   reason.
4. Different `SealedBidAuction` instances never share a ring or OTS keys
   (each `Create()` generates its own), so there is no cross-auction state
   for `Link` to even compare against — "different auctions do not share
   linkability state" is true by construction, not by an extra guard.

## 5. Running the demo

```sh
cd python/demo
pip install -r requirements.txt
streamlit run app.py
```

The first "Generate 5 bidder key pairs" or "Create auction" click will
trigger a CMake configure+build of the small demo executables
(`lrs_keygen_cli`, `lrs_auction_cli`) under `build/python_demo`; this is
cached by Streamlit (`@st.cache_resource`) so it only happens once per
server process. The auction section launches `lrs_auction_cli` as a
**persistent** subprocess, kept alive in `st.session_state` for the
lifetime of the browser session (Streamlit reruns the whole script on every
click, so the real cryptographic auction state — the ring, the OTS keys,
the accepted signatures — has to live in that long-running process, not in
Python). Clicking "Reset demo" in the sidebar terminates it.

The line protocol `lrs_auction_cli` speaks (one command per line in, one
JSON object per line out) is documented at the top of
`python/demo/auction_cli.cpp` and can be driven directly for debugging,
e.g.:

```sh
printf 'CREATE demo1\nBID demo1 0 150\nBID demo1 0 999\nLIST demo1\n' \
  | ./build/python_demo/lrs_auction_cli
```

## 5a. LPCom bid-amount commitment and the Streamlit demo

The Live Auction page's bid flow now actually runs:

```
BID auction_id bidder_index amount
    -> lpcom::Com(amount) -> (commitment c, opening (v, r))
    -> message = "PQ-LRS/Auction/v2-LPCom" || auction_id || c
    -> LRSignForTesting(message) -> LRVerifyForTesting(message)
    -> LinkForTesting against prior accepted submissions
    -> accept/reject
```

`lrs_auction_cli` exposes two settlement-stage commands used by the new
"Settlement & Bid Verification" section of the Live Auction page:

- `OPEN_BID <auction_id> <submission_index>` — reveals the real stored
  opening for the `submission_index`-th **accepted** submission (indexed
  in acceptance order, not the full public-log order) and independently
  re-verifies it via `lpcom::Unv`.
- `VERIFY_BID_AMOUNT <auction_id> <submission_index> <claimed_amount>` —
  checks a caller-supplied claimed amount against that submission's real
  stored commitment and real stored randomness. A correct amount returns
  `verified: true`; an incorrect one (in range) returns `verified: false`;
  an out-of-range claim surfaces as a backend error, shown to the user as
  rejected either way.

`SubmissionPublicView` gained `lpcom_commitment_hex` (the real commitment
vector, hex-encoded) alongside the pre-existing `bid_commitment_hex`
(now a short hash of that commitment, kept for backward compatibility).
Neither the opening randomness `r` nor the plaintext amount is ever
placed in `SubmissionPublicView`, `PublicLog()`, or any CLI response
other than `OPEN_BID`/`VERIFY_BID_AMOUNT`'s own result.

**Important limitation, stated plainly in the UI itself:** in this demo
the bid amount is sent to the backend process as plain text, which then
computes the LPCom commitment on the bidder's behalf (the same
centralized-secret-key simplification used throughout this demo). LPCom
hides the bid from anyone who only sees the public log, the signature,
or the commitment — it does **not** hide the bid from this particular
backend process, which sees the plaintext amount before committing to
it. A real deployment would have each bidder compute their own
commitment locally, before anything reaches the auctioneer.

LPCom's own parameters used here (`n=1, k=16, m=24, q=257, sigma^2=1024,
B=157`) are an explicitly experimental, non-security-validated profile —
see `cpp_backend/include/lattice_lrs/lpcom/lpcom.hpp` and the
Parameters/Limitations tabs of the Streamlit app's Technical Details
page. They are unrelated to, and not validated the same way as, Esgin's
named `N64` profile.

## 5b. Shamir-gated threshold settlement

### Shamir's role here, precisely

Shamir does **not** split the bid, the LPCom commitment `c`, or the
opening `(v, r)` itself. It splits a **fresh, per-submission symmetric
key `K`**. The opening is encrypted under `K` (AES-256-GCM) immediately
after a bid is accepted; `K` is what gets Shamir-split across `n`
settlement trustees with threshold `t`. Recovering the opening requires
reconstructing `K` from `>= t` trustee shares, then decrypting — the
math from `shamir_secret_sharing/shamir.py`/`committee.py` (pulled
verbatim from `origin/feature/shamir-threshold`, unmodified) is used
only for the key, never for the bid data.

### Difference from LPCom

LPCom (`lpcom::Com`/`Unv`) is what makes a bid *hideable and bindable*
in the first place — it is the cryptographic commitment itself, proven
in the Cabarcas et al. paper under its own (experimental, here)
parameters. Shamir adds a completely separate, later-stage control:
*who is authorized to even attempt opening it*. LPCom's security
properties (hiding, binding) are unaffected by whether Shamir-gating
exists at all; Shamir only decides when the already-computed opening
becomes retrievable, and requires multiple parties to agree before that
happens.

### Architecture

```
SealedBidAuction::SubmitBid (unchanged) -> accepted
          |
          v  (app.py, automatically, once, right after acceptance)
EXPORT_RAW_OPENING (new CLI command) -> (amount, randomness) in Python
          |
          v
settlement_seal.seal_opening(): fresh K (shamir.generate_key, unmodified)
    -> AES-256-GCM(K, nonce, AAD=auction_id|submission_index|commitment_hex)
    -> ShamirScheme(t,n).deal_bytes(K) (unmodified) -> n shares
          |
          v
amount/randomness/K discarded; only (ciphertext, nonce) + shares kept
          |
          v  (Settlement & Bid Verification page, "Threshold-Authorized
          |   Settlement (Shamir)")
>= t simulated trustees "submit" their share (SettlementTrusteeStore)
          |
          v
ShamirScheme(t,n).open_bytes() (unmodified) -> K reconstructed
          |
          v
AES-256-GCM decrypt+authenticate -> (amount, randomness)
          |
          v
VERIFY_SEALED_OPENING (new CLI command) -> SealedBidAuction::VerifyOpening
    -> real lpcom::Unv against the STORED commitment c
          |
          v
"SETTLEMENT AUTHORIZED" + verified amount shown, ONLY now
```

### CLI additions (additive only — no existing command's behavior changed)

- `EXPORT_RAW_OPENING <auction_id> <submission_index>` — internal/sealing
  use only. Returns the full `(amount, randomness)` with no verification
  gate. More sensitive than the pre-existing `OPEN_BID` (which only
  returns the amount, already verified). Intended to be called exactly
  once, automatically, immediately after acceptance; its result is never
  rendered in the UI.
- `VERIFY_SEALED_OPENING <auction_id> <submission_index> <amount> <r_0>
  ... <r_{k-1}>` — verifies an **externally supplied** opening (e.g. one
  just reconstructed via Shamir + decrypted) against the stored
  commitment, via the real, unmodified `SealedBidAuction::VerifyOpening`.
  Does not fall back to, or get satisfied by, this process's own
  internally stored copy of the randomness.

**On "the old unrestricted reveal path cannot bypass the new threshold
authorization":** `OPEN_BID` and `VERIFY_BID_AMOUNT` (added in the LPCom
settlement task, before Shamir existed in this integration) still exist
and are unchanged — removing them was out of scope here and would
itself have violated "preserve existing functionality." They are a
**different, pre-existing code path**, not a backdoor into the new
Shamir-gated one: nothing in `seal_opening`/`unseal_opening`/
`VERIFY_SEALED_OPENING` reads from, writes to, or is satisfied by
anything `OPEN_BID`/`VERIFY_BID_AMOUNT` do. In a real (non-demo)
deployment adopting threshold settlement, the unrestricted path would
be the one to remove — that is a deployment decision, not something
this integration silently did.

### Streamlit additions

"Threshold-Authorized Settlement (Shamir)" subsection of **Settlement &
Bid Verification**: `t`-of-`n` display, a progress bar, one button per
simulated trustee (disabled once that trustee has already submitted),
and a "Reconstruct key & verify opening" button that stays disabled
below threshold and, once enabled, reconstructs `K`, decrypts, and
calls `VERIFY_SEALED_OPENING` — showing the verified amount only after
all of that succeeds.

### Limitations (stated plainly, not fixed in this task)

- **Non-verifiable Shamir.** `shamir_secret_sharing/README.md`'s own
  "Current limitations" section applies unchanged: a corrupted trustee
  share is not detected as corrupted by Shamir itself. What this
  integration adds is that a corrupted share produces the wrong `K`,
  which then fails AES-GCM authentication on decrypt — a side effect of
  the AEAD layer around Shamir, not a Shamir verification property. No
  Verifiable Secret Sharing is implemented here, by design (out of this
  task's scope).
- **Single-process simulation.** All `n` trustees are Python objects
  inside one Streamlit session — there is no network, no independent
  parties, no real distributed trust boundary. Clicking "Trustee #i"
  only moves a share within this one process's memory.
- **Plaintext-to-server, again.** `EXPORT_RAW_OPENING` necessarily
  exposes the full plaintext opening to this same Python process for
  the moment it takes to seal it — consistent with, and not a new
  instance beyond, the centralized-key limitation already documented
  for LPCom/bid submission itself (§5a above). Sealing does not retroactively
  hide what this process already saw.

## 5c. Mapping to the project synopsis's Fig. 1 workflow

The synopsis (`Project_Synopsis_Group22`) describes a 6-stage workflow:
Registration → Sealed Bidding → Oblivious Transfer → Threshold Opening →
ZK Verification → Public Result. The Live Auction page now walks through
all six, in order, against the real backend:

| Synopsis stage | Status | Where |
|---|---|---|
| 1. Registration | Implemented | Ring formation at auction creation (`RING` command); shown as its own labeled step |
| 2. Sealed Bidding | Implemented | LPCom commitment + WCM LRS (§5a) |
| 3. Oblivious Transfer | Implemented (simulated primitive) | `OT/auction_ot_adapter.py`'s `PrivateSelectionSession`, now also invoked in-flow (private fulfillment-option selection), not only on the separate OT Demo page |
| 4. Threshold Opening | Implemented | Shamir-gated settlement (§5b) |
| 5. ZK Verification | **Not implemented** | Clearly marked "Not yet implemented" in the UI, with a precise statement of what it would add (a range/max-bid proof over the still-hidden bid) and why Esgin's internal ring-membership ZK proof is a different proof for a different statement |
| 6. Public Result | Implemented | `cpp_backend/include/lattice_lrs/audit/merkle_tree.hpp` (new), via `AUDIT_ROOT`/`AUDIT_PROOF`/`AUDIT_VERIFY` |

### Merkle/hash-chain audit log (new)

`lattice_lrs::audit::MerkleAuditTree` builds a SHA3-256 Merkle tree
(same function already linked via the vendored Dilithium `fips202.c`,
not a new hash primitive) over an auction's PUBLIC submission log —
`log_index`, `ovk_fingerprint`, `lpcom_commitment_hex`, `accepted`,
`reason`, nothing else. No existing repository branch had a Merkle
implementation to reuse (checked: none of the OT, Shamir, or
ring-signature branches); this module is new, built only from the
already-linked SHA3 function. It is conceptually SEPARATE from LPCom's
hiding/binding and Shamir's threshold control — it only proves the
published log hasn't changed since publication, nothing about what the
log's entries themselves hide.

CLI: `AUDIT_ROOT <auction_id>`, `AUDIT_PROOF <auction_id> <log_index>`,
`AUDIT_VERIFY <auction_id> <log_index> <claimed_root>` — all new,
additive, read-only over the existing `PublicLog()`.

### Oblivious Transfer woven into the live flow (new UI only)

The Live Auction page's "Step 3: Oblivious Transfer" section calls the
SAME `PrivateSelectionSession` adapter as the dedicated OT Demo page —
no new OT code, no change to `SimROT`/`Sender`/`Receiver`. It is placed
between Sealed Bidding and Threshold Opening to match the synopsis's
own Fig. 1 ordering, and is clearly marked with the same "SIMULATED
OT — NOT CRYPTOGRAPHICALLY SECURE" disclosure as the standalone page.
The selection is structurally independent of the bid amount, the LPCom
commitment, and the LRS signature: nothing in `SubmitBid`, `Com`, or
`LRSign`/`LRVerify` reads this selection or is affected by it.

### What "end-to-end" means and doesn't mean here

All 6 stages are now reachable from one page, in the synopsis's order,
against the real backend (not mocks) for every stage except #5. This is
NOT a claim that the combined pipeline has been analyzed as a single
security protocol — each stage's own documented assumptions and
limitations (§3, §5a, §5b, this section) still apply exactly as stated;
composing working pieces into one flow does not by itself establish a
new, stronger security property for the whole.

## 6. Known limitations and cryptographic assumptions

Everything inherited from the base RSign/RVerify integration still applies
(see the separate bug-fix report): `Shake256AuxiliaryCommitmentProvider` is
explicitly documented as an experimental aCom construction
("hiding/binding [as] conditional assumptions, not a paper security
proof"); passing these tests establishes internal self-consistency of this
specific pipeline, not a security proof of anonymity, unforgeability, or
post-quantum security in the sense of either paper's own theorems.

WCM-specific:

- **OTS provenance.** `ovk`/`osk` are `lattice_lrs::ots` Dilithium5 (NIST
  Round 3) keys — a documented stand-in for the "very high" parameter set
  of the *original 2018* CRYSTALS-Dilithium paper WCM actually cites;
  neither Round 2 nor Round 3 is byte-identical to that original
  submission. See `dilithium_ots.hpp` for the full provenance note.
- **H' construction.** `H'` (the public-key mask) is a SHAKE256-XOF
  construction with rejection sampling — an implementation choice
  consistent with, but not dictated by, the paper's "random oracle into
  R_q^n" requirement.
- **One-time-key enforcement is in-process only.** `OneTimeOtsKeyGuard`
  enforces "this osk signs at most once" only for the lifetime of a single
  guard object in one process. It is explicitly **not** a substitute for
  real OTS key lifecycle management (persisting "this osk has been used"
  across process restarts, or across independently constructed guards
  wrapping the same underlying key bytes — which is exactly what the
  auction's own duplicate-submission path deliberately does, by design, to
  exercise `Link` rather than rely on the guard). Do not read "the guard
  enforces one-time use" as "the system prevents key reuse" — it does not,
  by itself; `Link` is the actual enforcement mechanism this auction relies
  on, and only within a single `SealedBidAuction` instance's own
  submission history.
- **One-time linkability, not general linkability.** Per WCM's own Section
  6 Discussion: a `Linked` verdict means "these two signatures were
  produced with the same OTS key pair" — nothing about a shared ring,
  message, or auction. Everything this auction built on top of `Link`
  (per-auction duplicate detection) is an application-level use of that
  primitive, not a property WCM's paper proves on its own.
- **Demo-scale parameters are not validated.** See §3 — the auction's
  dimensions were chosen for speed, confirmed to satisfy the library's own
  structural `validate()` checks, and empirically confirmed to produce
  signatures that verify — but were never run through the Section 6.1 /
  Assumption 1 / Theorem 3 security-parameter derivation the named
  profiles were. Do not reuse these parameters outside this demo.
- **Centralized secret keys in the demo.** The demo process holds every
  simulated bidder's secret key so a single operator can submit "as" any
  ring member through one UI. A real deployment would never do this; each
  bidder would hold only their own key. The public submission log never
  reveals which ring index produced a given entry, consistent with what an
  external verifier would actually see, but the "Debug view" expander
  (clearly marked as not part of the public flow) does show it, for demo
  transparency.
