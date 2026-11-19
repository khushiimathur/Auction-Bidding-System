#pragma once

// Phase 3: a minimal sealed-bid auction built directly on top of the real
// WCM linkable ring signature primitives (lrs::LRKeygenForTesting/
// LRSignForTesting/LRVerifyForTesting/LinkForTesting), reusing them
// exactly as implemented -- no new cryptographic algorithm, no mocks.
//
// --- Why "ForTesting" (TestOnly) parameters, not ProductionLRSignContext's
// real N64 profile ---
// The only real, standards-reasoned ParameterProfile (N64) has a FIXED
// ring size of exactly 64 and real signing/verification times on the
// order of minutes (confirmed in
// tests/test_production_lrsign_integration.cpp). That is unusable for an
// interactive demo. This auction instead uses RSetupForTesting with a
// small, explicit commitment::Parameters/Protocol2Parameters
// configuration (degree=64, n=1, m=2, k=3, beta=2 -> ring size 8,
// repetitions=3, phi1=phi2=22, q a 41-bit prime), empirically measured
// at well under two seconds per sign/verify -- see the timing check this
// configuration was derived from (same real providers as
// ProductionLRSignContext: SigmaSection6GaussianProviderBundle,
// Section6BatchRejectionProvider, Shake256AuxiliaryCommitmentProvider,
// real Dilithium5 OTS, real H' masking). This is SMALLER and NOT
// validated against Esgin's Section 6.1 security analysis (no
// Assumption-1/Theorem-3 bound derivation was done for these dimensions,
// unlike the named profiles) -- it is explicitly a DEMO-SCALE
// configuration, not a security claim, and is labelled as such
// everywhere it surfaces (including in the Streamlit UI). It is NOT a
// mock: every algorithm, every provider, and every check that runs for
// ParameterProfile::N64() also runs here, unchanged, just at smaller
// dimensions.
//
// --- How duplicate-submission detection actually works (read before
// changing anything here) ---
// This auction does NOT use any bidder-name/ID/session-token check. Each
// SubmitBid call constructs a FRESH lrs::OneTimeOtsKeyGuard wrapping a
// COPY of the bidder's LinkableSecretKey (the guard enforces "this guard
// object signs once", not "this ovk signs once" -- copying the secret
// key and wrapping it in a new guard is exactly how WCM's one-time
// linkability is INTENDED to be exercised twice: see
// linkable_ring_signature.hpp's own documentation of this). That means a
// bidder CAN produce a second, independently valid signature in the same
// auction. What rejects it as a duplicate is this auction layer calling
// lrs::LinkForTesting between the new submission and every PREVIOUSLY
// ACCEPTED submission in the SAME auction (and only the same auction --
// a bidder's ring entry and OTS keys in a different SealedBidAuction
// instance are entirely separate, so cross-auction linkage never even
// has inputs that could match): if any prior accepted submission Links
// (same OTS key pair) with the new one, the new one is rejected as a
// duplicate. This is exactly "the actual cryptographic linkability
// mechanism", not a username lookup.
//
// --- What this auction does NOT claim ---
// - It does not claim the demo-scale parameters above are secure; see
//   the comment above and the Streamlit UI's own disclosure.
// - It does not claim bidder anonymity is unconditional: this process
//   holds every bidder's secret key centrally (it simulates all
//   bidders, standing in for what would otherwise be N separate
//   parties each holding only their own key) purely so one demo process
//   can submit "as" any ring member; a real deployment would never
//   centralize secret keys this way. The PUBLIC submission log (see
//   Submission::public_view()) never includes which ring index signed,
//   consistent with what a real verifier would see.
// - It does not claim WCM's formal Linkability/Nonslanderability
//   security properties; see link.hpp's own disclaimer, which applies
//   unchanged here.

#include "lattice_lrs/lpcom/lpcom.hpp"
#include "lattice_lrs/lrs/link.hpp"
#include "lattice_lrs/lrs/linkable_ring_signature.hpp"
#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/bernoulli_pi_exponential.hpp"
#include "lattice_lrs/proofs/discrete_gaussian_s.hpp"
#include "lattice_lrs/proofs/production_gaussian_provider.hpp"
#include "lattice_lrs/proofs/shake256_auxiliary_commitment.hpp"
#include "lattice_lrs/ring_signature/canonical_rsign_transcript.hpp"
#include "lattice_lrs/ring_signature/production_rejection_provider.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lattice_lrs::auction {

// Demo-scale ring size, fixed by the parameter choice documented above
// (k=3, beta=2 => ring_size = beta^k = 8).
inline constexpr std::size_t kDemoRingSize = 8;

// One ring member as the auction layer sees it: the public key every
// verifier (including the "public" view) can see, plus the secret key
// this DEMO process holds on that bidder's behalf (see the file-level
// comment on secret-key centralization). Real deployments would keep
// `secret_key` with the bidder, never with the auction.
struct AuctionBidder {
    sampling::PolynomialVector linkable_public_key;
    lrs::LinkableSecretKey secret_key;
};

// A single submission's PUBLIC view: what a real verifier (or the
// public Streamlit page) is allowed to see. Deliberately excludes which
// ring index signed, the bidder's secret key, and the plaintext bid
// payload (only a hash of it, preserving the "sealed" property) --
// see sealed_bid_auction.cpp's encode_sealed_bid/hash_bid_commitment.
struct SubmissionPublicView {
    std::string ovk_fingerprint;  // short hex digest of the OTS public key
                                  // (ovk) -- a pseudonymous per-signer tag,
                                  // NOT the ring index or bidder identity.
    std::string bid_commitment_hex;  // short display fingerprint (hash) of
                                     // the real LPCom commitment vector c
                                     // below -- kept under this name for
                                     // compatibility with callers written
                                     // before LPCom was integrated.
    std::string lpcom_commitment_hex;  // the ACTUAL LPCom commitment vector
                                       // c (Cabarcas et al. 2015/628,
                                       // Figure 1), hex-encoded coordinate
                                       // by coordinate -- this, not a bid
                                       // amount, is what SubmitBid's LRS
                                       // signature below actually covers.
                                       // Publishing c is exactly what
                                       // "sealed bid" means here: the
                                       // commitment is public, the opening
                                       // (v, r) is not (see RevealOpening).
    bool accepted = false;
    std::string reason;  // "accepted", or why it was rejected.
};

// Internal record (not part of the public API surface this file
// exposes to callers who only need the public view). `opening` is the
// LPCom opening (the bid amount v and the commitment randomness r) --
// it MUST NEVER be copied into a SubmissionPublicView or PublicLog();
// the only sanctioned way it leaves this object is RevealOpening(),
// which a caller invokes only at the settlement stage.
struct SubmissionRecord {
    std::size_t bidder_index = 0;
    std::vector<std::uint8_t> sealed_bid_payload;  // auction_id || commitment
    lrs::LinkableSignature signature;
    SubmissionPublicView public_view;
    lpcom::Commitment commitment;
    lpcom::Opening opening;
};

class SealedBidAuction final {
public:
    // Generates a fresh, demo-scale ring of kDemoRingSize bidder key
    // pairs via lrs::LRKeygenForTesting (real algorithm, TestOnly-scale
    // parameters -- see file header). Each auction gets its OWN ring:
    // two SealedBidAuction instances never share a ring entry or OTS
    // key, which is what makes "different auctions do not share
    // linkability state" true by construction, not by an extra check.
    static SealedBidAuction Create(std::string auction_id,
                                   sampling::RandomSource& random);

    SealedBidAuction(const SealedBidAuction&) = delete;
    SealedBidAuction& operator=(const SealedBidAuction&) = delete;
    SealedBidAuction(SealedBidAuction&&) = default;
    SealedBidAuction& operator=(SealedBidAuction&&) = delete;

    const std::string& auction_id() const noexcept { return auction_id_; }
    std::size_t ring_size() const noexcept { return kDemoRingSize; }
    std::size_t submission_count() const noexcept { return submissions_.size(); }

    // Submits a sealed bid as ring member `bidder_index`. `amount` is a
    // decimal ASCII byte string naming the bid amount. It is parsed into
    // an LPCom message v = (amount) and committed via lpcom::Com BEFORE
    // anything is signed: v and the fresh randomness r it generates
    // never appear in the signed message, the public view, or anywhere
    // in PublicLog() -- only the resulting commitment vector c does.
    // That commitment vector (not the amount) is folded together with
    // this auction's id into the signed message, so a signature from
    // one auction can never be replayed as a valid submission to a
    // different auction (LRVerify would recompute a different
    // H'-masked ring / transcript and reject it) -- this is the
    // auction-level use of the message field linkable_ring_signature.hpp's
    // own documentation says WCM leaves to the application.
    //
    // Order of checks, per the Phase 3 requirement that invalid
    // signatures are rejected BEFORE duplicate-submission checks:
    //   1. bidder_index must be a valid ring member.
    //   2. amount must parse as a non-negative integer strictly less
    //      than the LPCom modulus q (LPCom's message-range validation);
    //      a violation rejects immediately, before any commitment is
    //      even attempted.
    //   3. Compute the LPCom commitment (c, (v, r)) for the amount.
    //   4. Sign, then LRVerify the result; a verification failure
    //      rejects immediately (this should not happen for a correctly
    //      constructed signature, but is checked explicitly rather than
    //      assumed).
    //   5. Only once verified: Link against every PRIOR ACCEPTED
    //      submission in this SAME auction. Any Linked result rejects
    //      this submission as a duplicate. Any Rejected result (an
    //      inconsistency with an already-verified prior submission)
    //      rejects defensively.
    //   6. Otherwise, accept and record it (commitment public, opening
    //      private).
    SubmissionPublicView SubmitBid(std::size_t bidder_index,
                                  const std::vector<std::uint8_t>& amount,
                                  sampling::RandomSource& random);

    // The LPCom public parameters (pk = (A1, A2), q, sigma^2, B) this
    // auction's commitments were generated under -- needed by any
    // caller that wants to independently run lpcom::Unv itself (e.g. a
    // settlement process that is not this object).
    const lpcom::Parameters& lpcom_parameters() const noexcept {
        return lpcom_params_;
    }

    // SETTLEMENT-STAGE ONLY. Reveals the private LPCom opening (bid
    // amount v and commitment randomness r) of the `submission_index`-th
    // ACCEPTED submission (indexing matches the order submissions were
    // ACCEPTED in -- i.e. this object's internal `submissions_`, NOT
    // PublicLog(), which also contains rejected entries with no
    // opening at all). Calling this is what it means for a bidder to
    // "reveal" their bid; a real deployment would call it only once
    // settlement begins, never during bidding, and the result must
    // never be written into any public log. Throws std::out_of_range
    // for an invalid index.
    lpcom::Opening RevealOpening(std::size_t submission_index) const;

    // SETTLEMENT-STAGE ONLY. Verifies an (externally supplied) opening
    // against the `submission_index`-th accepted submission's STORED
    // commitment via lpcom::Unv -- this does NOT trust
    // RevealOpening()'s own return value, so a caller that wants to
    // confirm "does this revealed (v, r) actually open this
    // commitment" gets a real, independent check, not a tautology.
    // Returns false (never throws) for an opening that fails Unv;
    // throws std::out_of_range for an invalid submission_index.
    bool VerifyOpening(std::size_t submission_index,
                       const lpcom::Opening& opening) const;

    // The public submission log, in submission order -- exactly what a
    // public verification page may display.
    const std::vector<SubmissionPublicView>& PublicLog() const noexcept {
        return public_log_;
    }

    // A short, deterministic hash of each ring member's PUBLIC key
    // pk_i = p̂k_i + H'(ovk_i) (see linkable_ring_signature.hpp), in ring
    // order, fixed at Create() time -- this is the ring WCM's own
    // LRSign/LRVerify actually operate over (RSign internally requires
    // `signer_index` to name a real entry in this exact list; RVerify
    // recomputes it and rejects a mismatch). Exposed purely so a demo
    // can SHOW ring formation (8 fixed, independent public keys) before
    // any bid is submitted -- it is not a secret and reveals nothing
    // about any bidder's OTS key pair, which is what submissions are
    // actually linked on.
    std::vector<std::string> RingFingerprints() const;

private:
    SealedBidAuction(std::string auction_id,
                     ring_signature::PublicParameters public_parameters,
                     proofs::Protocol2Parameters proof_parameters,
                     std::vector<AuctionBidder> bidders,
                     lpcom::Parameters lpcom_params);

    std::string auction_id_;
    ring_signature::PublicParameters public_parameters_;
    proofs::Protocol2Parameters proof_parameters_;
    std::vector<AuctionBidder> bidders_;
    proofs::Protocol2PublicList ring_;

    ring_signature::CanonicalRSignTranscriptEncoder transcript_encoder_;
    proofs::Shake256AuxiliaryCommitmentProvider auxiliary_commitment_;
    proofs::ExactBernoulliExponentialProvider rejection_exponential_;
    ring_signature::Section6BatchRejectionProvider rejection_;
    proofs::SigmaSection6GaussianProviderBundle gaussian_bundle_;

    // LPCom (bid-amount commitment, Cabarcas et al. 2015/628) state --
    // entirely separate from the WCM ring-signature providers above.
    // lpcom_exponential_/lpcom_gaussian_ follow the same
    // self-referencing-member pattern already used by
    // rejection_exponential_/rejection_ above (see that pair): declared
    // and constructed in this exact order so lpcom_gaussian_'s
    // reference to lpcom_exponential_ is always valid for this object's
    // lifetime.
    lpcom::Parameters lpcom_params_;
    proofs::ExactBernoulliPiExponentialProvider lpcom_exponential_;
    proofs::ExactDiscreteGaussianSProvider lpcom_gaussian_;

    std::vector<SubmissionRecord> submissions_;
    std::vector<SubmissionPublicView> public_log_;
};

}  // namespace lattice_lrs::auction
