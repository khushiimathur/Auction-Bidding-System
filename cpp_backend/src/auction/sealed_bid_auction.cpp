#include "lattice_lrs/auction/sealed_bid_auction.hpp"

#include "lattice_lrs/demo/demo_parameters.hpp"

extern "C" {
#include "fips202.h"
}

#include <array>
#include <sstream>
#include <stdexcept>

namespace lattice_lrs::auction {
namespace {

using lattice_lrs::proofs::Protocol2Parameters;
using lattice_lrs::proofs::PositiveRational;
using lattice_lrs::ring_signature::PublicParameters;
using lattice_lrs::ring_signature::RSetupForTesting;
using lattice_lrs::ring_signature::Shake256CToChallenges;
using lattice_lrs::ring_signature::TestOnlySetupParameters;

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

std::string to_hex(const std::uint8_t* bytes, std::size_t length) {
    static const char* kDigits = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        result.push_back(kDigits[bytes[i] >> 4]);
        result.push_back(kDigits[bytes[i] & 0x0F]);
    }
    return result;
}

std::string shake256_hex(const std::vector<std::uint8_t>& input,
                         std::size_t output_bytes) {
    std::vector<std::uint8_t> digest(output_bytes);
    shake256(digest.data(), digest.size(), input.data(), input.size());
    return to_hex(digest.data(), digest.size());
}

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(
            static_cast<std::uint64_t>(value) >> shift));
    }
}

// Deterministic (not necessarily canonical/compact) byte encoding of a
// public key's polynomial vector, used only to compute a display
// fingerprint -- NOT part of any protocol transcript. Each coefficient's
// decimal digits are length-prefixed, which is enough to make the
// encoding injective per polynomial degree/coefficient count without
// needing NTL::ZZ's own byte-serialization routines.
void append_polynomial_vector_for_fingerprint(
    std::vector<std::uint8_t>& output, const sampling::PolynomialVector& key) {
    append_size(output, key.size());
    for (const arithmetic::Polynomial& polynomial : key) {
        append_size(output, polynomial.degree());
        for (const NTL::ZZ& coefficient : polynomial.coefficients()) {
            std::ostringstream text;
            text << coefficient;
            const std::string digits = text.str();
            append_size(output, digits.size());
            output.insert(output.end(), digits.begin(), digits.end());
        }
    }
}

void append_bytes(std::vector<std::uint8_t>& output,
                  const std::vector<std::uint8_t>& bytes) {
    append_size(output, bytes.size());
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_lpcom_vector(std::vector<std::uint8_t>& output,
                         const lpcom::Vector& values) {
    append_size(output, values.size());
    for (const NTL::ZZ& coordinate : values) {
        std::ostringstream text;
        text << coordinate;
        const std::string digits = text.str();
        append_size(output, digits.size());
        output.insert(output.end(), digits.begin(), digits.end());
    }
}

std::string hex_digits_of_lpcom_vector(const lpcom::Vector& values) {
    std::ostringstream text;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) text << ',';
        text << values[i];
    }
    const std::string decimal = text.str();
    return to_hex(reinterpret_cast<const std::uint8_t*>(decimal.data()),
                 decimal.size());
}

// message = "PQ-LRS/Auction/v2-LPCom" || auction_id || commitment_c.
// This signs the LPCom COMMITMENT vector, not the bid amount itself --
// the amount never appears in anything that gets signed, verified,
// linked, or logged. As before, folding the auction id into every
// signed message means a signature produced for one auction's
// ring/parameters can never be replayed as a valid submission to a
// different auction: LRVerify recomputes the transcript/challenge hash
// over the EXACT message bytes, so a mismatch here is an ordinary
// verification failure, not a special case this file has to detect
// itself. The domain tag is bumped from v1 to v2-LPCom because the
// bytes being signed changed meaning (commitment, not amount) -- a v1
// signature could never accidentally verify as a v2 one or vice versa.
std::vector<std::uint8_t> encode_sealed_bid_commitment(
    const std::string& auction_id, const lpcom::Vector& commitment_c) {
    std::vector<std::uint8_t> encoded;
    const std::string domain = "PQ-LRS/Auction/v2-LPCom";
    append_bytes(encoded, std::vector<std::uint8_t>(domain.begin(), domain.end()));
    append_bytes(encoded,
                std::vector<std::uint8_t>(auction_id.begin(), auction_id.end()));
    append_lpcom_vector(encoded, commitment_c);
    return encoded;
}

// Parses `amount` as the ASCII decimal digits of a non-negative
// integer. Throws std::invalid_argument for anything else (empty
// input, a sign, non-digit characters) -- this is message-format
// validation, done BEFORE any LPCom commitment is attempted. LPCom's
// own message-RANGE validation (value < q) happens inside lpcom::Com
// itself.
NTL::ZZ parse_amount(const std::vector<std::uint8_t>& amount) {
    if (amount.empty()) {
        throw std::invalid_argument("bid amount must not be empty");
    }
    NTL::ZZ value(0);
    for (std::uint8_t byte : amount) {
        if (byte < '0' || byte > '9') {
            throw std::invalid_argument(
                "bid amount must be a non-negative decimal integer");
        }
        value = value * 10 + (byte - '0');
    }
    return value;
}

// Demo-scale parameters moved to lattice_lrs::demo (demo_parameters.hpp)
// so the auction and the cryptographic playground always use the exact
// same dimensions; see that header for the full rationale.
using lattice_lrs::demo::DemoCommitmentParameters;
using lattice_lrs::demo::DemoProtocol2Parameters;

void reject(SubmissionPublicView& view, std::string reason) {
    view.accepted = false;
    view.reason = std::move(reason);
}

}  // namespace

SealedBidAuction::SealedBidAuction(
    std::string auction_id, PublicParameters public_parameters,
    Protocol2Parameters proof_parameters, std::vector<AuctionBidder> bidders,
    lpcom::Parameters lpcom_params)
    : auction_id_(std::move(auction_id)),
      public_parameters_(std::move(public_parameters)),
      proof_parameters_(proof_parameters),
      bidders_(std::move(bidders)),
      transcript_encoder_(),
      auxiliary_commitment_(),
      rejection_exponential_(),
      rejection_(rejection_exponential_),
      gaussian_bundle_(),
      lpcom_params_(std::move(lpcom_params)),
      lpcom_exponential_(),
      lpcom_gaussian_(lpcom_exponential_, z(32), z(1)) {
    ring_.reserve(bidders_.size());
    for (const AuctionBidder& bidder : bidders_) {
        ring_.push_back(bidder.linkable_public_key);
    }
}

SealedBidAuction SealedBidAuction::Create(std::string auction_id,
                                          sampling::RandomSource& random) {
    TestOnlySetupParameters setup{DemoCommitmentParameters(), 3};
    auto hash_to_challenges = std::make_shared<const Shake256CToChallenges>();
    PublicParameters public_parameters =
        RSetupForTesting(setup, hash_to_challenges, random);

    std::vector<AuctionBidder> bidders;
    bidders.reserve(kDemoRingSize);
    for (std::size_t i = 0; i < kDemoRingSize; ++i) {
        lrs::LinkableKeyPair key_pair =
            lrs::LRKeygenForTesting(public_parameters, random);
        bidders.push_back(AuctionBidder{std::move(key_pair.linkable_public_key),
                                       std::move(key_pair.secret_key)});
    }

    lpcom::Parameters lpcom_params =
        lpcom::ScalarMessageDemoParameters(random);

    return SealedBidAuction(std::move(auction_id), std::move(public_parameters),
                            DemoProtocol2Parameters(), std::move(bidders),
                            std::move(lpcom_params));
}

SubmissionPublicView SealedBidAuction::SubmitBid(
    std::size_t bidder_index, const std::vector<std::uint8_t>& amount,
    sampling::RandomSource& random) {
    SubmissionPublicView view;

    if (bidder_index >= bidders_.size()) {
        reject(view, "bidder_index is not a member of this auction's ring");
        public_log_.push_back(view);
        return view;
    }

    // LPCom commitment to the bid amount, computed BEFORE anything is
    // signed. v and r (the opening) are never placed in `view` or in
    // the signed message below -- only the resulting commitment c is.
    lpcom::ComResult commitment_result;
    try {
        const NTL::ZZ amount_value = parse_amount(amount);
        commitment_result = lpcom::Com(lpcom_params_, lpcom::Vector{amount_value},
                                       lpcom_gaussian_, random);
    } catch (const std::exception& error) {
        reject(view, std::string("bid amount could not be committed: ") +
                   error.what());
        public_log_.push_back(view);
        return view;
    }

    view.lpcom_commitment_hex =
        hex_digits_of_lpcom_vector(commitment_result.commitment.c);
    view.bid_commitment_hex =
        shake256_hex(std::vector<std::uint8_t>(view.lpcom_commitment_hex.begin(),
                                               view.lpcom_commitment_hex.end()),
                    16);

    const std::vector<std::uint8_t> ovk_bytes(
        bidders_[bidder_index].secret_key.ots_public_key.bytes.begin(),
        bidders_[bidder_index].secret_key.ots_public_key.bytes.end());
    view.ovk_fingerprint = shake256_hex(ovk_bytes, 8);

    const std::vector<std::uint8_t> message = encode_sealed_bid_commitment(
        auction_id_, commitment_result.commitment.c);

    // A fresh guard wrapping a COPY of this bidder's secret key: see the
    // header's extensive comment on why this is deliberate (it is what
    // lets a dishonest or merely repeat-clicking bidder produce a SECOND
    // valid signature at all, so that Link -- not the guard -- is what
    // this auction relies on to reject the duplicate).
    lrs::OneTimeOtsKeyGuard guard(bidders_[bidder_index].secret_key);

    lrs::LinkableSignature signature;
    try {
        signature = lrs::LRSignForTesting(
            public_parameters_, proof_parameters_, ring_, bidder_index, guard,
            message, transcript_encoder_, gaussian_bundle_.provider(),
            auxiliary_commitment_, rejection_, random);
    } catch (const std::exception& error) {
        reject(view, std::string("signing failed: ") + error.what());
        public_log_.push_back(view);
        return view;
    }

    // Check 2 (per the header's documented order): a bad signature is
    // rejected before any duplicate check runs.
    const bool verified = lrs::LRVerifyForTesting(
        public_parameters_, proof_parameters_, ring_, message, signature,
        transcript_encoder_, auxiliary_commitment_);
    if (!verified) {
        reject(view, "signature failed verification");
        public_log_.push_back(view);
        return view;
    }

    // Check 3: the real cryptographic linkability mechanism, not a
    // username/session check. Compare against every PRIOR ACCEPTED
    // submission in this same auction only.
    for (const SubmissionRecord& existing : submissions_) {
        const lrs::LinkOutcome outcome = lrs::LinkForTesting(
            public_parameters_, proof_parameters_, ring_,
            existing.sealed_bid_payload, existing.signature, ring_, message,
            signature, transcript_encoder_, auxiliary_commitment_);
        if (outcome == lrs::LinkOutcome::Linked) {
            reject(view,
                  "duplicate submission: this bidder has already "
                  "submitted to this auction (detected via Link, same "
                  "one-time signature key)");
            public_log_.push_back(view);
            return view;
        }
        if (outcome == lrs::LinkOutcome::Rejected) {
            // Defensive: an already-accepted submission that suddenly
            // fails to verify again would indicate an internal
            // inconsistency, not a legitimate duplicate or a clean
            // accept.
            reject(view,
                  "internal inconsistency: a prior accepted submission "
                  "did not re-verify during the Link check");
            public_log_.push_back(view);
            return view;
        }
    }

    view.accepted = true;
    view.reason = "accepted";
    public_log_.push_back(view);

    SubmissionRecord record;
    record.bidder_index = bidder_index;
    record.sealed_bid_payload = message;
    record.signature = std::move(signature);
    record.public_view = view;
    record.commitment = std::move(commitment_result.commitment);
    record.opening = std::move(commitment_result.opening);
    submissions_.push_back(std::move(record));

    return view;
}

lpcom::Opening SealedBidAuction::RevealOpening(
    std::size_t submission_index) const {
    if (submission_index >= submissions_.size()) {
        throw std::out_of_range(
            "RevealOpening: submission_index is not an accepted submission");
    }
    return submissions_[submission_index].opening;
}

bool SealedBidAuction::VerifyOpening(std::size_t submission_index,
                                    const lpcom::Opening& opening) const {
    if (submission_index >= submissions_.size()) {
        throw std::out_of_range(
            "VerifyOpening: submission_index is not an accepted submission");
    }
    return lpcom::Unv(lpcom_params_, submissions_[submission_index].commitment,
                      opening.v, opening.r);
}

std::vector<std::string> SealedBidAuction::RingFingerprints() const {
    std::vector<std::string> fingerprints;
    fingerprints.reserve(bidders_.size());
    for (const AuctionBidder& bidder : bidders_) {
        std::vector<std::uint8_t> encoded;
        append_polynomial_vector_for_fingerprint(encoded,
                                                  bidder.linkable_public_key);
        fingerprints.push_back(shake256_hex(encoded, 8));
    }
    return fingerprints;
}

}  // namespace lattice_lrs::auction
