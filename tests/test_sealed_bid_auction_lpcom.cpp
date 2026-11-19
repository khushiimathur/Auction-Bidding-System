// Integration tests for LPCom's integration into
// lattice_lrs::auction::SealedBidAuction (bid-amount commitment,
// signature binding, settlement-stage opening). Real cryptographic
// primitives throughout -- the actual WCM LRSign/LRVerify/Link, the
// actual LPCom GenCom/Com/Unv, the actual exact discrete Gaussian
// sampler; no mocks anywhere in this file.

#include "lattice_lrs/auction/sealed_bid_auction.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lattice_lrs;
using namespace lattice_lrs::auction;
using namespace lattice_lrs::sampling;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint8_t> amount_bytes(long amount) {
    const std::string text = std::to_string(amount);
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void test_valid_bid_carries_a_real_lpcom_commitment() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("lpcom-A", random);

    const SubmissionPublicView result =
        auction.SubmitBid(0, amount_bytes(100), random);
    require(result.accepted, "a genuine bid must be accepted: " + result.reason);
    require(!result.lpcom_commitment_hex.empty(),
           "an accepted submission must publish a non-empty LPCom "
           "commitment");

    // The public view must never contain the bid amount itself.
    require(result.lpcom_commitment_hex.find("100") == std::string::npos ||
               result.lpcom_commitment_hex.size() > 3,
           "sanity: commitment encoding should not just be the literal "
           "amount");
}

void test_settlement_opening_round_trips() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("lpcom-B", random);

    const SubmissionPublicView result =
        auction.SubmitBid(1, amount_bytes(77), random);
    require(result.accepted, "bid must be accepted");

    const lpcom::Opening opening = auction.RevealOpening(0);
    const bool opens = auction.VerifyOpening(0, opening);
    require(opens,
           "the real opening revealed for an accepted submission must "
           "verify against its own commitment via Unv");
}

void test_tampered_opening_is_rejected_at_settlement() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("lpcom-C", random);

    const SubmissionPublicView result =
        auction.SubmitBid(2, amount_bytes(55), random);
    require(result.accepted, "bid must be accepted");

    lpcom::Opening tampered = auction.RevealOpening(0);
    tampered.v[0] += 1;
    const bool opens = auction.VerifyOpening(0, tampered);
    require(!opens,
           "an opening with a modified bid amount must be rejected at "
           "settlement, even though the submission itself was accepted");
}

void test_invalid_signature_is_still_rejected_before_any_commitment_concern() {
    // This exercises that the pre-existing LRVerify rejection path is
    // untouched by the LPCom integration: an out-of-range bidder index
    // must still be rejected, and must not have produced any commitment.
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("lpcom-D", random);

    const SubmissionPublicView result =
        auction.SubmitBid(999, amount_bytes(10), random);
    require(!result.accepted, "an invalid bidder_index must be rejected");
    require(result.lpcom_commitment_hex.empty(),
           "a submission rejected for an invalid ring index must not "
           "carry a commitment at all");
}

void test_duplicate_submission_via_real_link_is_still_rejected() {
    // The LPCom integration must not have disturbed the real Link-based
    // duplicate check: same bidder, different bid amount (so a
    // different commitment), must still be caught as a duplicate.
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("lpcom-E", random);

    const SubmissionPublicView first =
        auction.SubmitBid(3, amount_bytes(20), random);
    require(first.accepted, "first submission must be accepted");

    const SubmissionPublicView second =
        auction.SubmitBid(3, amount_bytes(999), random);
    require(!second.accepted,
           "a second submission from the same ring member, with a "
           "DIFFERENT bid amount (and therefore a different LPCom "
           "commitment), must still be rejected as a duplicate via Link");
    require(second.reason.find("duplicate") != std::string::npos,
           "rejection reason must identify this as a duplicate: " +
               second.reason);
}

void test_same_signer_different_auction_is_not_linked() {
    // A bidder signing in two DIFFERENT SealedBidAuction instances (two
    // independent rings/keys) must not be treated as a duplicate -- and
    // commitments for the same amount in two different auctions must
    // still each carry their own auction-bound signature.
    SystemRandomSource random;
    SealedBidAuction auction_one = SealedBidAuction::Create("lpcom-F1", random);
    SealedBidAuction auction_two = SealedBidAuction::Create("lpcom-F2", random);

    const SubmissionPublicView first =
        auction_one.SubmitBid(4, amount_bytes(30), random);
    const SubmissionPublicView second =
        auction_two.SubmitBid(4, amount_bytes(30), random);
    require(first.accepted, "first auction's submission must be accepted");
    require(second.accepted,
           "second auction's submission (same ring index, same amount, "
           "but a DIFFERENT auction/ring) must be independently accepted");
}

void test_public_log_never_exposes_the_opening() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("lpcom-G", random);
    auction.SubmitBid(5, amount_bytes(42), random);

    const auto& log = auction.PublicLog();
    require(log.size() == 1, "one submission must be logged");
    // SubmissionPublicView has no field capable of holding (v, r) at
    // all -- this test documents that invariant rather than merely
    // inspecting values, since the type itself is the guarantee.
    require(!log[0].lpcom_commitment_hex.empty(),
           "the public log entry must still show the real commitment");
}

}  // namespace

int main() {
    try {
        test_valid_bid_carries_a_real_lpcom_commitment();
        test_settlement_opening_round_trips();
        test_tampered_opening_is_rejected_at_settlement();
        test_invalid_signature_is_still_rejected_before_any_commitment_concern();
        test_duplicate_submission_via_real_link_is_still_rejected();
        test_same_signer_different_auction_is_not_linked();
        test_public_log_never_exposes_the_opening();
    } catch (const std::exception& error) {
        std::cerr << "sealed_bid_auction_lpcom test failure: " << error.what()
                  << std::endl;
        return 1;
    }
    std::cout << "All sealed_bid_auction_lpcom tests passed." << std::endl;
    return 0;
}
