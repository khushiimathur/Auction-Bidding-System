// Phase 3 tests for lattice_lrs::auction::SealedBidAuction. Real
// cryptographic primitives throughout (see sealed_bid_auction.hpp's
// file-level comment for the demo-scale parameter rationale); no mocks.

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

void test_valid_bid_is_accepted() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("auction-A", random);
    require(auction.ring_size() == kDemoRingSize,
            "the demo ring size must match kDemoRingSize");

    const SubmissionPublicView result =
        auction.SubmitBid(0, amount_bytes(100), random);
    require(result.accepted, "a genuine first-time bid must be accepted: " +
                                 result.reason);
    require(!result.ovk_fingerprint.empty(),
            "an accepted submission must carry a non-empty ovk fingerprint");
    require(auction.submission_count() == 1,
            "an accepted submission must be recorded");
}

void test_duplicate_submission_from_same_bidder_is_rejected() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("auction-B", random);

    const SubmissionPublicView first =
        auction.SubmitBid(2, amount_bytes(50), random);
    require(first.accepted, "the first submission must be accepted");

    const SubmissionPublicView second =
        auction.SubmitBid(2, amount_bytes(200), random);
    require(!second.accepted,
            "a second submission from the SAME ring member must be "
            "rejected as a duplicate, even with a different bid amount "
            "and a freshly-signed signature");
    require(second.reason.find("duplicate") != std::string::npos,
            "the rejection reason must identify this as a duplicate, not "
            "a generic failure: " + second.reason);
    require(auction.submission_count() == 1,
            "a rejected duplicate must not be recorded as a submission");

    // The two signatures share the same underlying OTS key, so their
    // public ovk fingerprints must match -- this is the actual
    // cryptographic signal the duplicate check used, not a coincidence.
    require(first.ovk_fingerprint == second.ovk_fingerprint,
            "same-bidder resubmissions must carry the same ovk "
            "fingerprint (this is the property Link actually detects)");
}

void test_different_bidders_can_both_submit() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("auction-C", random);

    const SubmissionPublicView bidder_1 =
        auction.SubmitBid(1, amount_bytes(10), random);
    const SubmissionPublicView bidder_3 =
        auction.SubmitBid(3, amount_bytes(20), random);

    require(bidder_1.accepted, "bidder 1's submission must be accepted");
    require(bidder_3.accepted, "bidder 3's submission must be accepted");
    require(auction.submission_count() == 2,
            "two distinct bidders must both be recorded");
    require(bidder_1.ovk_fingerprint != bidder_3.ovk_fingerprint,
            "different bidders must carry different ovk fingerprints");
}

void test_same_bidder_different_auctions_both_accepted() {
    SystemRandomSource random;
    // Two SEPARATE auctions: each Create() generates its own fresh ring
    // and OTS keys, so "bidder index 4" in one auction shares no
    // cryptographic material with "bidder index 4" in the other --
    // there is no shared linkability state between them to even check.
    SealedBidAuction auction_1 = SealedBidAuction::Create("auction-D1", random);
    SealedBidAuction auction_2 = SealedBidAuction::Create("auction-D2", random);

    const SubmissionPublicView first =
        auction_1.SubmitBid(4, amount_bytes(150), random);
    const SubmissionPublicView second =
        auction_2.SubmitBid(4, amount_bytes(150), random);

    require(first.accepted, "the first auction's submission must be accepted");
    require(second.accepted,
            "the SAME ring index submitting to a DIFFERENT auction must "
            "also be accepted -- different auctions do not share "
            "linkability state");
    require(first.ovk_fingerprint != second.ovk_fingerprint,
            "even at the same ring index, a different auction's OTS key "
            "pair is entirely independent, so the fingerprints must differ");
}

void test_invalid_bidder_index_is_rejected_before_any_duplicate_check() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("auction-E", random);

    const SubmissionPublicView result =
        auction.SubmitBid(kDemoRingSize, amount_bytes(1), random);
    require(!result.accepted,
            "an out-of-range bidder index must be rejected");
    require(auction.submission_count() == 0,
            "a rejected submission must not be recorded");
}

void test_public_log_never_reveals_amount_or_bidder_index() {
    SystemRandomSource random;
    SealedBidAuction auction = SealedBidAuction::Create("auction-F", random);
    (void)auction.SubmitBid(5, amount_bytes(123), random);

    const auto& log = auction.PublicLog();
    require(log.size() == 1, "one submission must appear in the public log");
    const std::string amount_text = "123";
    require(log[0].bid_commitment_hex.find(amount_text) == std::string::npos,
            "the public log's bid commitment must be a hash, not the "
            "plaintext amount");
    // SubmissionPublicView has no bidder-index field at all; this is a
    // compile-time guarantee, not just a runtime check, but we restate
    // the intent here for documentation.
    require(!log[0].ovk_fingerprint.empty(),
            "the public log's pseudonymous tag must still be present");
}

}  // namespace

int main() {
    try {
        test_valid_bid_is_accepted();
        test_duplicate_submission_from_same_bidder_is_rejected();
        test_different_bidders_can_both_submit();
        test_same_bidder_different_auctions_both_accepted();
        test_invalid_bidder_index_is_rejected_before_any_duplicate_check();
        test_public_log_never_reveals_amount_or_bidder_index();
    } catch (const std::exception& error) {
        std::cerr << "Sealed-bid auction test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "All sealed-bid auction tests passed.\n";
    return EXIT_SUCCESS;
}
