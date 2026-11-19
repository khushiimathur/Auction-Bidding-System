// A small, long-running line-protocol server wrapping
// lattice_lrs::auction::SealedBidAuction for the Streamlit demo (Phase
// 4). Streamlit reruns its whole script on every interaction, so a
// one-shot CLI (like keygen_cli.cpp) cannot hold auction state between
// clicks; this process is instead launched ONCE per browser session (see
// app.py) and kept alive for that session's lifetime, communicating over
// its stdin/stdout pipes.
//
// Protocol: one plain-text command per line on stdin, one JSON response
// per line on stdout (flushed immediately). Commands:
//   CREATE <auction_id>
//   BID <auction_id> <bidder_index> <amount>
//   LIST <auction_id>
//   RING <auction_id>
//   AUCTIONS
//   PLAYGROUND_RESET
//   PLAYGROUND_SIGN <signer_index> <message...rest of line>
//   PLAYGROUND_VERIFY <signature_id> <none|message|signature|ring>
//   PLAYGROUND_LINK <signature_id_a> <signature_id_b>
// No JSON parsing is needed for requests (kept deliberately simple,
// whitespace-separated fields, except PLAYGROUND_SIGN's message which
// takes the rest of the line); responses are hand-written JSON, the
// same style keygen_cli.cpp already uses in this directory.
//
// The playground is a SEPARATE, independent real-crypto session from
// every SealedBidAuction (see playground_session.hpp): it demonstrates
// raw sign/verify/tamper/link one step at a time, with no auction
// semantics (no duplicate detection). PLAYGROUND_RESET starts a fresh
// ring/keys; calling it again discards the previous playground session
// entirely (any earlier signature ids become invalid).

#include "lattice_lrs/auction/sealed_bid_auction.hpp"
#include "lattice_lrs/demo/playground_session.hpp"
#include "lattice_lrs/sampling/random_source.hpp"

#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace lattice_lrs;
using namespace lattice_lrs::auction;
using lattice_lrs::demo::PlaygroundSession;
using lattice_lrs::demo::TamperMode;

namespace {

std::string json_escape(const std::string& text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (char character : text) {
        switch (character) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            default: escaped += character;
        }
    }
    return escaped;
}

void write_submission_json(std::ostream& output,
                           const SubmissionPublicView& view) {
    output << "{\"ovk_fingerprint\":\"" << json_escape(view.ovk_fingerprint)
           << "\",\"bid_commitment_hex\":\""
           << json_escape(view.bid_commitment_hex) << "\",\"accepted\":"
           << (view.accepted ? "true" : "false") << ",\"reason\":\""
           << json_escape(view.reason) << "\"}";
}

void write_error(const std::string& message) {
    std::cout << "{\"ok\":false,\"error\":\"" << json_escape(message)
              << "\"}" << std::endl;
}

void write_fingerprint_array(std::ostream& output,
                             const std::vector<std::string>& fingerprints) {
    output << '[';
    for (std::size_t i = 0; i < fingerprints.size(); ++i) {
        if (i != 0) output << ',';
        output << "\"" << json_escape(fingerprints[i]) << "\"";
    }
    output << ']';
}

TamperMode parse_tamper_mode(const std::string& text) {
    if (text == "message") return TamperMode::Message;
    if (text == "signature") return TamperMode::Signature;
    if (text == "ring") return TamperMode::Ring;
    return TamperMode::None;
}

}  // namespace

int main() {
    sampling::SystemRandomSource random;
    // auction_id -> auction, in creation order (also used for the
    // AUCTIONS listing).
    std::vector<std::string> auction_order;
    std::map<std::string, SealedBidAuction> auctions;
    std::unique_ptr<PlaygroundSession> playground;

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream tokens(line);
        std::string command;
        tokens >> command;

        if (command == "CREATE") {
            std::string auction_id;
            tokens >> auction_id;
            if (auction_id.empty()) {
                write_error("CREATE requires an auction_id");
                continue;
            }
            if (auctions.find(auction_id) != auctions.end()) {
                write_error("an auction with this id already exists");
                continue;
            }
            try {
                SealedBidAuction auction =
                    SealedBidAuction::Create(auction_id, random);
                auction_order.push_back(auction_id);
                auctions.emplace(auction_id, std::move(auction));
                std::cout << "{\"ok\":true,\"auction_id\":\""
                          << json_escape(auction_id) << "\",\"ring_size\":"
                          << kDemoRingSize << "}" << std::endl;
            } catch (const std::exception& error) {
                write_error(std::string("auction creation failed: ") +
                           error.what());
            }
            continue;
        }

        if (command == "BID") {
            std::string auction_id;
            std::size_t bidder_index = 0;
            std::string amount;
            tokens >> auction_id >> bidder_index >> amount;
            auto iterator = auctions.find(auction_id);
            if (iterator == auctions.end()) {
                write_error("no such auction");
                continue;
            }
            const std::vector<std::uint8_t> amount_bytes(amount.begin(),
                                                         amount.end());
            try {
                const SubmissionPublicView view = iterator->second.SubmitBid(
                    bidder_index, amount_bytes, random);
                std::cout << "{\"ok\":true,\"submission\":";
                write_submission_json(std::cout, view);
                std::cout << "}" << std::endl;
            } catch (const std::exception& error) {
                write_error(std::string("bid submission failed: ") +
                           error.what());
            }
            continue;
        }

        if (command == "LIST") {
            std::string auction_id;
            tokens >> auction_id;
            auto iterator = auctions.find(auction_id);
            if (iterator == auctions.end()) {
                write_error("no such auction");
                continue;
            }
            std::cout << "{\"ok\":true,\"auction_id\":\""
                      << json_escape(auction_id) << "\",\"ring_size\":"
                      << iterator->second.ring_size()
                      << ",\"submissions\":[";
            const auto& log = iterator->second.PublicLog();
            for (std::size_t i = 0; i < log.size(); ++i) {
                if (i != 0) std::cout << ',';
                write_submission_json(std::cout, log[i]);
            }
            std::cout << "]}" << std::endl;
            continue;
        }

        if (command == "RING") {
            std::string auction_id;
            tokens >> auction_id;
            auto iterator = auctions.find(auction_id);
            if (iterator == auctions.end()) {
                write_error("no such auction");
                continue;
            }
            std::cout << "{\"ok\":true,\"auction_id\":\""
                      << json_escape(auction_id) << "\",\"ring\":[";
            const std::vector<std::string> fingerprints =
                iterator->second.RingFingerprints();
            for (std::size_t i = 0; i < fingerprints.size(); ++i) {
                if (i != 0) std::cout << ',';
                std::cout << "\"" << json_escape(fingerprints[i]) << "\"";
            }
            std::cout << "]}" << std::endl;
            continue;
        }

        if (command == "AUCTIONS") {
            std::cout << "{\"ok\":true,\"auctions\":[";
            for (std::size_t i = 0; i < auction_order.size(); ++i) {
                if (i != 0) std::cout << ',';
                const std::string& auction_id = auction_order[i];
                const SealedBidAuction& auction = auctions.at(auction_id);
                std::cout << "{\"auction_id\":\"" << json_escape(auction_id)
                          << "\",\"ring_size\":" << auction.ring_size()
                          << ",\"submission_count\":"
                          << auction.submission_count() << "}";
            }
            std::cout << "]}" << std::endl;
            continue;
        }

        if (command == "PLAYGROUND_RESET") {
            try {
                playground = std::make_unique<PlaygroundSession>(
                    PlaygroundSession::Create(random));
                std::cout << "{\"ok\":true,\"ring_size\":"
                          << playground->ring_size() << ",\"ring\":";
                write_fingerprint_array(std::cout, playground->RingFingerprints());
                std::cout << "}" << std::endl;
            } catch (const std::exception& error) {
                write_error(std::string("playground reset failed: ") +
                           error.what());
            }
            continue;
        }

        if (command == "PLAYGROUND_SIGN") {
            if (!playground) {
                write_error("no playground session; send PLAYGROUND_RESET first");
                continue;
            }
            std::size_t signer_index = 0;
            tokens >> signer_index;
            std::string message;
            std::getline(tokens, message);
            if (!message.empty() && message.front() == ' ') {
                message.erase(0, 1);
            }
            const std::vector<std::uint8_t> message_bytes(message.begin(),
                                                           message.end());
            try {
                const PlaygroundSession::SignOutcome outcome =
                    playground->Sign(signer_index, message_bytes, random);
                std::cout << "{\"ok\":true,\"signature_id\":"
                          << outcome.signature_id << ",\"pk_fingerprint\":\""
                          << json_escape(outcome.pk_fingerprint)
                          << "\",\"ovk_fingerprint\":\""
                          << json_escape(outcome.ovk_fingerprint) << "\"}"
                          << std::endl;
            } catch (const std::exception& error) {
                write_error(std::string("signing failed: ") + error.what());
            }
            continue;
        }

        if (command == "PLAYGROUND_VERIFY") {
            if (!playground) {
                write_error("no playground session; send PLAYGROUND_RESET first");
                continue;
            }
            std::size_t signature_id = 0;
            std::string mode_text;
            tokens >> signature_id >> mode_text;
            try {
                const auto result =
                    playground->Verify(signature_id, parse_tamper_mode(mode_text));
                std::cout << "{\"ok\":true,\"accepted\":"
                          << (result.accepted ? "true" : "false")
                          << ",\"tamper_mode\":\""
                          << json_escape(result.tamper_mode) << "\"}"
                          << std::endl;
            } catch (const std::exception& error) {
                write_error(std::string("verification failed: ") + error.what());
            }
            continue;
        }

        if (command == "PLAYGROUND_LINK") {
            if (!playground) {
                write_error("no playground session; send PLAYGROUND_RESET first");
                continue;
            }
            std::size_t signature_id_a = 0;
            std::size_t signature_id_b = 0;
            tokens >> signature_id_a >> signature_id_b;
            try {
                const lrs::LinkOutcome outcome =
                    playground->Link(signature_id_a, signature_id_b);
                const char* outcome_text =
                    outcome == lrs::LinkOutcome::Linked ? "linked"
                    : outcome == lrs::LinkOutcome::Unlinked ? "unlinked"
                                                            : "rejected";
                std::cout << "{\"ok\":true,\"outcome\":\"" << outcome_text
                          << "\"}" << std::endl;
            } catch (const std::exception& error) {
                write_error(std::string("link check failed: ") + error.what());
            }
            continue;
        }

        if (command == "PLAYGROUND_RING") {
            if (!playground) {
                write_error("no playground session; send PLAYGROUND_RESET first");
                continue;
            }
            std::cout << "{\"ok\":true,\"ring_size\":" << playground->ring_size()
                      << ",\"ring\":";
            write_fingerprint_array(std::cout, playground->RingFingerprints());
            std::cout << "}" << std::endl;
            continue;
        }

        if (command.empty()) continue;
        write_error("unknown command: " + command);
    }

    return 0;
}
