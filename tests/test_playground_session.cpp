// Tests for lattice_lrs::demo::PlaygroundSession. Real cryptographic
// primitives throughout (demo-scale parameters, same real algorithms as
// ProductionLRSignContext/SealedBidAuction); no mocks.

#include "lattice_lrs/demo/playground_session.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lattice_lrs;
using namespace lattice_lrs::demo;
using namespace lattice_lrs::sampling;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint8_t> text(const char* value) {
    return std::vector<std::uint8_t>(value, value + std::char_traits<char>::length(value));
}

void test_sign_and_verify_accepts_genuine_signature() {
    SystemRandomSource random;
    PlaygroundSession session = PlaygroundSession::Create(random);
    require(session.ring_size() == 8, "playground ring size must be 8");

    const auto outcome = session.Sign(0, text("hello auction"), random);
    const VerifyResult result = session.Verify(outcome.signature_id, TamperMode::None);
    require(result.accepted, "a genuine signature must verify");
    require(result.tamper_mode == "none", "untampered verify must report mode 'none'");
}

void test_tampering_is_rejected() {
    SystemRandomSource random;
    PlaygroundSession session = PlaygroundSession::Create(random);
    const auto outcome = session.Sign(1, text("bid=100"), random);

    const VerifyResult message_result =
        session.Verify(outcome.signature_id, TamperMode::Message);
    require(!message_result.accepted, "a tampered message must be rejected");

    const VerifyResult signature_result =
        session.Verify(outcome.signature_id, TamperMode::Signature);
    require(!signature_result.accepted, "a tampered signature must be rejected");

    const VerifyResult ring_result =
        session.Verify(outcome.signature_id, TamperMode::Ring);
    require(!ring_result.accepted, "a tampered ring must be rejected");

    // The original, untouched signature must still verify after all the
    // tamper checks above -- confirms Verify() never mutates stored state.
    const VerifyResult clean_result =
        session.Verify(outcome.signature_id, TamperMode::None);
    require(clean_result.accepted,
            "the original signature must still verify after tamper checks");
}

void test_link_same_signer_is_linked() {
    SystemRandomSource random;
    PlaygroundSession session = PlaygroundSession::Create(random);
    const auto first = session.Sign(2, text("message-a"), random);
    const auto second = session.Sign(2, text("message-b"), random);

    require(first.ovk_fingerprint == second.ovk_fingerprint,
            "two signatures from the same ring member must share an ovk "
            "fingerprint");
    require(session.Link(first.signature_id, second.signature_id) ==
                lrs::LinkOutcome::Linked,
            "two signatures from the same signer must Link as Linked");
}

void test_link_different_signers_is_unlinked() {
    SystemRandomSource random;
    PlaygroundSession session = PlaygroundSession::Create(random);
    const auto first = session.Sign(3, text("message-a"), random);
    const auto second = session.Sign(5, text("message-b"), random);

    require(first.ovk_fingerprint != second.ovk_fingerprint,
            "two signatures from different ring members must carry "
            "different ovk fingerprints");
    require(session.Link(first.signature_id, second.signature_id) ==
                lrs::LinkOutcome::Unlinked,
            "two signatures from different signers must Link as Unlinked");
}

void test_independent_sessions_have_independent_rings() {
    SystemRandomSource random;
    PlaygroundSession session_a = PlaygroundSession::Create(random);
    PlaygroundSession session_b = PlaygroundSession::Create(random);
    require(session_a.RingFingerprints() != session_b.RingFingerprints(),
            "two independently created sessions must have different rings");
}

}  // namespace

int main() {
    try {
        test_sign_and_verify_accepts_genuine_signature();
        test_tampering_is_rejected();
        test_link_same_signer_is_linked();
        test_link_different_signers_is_unlinked();
        test_independent_sessions_have_independent_rings();
    } catch (const std::exception& error) {
        std::cerr << "Playground session test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "All playground session tests passed.\n";
    return EXIT_SUCCESS;
}
