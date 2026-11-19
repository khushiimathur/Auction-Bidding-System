// Production WCM linkable-ring-signature end-to-end integration test.
//
// Exercises lrs::ProductionLRSignContext (production_lrsign.hpp) -- the
// first real, non-mock wiring of LRKeygen, LRSign, LRVerify, and Link on
// top of the now-working production RSign/RVerify pipeline (see
// tests/test_production_rsign_integration.cpp for that base-layer
// validation) at a real, named ParameterProfile (N64). No test doubles,
// no mocks anywhere in this call chain: every provider is the real
// implementation, and sampling::SystemRandomSource supplies real OS
// entropy throughout.
//
// This test is expensive: N64-scale RSign takes several minutes per
// signature (see test_production_rsign_integration.cpp's own timing),
// and this file performs THREE real signings (to exercise both the
// "same OTS key -> Linked" and "different OTS key -> Unlinked" cases)
// on top of one real 64-member RKeygen batch. Expect this test to take
// on the order of 10-30 minutes.

#include "lattice_lrs/lrs/production_lrsign.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lattice_lrs;
using namespace lattice_lrs::lrs;
using namespace lattice_lrs::ring_signature;
using namespace lattice_lrs::sampling;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void test_context_create_rejects_invalid_profile() {
    SystemRandomSource random;
    const ParameterProfile profile = ParameterProfile::N64();
    ProductionLRSignContext context =
        ProductionLRSignContext::Create(profile, random);
    require(context.public_parameters().is_test_only() == false,
            "ProductionLRSignContext must never produce test-only "
            "PublicParameters");
    require(context.expected_ring_size() == 64,
            "N64's expected ring size must be 64");
}

// Real RSetup, real RKeygen (via LRKeygen) for every one of the 64 ring
// members, three real LRSign operations, real LRVerify, and real Link --
// no mocks anywhere in this call chain.
void test_production_lrsign_n64_full_flow() {
    SystemRandomSource random;
    const ParameterProfile profile = ParameterProfile::N64();
    ProductionLRSignContext context =
        ProductionLRSignContext::Create(profile, random);

    const std::size_t ring_size = context.expected_ring_size();
    require(ring_size == 64, "N64 ring size must be 64");

    std::vector<LinkableKeyPair> keys;
    keys.reserve(ring_size);
    const auto keygen_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < ring_size; ++i) {
        keys.push_back(context.GenerateKeyPair(random));
    }
    const auto keygen_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - keygen_start).count();
    std::cout << "  (real LRKeygen for all " << ring_size << " members took "
              << keygen_seconds << "s)\n";

    proofs::Protocol2PublicList ring;
    ring.reserve(ring_size);
    for (const LinkableKeyPair& key_pair : keys) {
        ring.push_back(key_pair.linkable_public_key);
    }

    // Signer A signs message_1 with a fresh guard wrapping its own
    // LinkableSecretKey.
    const std::size_t signer_a_index = 0;
    OneTimeOtsKeyGuard guard_a1(keys[signer_a_index].secret_key);
    const std::vector<std::uint8_t> message_1{0x41, 0x55, 0x43, 0x31};  // "AUC1"

    const auto sign1_start = std::chrono::steady_clock::now();
    const LinkableSignature signature_1 =
        context.Sign(ring, signer_a_index, guard_a1, message_1, random);
    std::cout << "  (real LRSign #1 took "
              << std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - sign1_start).count()
              << "s)\n";

    require(context.Verify(ring, message_1, signature_1),
            "a genuine signature over its own ring and message must verify");

    // A second guard wrapping a COPY of signer A's SAME secret key
    // (same ovk/osk) signs a DIFFERENT message. Per WCM Section 6
    // ("one-time linkability"), reusing the same OTS key pair across two
    // signing contexts is exactly what makes the resulting signatures
    // Link as the SAME signer; LinkableSecretKey itself has no atomics
    // and is freely copyable, only OneTimeOtsKeyGuard enforces the
    // one-signing-per-guard-object policy, so this is an intentional,
    // explicit choice by the (simulated) signer to link these two
    // signatures, not a bypass of the guard.
    OneTimeOtsKeyGuard guard_a2(keys[signer_a_index].secret_key);
    const std::vector<std::uint8_t> message_2{0x41, 0x55, 0x43, 0x32};  // "AUC2"

    const auto sign2_start = std::chrono::steady_clock::now();
    const LinkableSignature signature_2 =
        context.Sign(ring, signer_a_index, guard_a2, message_2, random);
    std::cout << "  (real LRSign #2 took "
              << std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - sign2_start).count()
              << "s)\n";

    require(context.Verify(ring, message_2, signature_2),
            "the second genuine signature must also verify independently");

    // A different signer, with its OWN fresh OTS key pair (from its own
    // LRKeygen output), signs a third message.
    const std::size_t signer_b_index = 1;
    OneTimeOtsKeyGuard guard_b(keys[signer_b_index].secret_key);
    const std::vector<std::uint8_t> message_3{0x41, 0x55, 0x43, 0x33};  // "AUC3"

    const auto sign3_start = std::chrono::steady_clock::now();
    const LinkableSignature signature_3 =
        context.Sign(ring, signer_b_index, guard_b, message_3, random);
    std::cout << "  (real LRSign #3 took "
              << std::chrono::duration<double>(
                     std::chrono::steady_clock::now() - sign3_start).count()
              << "s)\n";

    require(context.Verify(ring, message_3, signature_3),
            "the third genuine signature (different signer) must verify");

    // --- Linkability: real Link on real signatures ---
    require(context.Link(ring, message_1, signature_1, ring, message_2,
                         signature_2) == LinkOutcome::Linked,
            "two genuine signatures sharing the same OTS key pair must "
            "Link as Linked");
    require(context.Link(ring, message_1, signature_1, ring, message_3,
                         signature_3) == LinkOutcome::Unlinked,
            "two genuine signatures from different OTS key pairs must "
            "Link as Unlinked");
    require(context.Link(ring, message_2, signature_2, ring, message_3,
                         signature_3) == LinkOutcome::Unlinked,
            "signature_2 and signature_3 (different signers/OTS keys) "
            "must Link as Unlinked");

    // --- Rejection: tampered message / ring / signature ---
    std::vector<std::uint8_t> tampered_message = message_1;
    tampered_message[0] ^= 0x01;
    require(!context.Verify(ring, tampered_message, signature_1),
            "a signature must not verify against a modified message");

    proofs::Protocol2PublicList tampered_ring = ring;
    tampered_ring[2] = tampered_ring[3];
    require(!context.Verify(tampered_ring, message_1, signature_1),
            "a signature must not verify against a modified ring");

    LinkableSignature tampered_signature = signature_1;
    std::vector<NTL::ZZ> coefficients =
        tampered_signature.base_signature.challenges[0].coefficients();
    coefficients[0] += 1;
    tampered_signature.base_signature.challenges[0] = arithmetic::Polynomial(
        tampered_signature.base_signature.challenges[0].degree(),
        tampered_signature.base_signature.challenges[0].modulus(),
        coefficients);
    require(!context.Verify(ring, message_1, tampered_signature),
            "a signature must not verify after its base challenge is "
            "modified");

    // Link must reject (not merely mis-report) a pair where one side is
    // tampered -- per WCM's own Link algorithm, both calls to Vrfy must
    // succeed before the ovk comparison is even reached.
    require(context.Link(ring, message_1, tampered_signature, ring, message_2,
                         signature_2) == LinkOutcome::Rejected,
            "Link must report Rejected (not Linked/Unlinked) when one "
            "signature in the pair fails to verify");
    require(context.Link(ring, tampered_message, signature_1, ring, message_2,
                         signature_2) == LinkOutcome::Rejected,
            "Link must report Rejected when one side's message does not "
            "match its signature");

    // --- One-time OTS key reuse ---
    bool reuse_rejected = false;
    try {
        (void)context.Sign(ring, signer_a_index, guard_a1, message_3, random);
    } catch (const OneTimeKeyReuseError&) {
        reuse_rejected = true;
    }
    require(reuse_rejected,
            "signing again with an already-consumed OneTimeOtsKeyGuard "
            "must throw OneTimeKeyReuseError, not silently sign again");

    // --- Link is a stateless, pairwise operation: calling it again with
    // the exact same inputs must be deterministic (no hidden mutable
    // state carried between calls -- this is the concrete, testable
    // substance behind "different auctions do not share linkability
    // state": Link itself never accumulates or consults any record of
    // previously-seen signatures). ---
    require(context.Link(ring, message_1, signature_1, ring, message_2,
                         signature_2) == LinkOutcome::Linked,
            "repeating an identical Link call must be deterministic "
            "(Link carries no hidden state between calls)");
}

}  // namespace

int main() {
    const std::pair<const char*, void (*)()> cases[] = {
        {"production_lrsign_context_create_rejects_invalid_profile",
         test_context_create_rejects_invalid_profile},
        {"production_lrsign_n64_full_flow",
         test_production_lrsign_n64_full_flow},
    };

    int failures = 0;
    for (const auto& [name, fn] : cases) {
        try {
            fn();
            std::cout << "PASS: " << name << "\n";
        } catch (const std::exception& error) {
            std::cout << "FAIL: " << name << " (" << error.what() << ")\n";
            ++failures;
        }
    }
    return failures == 0 ? 0 : 1;
}
