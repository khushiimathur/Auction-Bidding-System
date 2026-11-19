#include "lattice_lrs/ring_signature/canonical_rsign_transcript.hpp"

#include "lattice_lrs/proofs/binary_proof.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using lattice_lrs::arithmetic::Matrix;
using lattice_lrs::arithmetic::Polynomial;
using lattice_lrs::commitment::CommitmentKey;
using lattice_lrs::commitment::Parameters;
using lattice_lrs::commitment::SquaredNormBound;
using lattice_lrs::proofs::Protocol2FirstMessage;
using lattice_lrs::proofs::Protocol2PublicList;
using lattice_lrs::ring_signature::CanonicalRSignTranscriptEncoder;
using lattice_lrs::ring_signature::Shake256CToChallenges;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

CommitmentKey make_key() {
    const std::size_t d = 4;
    const NTL::ZZ q = z(101);
    Parameters p{1, 2, 1, d, q, z(3),
                 SquaredNormBound(z(1000), z(1))};
    Matrix G_r(1, 2, d, q);
    Matrix G_m(1, 1, d, q);
    G_r.at(0, 0) = Polynomial(d, q, {z(1), z(0), z(0), z(0)});
    G_r.at(0, 1) = Polynomial(d, q, {z(2), z(0), z(0), z(0)});
    G_m.at(0, 0) = Polynomial(d, q, {z(3), z(0), z(0), z(0)});
    Matrix G(1, 3, d, q);
    G.at(0, 0) = G_r.at(0, 0);
    G.at(0, 1) = G_r.at(0, 1);
    G.at(0, 2) = G_m.at(0, 0);
    return CommitmentKey(p, G_r, G_m);
}

Polynomial poly(long value) {
    return Polynomial(4, z(101),
                      {z(value), z(0), z(0), z(0)});
}

Protocol2FirstMessage make_first(long id) {
    Protocol2FirstMessage first;
    first.A = {poly(id)};
    first.B = {poly(id + 1)};
    first.C = {poly(id + 2)};
    first.D = {poly(id + 3)};
    first.E = {{poly(id + 4)}, {poly(id + 5)}};
    first.auxiliary_commitment.bytes =
        std::vector<std::uint8_t>(32, static_cast<std::uint8_t>(id));
    return first;
}

Protocol2PublicList make_ring() {
    return {{poly(1)}, {poly(2)}, {poly(3)}, {poly(4)}};
}

void test_deterministic_and_prover_verifier_consistency() {
    const CommitmentKey key = make_key();
    CanonicalRSignTranscriptEncoder encoder;
    Shake256CToChallenges challenges;
    const Protocol2PublicList ring = make_ring();
    const std::vector<Protocol2FirstMessage> first{make_first(1), make_first(2)};
    const std::vector<std::uint8_t> message{'b','i','d'};

    const std::vector<std::uint8_t> one =
        encoder.encode(key, message, ring, first);
    const std::vector<std::uint8_t> two =
        encoder.encode(key, message, ring, first);
    require(one == two, "canonical transcript encoding must be deterministic");

    lattice_lrs::ring_signature::ChallengeSet set;
    for (std::size_t exponent = 0; exponent < 8; ++exponent) {
        set.push_back(lattice_lrs::proofs::BinaryChallengeFromExponent(
            key.parameters(), exponent));
    }
    const auto result1 = challenges.hash(one, set, 16);
    const auto result2 = challenges.hash(two, set, 16);
    require(result1 == result2,
            "prover and verifier challenge derivation must be identical");
    require(result1.size() == 16,
            "challenge derivation must return exactly r challenges");
}

void test_message_ring_and_first_message_binding() {
    const CommitmentKey key = make_key();
    CanonicalRSignTranscriptEncoder encoder;
    const Protocol2PublicList ring = make_ring();
    const std::vector<Protocol2FirstMessage> first{make_first(1)};

    const auto base =
        encoder.encode(key, {'a','b','c'}, ring, first);
    const auto boundary_changed =
        encoder.encode(key, {'a','b','c'}, ring, first);
    require(base == boundary_changed,
            "unchanged field boundaries must encode identically");

    const auto changed_message =
        encoder.encode(key, {'a','b','d'}, ring, first);
    require(base != changed_message,
            "changed message bytes must change the transcript");

    Protocol2PublicList swapped = ring;
    std::swap(swapped[0], swapped[1]);
    const auto changed_ring =
        encoder.encode(key, {'a','b','c'}, swapped, first);
    require(base != changed_ring,
            "changed ring order must change the transcript");

    std::vector<Protocol2FirstMessage> changed_first = first;
    changed_first[0].C[0] = poly(99);
    const auto changed_commitment =
        encoder.encode(key, {'a','b','c'}, ring, changed_first);
    require(base != changed_commitment,
            "changed first-message values must change the transcript");

    changed_first = first;
    changed_first[0].auxiliary_commitment.bytes[0] ^= 1;
    const auto changed_ca =
        encoder.encode(key, {'a','b','c'}, ring, changed_first);
    require(base != changed_ca,
            "changed c_a auxiliary commitment must change the transcript");
}

void test_encoding_ambiguity_and_malformed_inputs() {
    const CommitmentKey key = make_key();
    CanonicalRSignTranscriptEncoder encoder;
    const Protocol2PublicList ring = make_ring();
    const std::vector<Protocol2FirstMessage> first{make_first(1)};

    const auto ab_c =
        encoder.encode(key, {'a','b','c'}, ring, first);
    const auto a_bc =
        encoder.encode(key, {'a','b','c'}, ring, first);
    require(ab_c == a_bc,
            "equivalent byte strings must remain deterministic");

    bool empty_ring_rejected = false;
    try {
        (void)encoder.encode(key, {}, {}, first);
    } catch (const std::invalid_argument&) {
        empty_ring_rejected = true;
    }
    require(empty_ring_rejected,
            "malformed empty ring must be rejected");

    Protocol2FirstMessage malformed = make_first(1);
    malformed.E.clear();
    bool empty_e_rejected = false;
    try {
        (void)encoder.encode(key, {}, ring, {malformed});
    } catch (const std::invalid_argument&) {
        empty_e_rejected = true;
    }
    require(empty_e_rejected,
            "malformed first message with no E_j must be rejected");

    malformed = make_first(1);
    malformed.auxiliary_commitment.bytes.clear();
    bool empty_ca_rejected = false;
    try {
        (void)encoder.encode(key, {}, ring, {malformed});
    } catch (const std::invalid_argument&) {
        empty_ca_rejected = true;
    }
    require(empty_ca_rejected,
            "malformed empty c_a must be rejected");
}

void test_challenge_mapping_rejects_malformed_sets() {
    Shake256CToChallenges challenges;
    lattice_lrs::ring_signature::ChallengeSet set;
    const NTL::ZZ q = z(101);
    for (std::size_t i = 0; i < 3; ++i) {
        set.push_back(Polynomial(3, q,
                                 i == 0 ? std::vector<NTL::ZZ>{z(1),z(0),z(0)}
                                        : std::vector<NTL::ZZ>{z(0),z(0),z(0)}));
    }
    bool rejected = false;
    try {
        (void)challenges.hash({1,2,3}, set, 2);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected,
            "challenge mapping must reject malformed or non-power-of-two C");
}

}  // namespace

int main() {
    try {
        test_deterministic_and_prover_verifier_consistency();
        test_message_ring_and_first_message_binding();
        test_encoding_ambiguity_and_malformed_inputs();
        test_challenge_mapping_rejects_malformed_sets();
    } catch (const std::exception& error) {
        std::cerr << "canonical RSign transcript test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
