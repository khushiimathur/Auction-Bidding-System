// Phase D tests: Link (lattice_lrs::lrs), composing over Phase C's
// LRVerify. See link.hpp for the exact WCM Section 3.1 Link algorithm, the
// one-time-linkability limitation quoted from the paper's own Section 6
// Discussion, and the carried-over Dilithium5/experimental-provider
// caveats.
//
// IMPORTANT (reuse-fixture note): to build a pair of signatures that
// legitimately carry the SAME ovk (needed to test the "Linked" outcome),
// this file constructs two INDEPENDENT OneTimeOtsKeyGuard objects, each
// wrapping its own copy of the identical underlying (ovk, osk) key
// material, and signs once through each guard. This does not bypass or
// weaken OneTimeOtsKeyGuard: each individual guard object still enforces
// "used at most once" within its own lifetime (see
// test_ots_key_reuse_rejected in test_linkable_ring_signature.cpp for that
// enforcement itself). What this constructs is the exact misuse scenario
// Link exists to detect -- the same OTS key pair used to sign twice,
// whether because an application failed to generate a fresh key pair per
// context or because of malicious signer behaviour. This is NOT a
// statement that reusing an OTS key pair is a valid production workflow;
// it is the fixture for testing the detector.
//
// A single lattice_lrs::ring_signature::PublicParameters (and the same
// Protocol2Parameters) is built ONCE per test and shared by both rings:
// WCM's Link only makes sense comparing two signatures produced under the
// same scheme deployment, and PublicParameters carries scheme-wide state
// (here, the test HashToChallenges double's own internal map) that must
// not be duplicated across two independently-constructed instances.
//
// These tests establish functional composition and rejection behaviour
// only. They do not establish the paper's Linkability or Nonslanderability
// security properties.

#include "lattice_lrs/lrs/link.hpp"

#include "lattice_lrs/proofs/binary_proof.hpp"

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lattice_lrs::arithmetic;
using namespace lattice_lrs::commitment;
using namespace lattice_lrs::proofs;
using namespace lattice_lrs::ring_signature;
using namespace lattice_lrs::sampling;
using namespace lattice_lrs::lrs;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

// --- Test doubles, deliberately the same shape (and, where it matters,
// the exact same crafted values) as tests/test_rsign_batch.cpp and
// tests/test_linkable_ring_signature.cpp. See those files' comments: no
// production Protocol2RSignGaussianProvider or RSignBatchRejectionProvider
// exists anywhere in this repository. Kept local to this file, matching
// this codebase's convention of not sharing a test-utilities header. ---

class ZeroByteSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override {
        std::fill(output, output + length, std::uint8_t(0));
    }
};

class InputDependentHash final : public HashToChallenges {
public:
    ChallengeVector hash(const std::vector<std::uint8_t>& input,
                        const ChallengeSet& challenge_set,
                        std::size_t output_count) const override {
        if (output_count > challenge_set.size()) {
            throw std::invalid_argument("invalid test transcript");
        }
        const auto [entry, inserted] = indices.emplace(input, indices.size());
        (void)inserted;
        const std::size_t max_start = challenge_set.size() - output_count;
        const std::size_t start = (5 + entry->second) % (max_start + 1);
        ChallengeVector result;
        result.reserve(output_count);
        for (std::size_t i = 0; i < output_count; ++i) {
            result.push_back(challenge_set[start + i]);
        }
        return result;
    }

private:
    mutable std::map<std::vector<std::uint8_t>, std::size_t> indices;
};

class InsecureIdAuxiliaryCommitmentForTesting final
    : public Protocol2AuxiliaryCommitmentProvider {
public:
    AuxiliaryCommitmentOpening commit(
        const PolynomialVector&, const PolynomialVector&,
        const PolynomialVector&, const PolynomialVector&,
        const std::vector<PolynomialVector>&, RandomSource&) override {
        ++next_id;
        const auto id = static_cast<std::uint8_t>(next_id);
        return {AuxiliaryCommitmentValue{{id}}, {id}};
    }

    bool verify(const PolynomialVector&, const PolynomialVector&,
               const PolynomialVector&, const PolynomialVector&,
               const std::vector<PolynomialVector>&,
               const AuxiliaryCommitmentValue& commitment,
               const std::vector<std::uint8_t>& opening) const override {
        return commitment.bytes.size() == 1 && opening.size() == 1 &&
               commitment.bytes.front() == opening.front();
    }

    std::uint8_t next_id = 0;
};

class RunIndexedGaussian final : public Protocol2RSignGaussianProvider {
public:
    bool supports_section6_distributions() const noexcept override {
        return true;
    }

    NTL::ZZ sample_coefficient(Protocol2GaussianSampleKind kind,
                               std::size_t run_index, std::size_t repetitions,
                               const CommitmentKey& key,
                               const Protocol2Parameters& proof,
                               RandomSource&) override {
        require(repetitions == 2, "Gaussian provider received wrong batch size");
        if (kind == Protocol2GaussianSampleKind::binary_mask) {
            return z(static_cast<long>(run_index));
        }
        const std::size_t md = key.parameters().m * key.parameters().degree;
        if (kind == Protocol2GaussianSampleKind::response_mask) {
            const std::size_t local =
                response_mask_calls_[run_index]++ % (2 * md);
            return key.parameters().q + z(static_cast<long>(100 * run_index)) +
                   z(local < md ? 1000 : 2000);
        }
        const std::size_t local = rho_calls_[run_index]++ % (proof.k * md);
        const std::size_t rho_index = local / md;
        return key.parameters().q + z(static_cast<long>(100 * run_index)) +
               z(static_cast<long>(3000 + 500 * rho_index));
    }

private:
    std::vector<std::size_t> response_mask_calls_ = std::vector<std::size_t>(2, 0);
    std::vector<std::size_t> rho_calls_ = std::vector<std::size_t>(2, 0);
};

class ScriptedRejection final : public RSignBatchRejectionProvider {
public:
    explicit ScriptedRejection(std::vector<bool> f_decisions,
                               std::vector<bool> response_decisions)
        : f_decisions_(std::move(f_decisions)),
          response_decisions_(std::move(response_decisions)) {}

    bool supports_section6_rejection() const noexcept override { return true; }

    bool accept(const std::vector<NTL::ZZ>&, const std::vector<NTL::ZZ>&,
               const RSignBatchRejectionParameters& parameters,
               RandomSource&) override {
        if (parameters.stage == RSignRejectionStage::f_vector) {
            require(f_index_ < f_decisions_.size(),
                    "unexpected f rejection invocation");
            return f_decisions_[f_index_++];
        }
        require(response_index_ < response_decisions_.size(),
                "unexpected response rejection invocation");
        return response_decisions_[response_index_++];
    }

private:
    std::vector<bool> f_decisions_;
    std::vector<bool> response_decisions_;
    std::size_t f_index_ = 0;
    std::size_t response_index_ = 0;
};

class TestEncoder final : public RSignTranscriptEncoder {
public:
    std::vector<std::uint8_t> encode(
        const CommitmentKey&, const std::vector<std::uint8_t>& message,
        const Protocol2PublicList& ring,
        const std::vector<Protocol2FirstMessage>& first_messages)
        const override {
        std::vector<std::uint8_t> bytes = message;
        for (const PolynomialVector& entry : ring) {
            bytes.push_back(static_cast<std::uint8_t>(entry.size()));
        }
        for (const auto& first : first_messages) {
            bytes.push_back(first.auxiliary_commitment.bytes.at(0));
        }
        return bytes;
    }
};

// --- Shared setup: ONE PublicParameters/Protocol2Parameters per test,
// reused for both rings a Link call compares (see file header for why).
// Scale and Section-6 rejection/Gaussian script match what is already
// proven in tests/test_rsign_batch.cpp and
// tests/test_linkable_ring_signature.cpp. ---

PublicParameters make_shared_public_parameters(ZeroByteSource& random) {
    const std::size_t degree = 86;
    TestOnlySetupParameters setup{
        Parameters{1, 1, 4, degree, z(1000000007), z(1),
                  SquaredNormBound(z(1) << 256, z(1))},
        2};
    auto hash = std::make_shared<InputDependentHash>();
    return RSetupForTesting(setup, hash, random);
}

Protocol2Parameters make_shared_proof_parameters() {
    return Protocol2Parameters{2, 2, PositiveRational(z(1), z(1)),
                               PositiveRational(z(1000000000), z(1))};
}

// A ring plus the secret material needed to sign as its designated member.
// `forced_signer_ots`, when provided, makes the signer's ovk/osk the given
// key pair instead of a freshly generated one -- this is how two rings
// built from the SAME public_parameters are made to share one ovk.
struct RingFixture {
    Protocol2PublicList ring;
    std::size_t signer_index;
    LinkableSecretKey signer_secret_key;
};

RingFixture make_ring_fixture(
    const PublicParameters& public_parameters,
    std::optional<lattice_lrs::ots::DilithiumKeyPair> forced_signer_ots =
        std::nullopt) {
    const CommitmentKey& key = public_parameters.commitment_key();
    const auto& p = key.parameters();
    const Parameters& parameters = p;

    const Polynomial zero(p.degree, p.q);
    const PolynomialVector zero_message(p.v, zero);
    const PolynomialVector zero_randomness(p.m, zero);
    const PolynomialVector zero_commitment =
        lattice_lrs::commitment::Com(key, zero_message, zero_randomness);

    PolynomialVector witness_randomness = zero_randomness;
    witness_randomness[0] = Polynomial(p.degree, p.q, {z(1)});
    const PolynomialVector witness_commitment =
        lattice_lrs::commitment::Com(key, zero_message, witness_randomness);

    const std::vector<PolynomialVector> base_ring{
        zero_commitment, witness_commitment, zero_commitment, zero_commitment};
    const std::size_t signer_index = 1;

    Protocol2PublicList ring;
    LinkableSecretKey signer_secret_key{};
    for (std::size_t i = 0; i < base_ring.size(); ++i) {
        lattice_lrs::ots::DilithiumKeyPair ots_keys =
            (i == signer_index && forced_signer_ots.has_value())
                ? *forced_signer_ots
                : lattice_lrs::ots::GenerateKeyPair();
        ring.push_back(MaskPublicKey(parameters, base_ring[i], ots_keys.public_key));
        if (i == signer_index) {
            signer_secret_key = LinkableSecretKey{
                SecretKey{witness_randomness}, ots_keys.secret_key,
                ots_keys.public_key};
        }
    }

    return RingFixture{std::move(ring), signer_index, std::move(signer_secret_key)};
}

LinkableSignature sign_with_fresh_doubles(
    const PublicParameters& public_parameters,
    const Protocol2Parameters& proof_parameters, const RingFixture& fixture,
    OneTimeOtsKeyGuard& guard, const std::vector<std::uint8_t>& message,
    ZeroByteSource& random) {
    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({false, true, true}, {false, true});
    TestEncoder encoder;
    return LRSignForTesting(public_parameters, proof_parameters, fixture.ring,
                            fixture.signer_index, guard, message, encoder,
                            gaussian, auxiliary, rejection, random);
}

LinkOutcome link_with_fresh_double(
    const PublicParameters& public_parameters,
    const Protocol2Parameters& proof_parameters,
    const Protocol2PublicList& ring1, const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1, const Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2) {
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    TestEncoder encoder;
    return LinkForTesting(public_parameters, proof_parameters, ring1, message1,
                          signature1, ring2, message2, signature2, encoder,
                          auxiliary);
}

void test_linked_when_ovk_matches() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();

    RingFixture ring1 = make_ring_fixture(public_parameters);
    const lattice_lrs::ots::DilithiumKeyPair shared_ots{
        ring1.signer_secret_key.ots_public_key,
        ring1.signer_secret_key.ots_secret_key};
    RingFixture ring2 = make_ring_fixture(public_parameters, shared_ots);

    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);

    require(signature1.ots_public_key.bytes == signature2.ots_public_key.bytes,
            "test setup error: the two rings must share one ovk");

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, message1, signature1, ring2.ring,
                                  message2, signature2) == LinkOutcome::Linked,
            "two independently valid signatures carrying the same ovk must "
            "be Linked");
}

void test_unlinked_when_ovk_differs() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();

    RingFixture ring1 = make_ring_fixture(public_parameters);
    RingFixture ring2 = make_ring_fixture(public_parameters);  // fresh ovk

    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x01, 0x02};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);

    require(!(signature1.ots_public_key.bytes == signature2.ots_public_key.bytes),
            "test setup error: the two rings must have independent ovks");

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, message1, signature1, ring2.ring,
                                  message2, signature2) ==
                LinkOutcome::Unlinked,
            "two independently valid signatures carrying different ovks "
            "must be Unlinked");
}

void test_rejected_when_first_signature_invalid() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();
    RingFixture ring1 = make_ring_fixture(public_parameters);
    RingFixture ring2 = make_ring_fixture(public_parameters);
    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);
    signature1.ots_signature.bytes[0] ^= 0x01U;

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, message1, signature1, ring2.ring,
                                  message2, signature2) ==
                LinkOutcome::Rejected,
            "Link must return Rejected when the first signature does not "
            "verify");
}

void test_rejected_when_second_signature_invalid() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();
    RingFixture ring1 = make_ring_fixture(public_parameters);
    RingFixture ring2 = make_ring_fixture(public_parameters);
    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);
    signature2.ots_signature.bytes[0] ^= 0x01U;

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, message1, signature1, ring2.ring,
                                  message2, signature2) ==
                LinkOutcome::Rejected,
            "Link must return Rejected when the second signature does not "
            "verify");
}

void test_rejected_when_message_modified() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();
    RingFixture ring1 = make_ring_fixture(public_parameters);
    RingFixture ring2 = make_ring_fixture(public_parameters);
    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, {0x01, 0x99}, signature1,
                                  ring2.ring, message2, signature2) ==
                LinkOutcome::Rejected,
            "Link must reject through verification once a signed message "
            "is modified before being passed to Link");
}

void test_rejected_when_ring_modified() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();
    RingFixture ring1 = make_ring_fixture(public_parameters);
    RingFixture ring2 = make_ring_fixture(public_parameters);
    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);

    Protocol2PublicList tampered_ring1 = ring1.ring;
    tampered_ring1[0][0] =
        tampered_ring1[0][0] +
        Polynomial(tampered_ring1[0][0].degree(),
                  tampered_ring1[0][0].modulus(), {z(1)});

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  tampered_ring1, message1, signature1,
                                  ring2.ring, message2, signature2) ==
                LinkOutcome::Rejected,
            "Link must reject through verification once a ring passed to "
            "Link is modified");
}

void test_rejected_when_signature_structure_malformed() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();
    RingFixture ring1 = make_ring_fixture(public_parameters);
    RingFixture ring2 = make_ring_fixture(public_parameters);
    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);
    // Structurally malformed: drop a repetition's worth of transcript data.
    signature1.base_signature.first_messages.pop_back();

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, message1, signature1, ring2.ring,
                                  message2, signature2) ==
                LinkOutcome::Rejected,
            "Link must reject a structurally malformed signature safely "
            "(no exception, just Rejected)");
}

void test_two_invalid_signatures_with_equal_ovk_are_not_linked() {
    ZeroByteSource random;
    PublicParameters public_parameters = make_shared_public_parameters(random);
    Protocol2Parameters proof_parameters = make_shared_proof_parameters();

    RingFixture ring1 = make_ring_fixture(public_parameters);
    const lattice_lrs::ots::DilithiumKeyPair shared_ots{
        ring1.signer_secret_key.ots_public_key,
        ring1.signer_secret_key.ots_secret_key};
    RingFixture ring2 = make_ring_fixture(public_parameters, shared_ots);

    OneTimeOtsKeyGuard guard1(ring1.signer_secret_key);
    OneTimeOtsKeyGuard guard2(ring2.signer_secret_key);
    const std::vector<std::uint8_t> message1{0x01, 0x02};
    const std::vector<std::uint8_t> message2{0x03, 0x04};

    LinkableSignature signature1 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring1, guard1, message1, random);
    LinkableSignature signature2 = sign_with_fresh_doubles(
        public_parameters, proof_parameters, ring2, guard2, message2, random);
    require(signature1.ots_public_key.bytes == signature2.ots_public_key.bytes,
            "test setup error: the two rings must share one ovk");

    // Tamper BOTH signatures so neither verifies, even though their ovk
    // values are identical.
    signature1.ots_signature.bytes[0] ^= 0x01U;
    signature2.ots_signature.bytes[0] ^= 0x01U;

    require(link_with_fresh_double(public_parameters, proof_parameters,
                                  ring1.ring, message1, signature1, ring2.ring,
                                  message2, signature2) ==
                LinkOutcome::Rejected,
            "Link must never report Linked for a pair of signatures that "
            "share an ovk but do not both verify -- equal ovk alone is not "
            "sufficient, both signatures must verify first");
}

}  // namespace

int main() {
    const std::pair<const char*, void (*)()> cases[] = {
        {"linked_when_ovk_matches", test_linked_when_ovk_matches},
        {"unlinked_when_ovk_differs", test_unlinked_when_ovk_differs},
        {"rejected_when_first_signature_invalid",
         test_rejected_when_first_signature_invalid},
        {"rejected_when_second_signature_invalid",
         test_rejected_when_second_signature_invalid},
        {"rejected_when_message_modified", test_rejected_when_message_modified},
        {"rejected_when_ring_modified", test_rejected_when_ring_modified},
        {"rejected_when_signature_structure_malformed",
         test_rejected_when_signature_structure_malformed},
        {"two_invalid_signatures_with_equal_ovk_are_not_linked",
         test_two_invalid_signatures_with_equal_ovk_are_not_linked},
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
