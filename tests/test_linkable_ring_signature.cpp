// Phase C tests: LRKeygen, LRSign, LRVerify (lattice_lrs::lrs), composing
// over the existing Esgin RS (RKeygen*/RSign*/RVerify*), the Phase A OTS
// wrapper, and the Phase B H'/MaskPublicKey/UnmaskPublicKey. See
// linkable_ring_signature.hpp for the exact WCM equations implemented and
// the flagged implementation choices/limitations (including the lack of a
// production-grade Protocol2RSignGaussianProvider/RSignBatchRejectionProvider
// anywhere in this repository -- this file uses the same kind of explicit,
// non-cryptographic test doubles already used by tests/test_rsign_batch.cpp
// for exactly that reason).
//
// These tests establish functional composition and rejection behaviour
// only. They do not establish anonymity, unforgeability, or linkability in
// the sense of the WCM paper's security definitions.

#include "lattice_lrs/lrs/linkable_ring_signature.hpp"

#include "lattice_lrs/proofs/binary_proof.hpp"

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lattice_lrs::arithmetic;
using namespace lattice_lrs::commitment;
using namespace lattice_lrs::ots;
using namespace lattice_lrs::proofs;
using namespace lattice_lrs::ring_signature;
using namespace lattice_lrs::sampling;
using namespace lattice_lrs::lrs;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

NTL::ZZ z(long value) { return NTL::to_ZZ(value); }

// --- Test doubles, deliberately the same shape as tests/test_rsign_batch.cpp
// (see Phase C report: no production Protocol2RSignGaussianProvider or
// RSignBatchRejectionProvider exists in this repository). Kept local to
// this file, matching this codebase's existing convention of not sharing a
// test-utilities header across test binaries. ---

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

// --- Fixture: same scale (n=1,m=1,v=4,degree=86,k=2,beta=2,repetitions=2)
// and the same Section-6 rejection/Gaussian script as the already-verified
// tests/test_rsign_batch.cpp scenario, so this test exercises LRSign/
// LRVerify's composition over a combination already known to produce an
// accepting RSign/RVerify pair. ---

struct Fixture {
    PublicParameters public_parameters;
    Protocol2Parameters proof_parameters;
    Protocol2PublicList ring;               // T: the published/masked pk_i's
    std::vector<lattice_lrs::ots::DilithiumPublicKey> ovks;  // ring members' ovk_i
    std::size_t signer_index;
    LinkableSecretKey signer_secret_key;
};

Fixture make_fixture(ZeroByteSource& random) {
    const std::size_t degree = 86;
    TestOnlySetupParameters setup{
        Parameters{1, 1, 4, degree, z(1000000007), z(1),
                  SquaredNormBound(z(1) << 256, z(1))},
        2};
    auto hash = std::make_shared<InputDependentHash>();
    PublicParameters public_parameters = RSetupForTesting(setup, hash, random);
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

    // Base (Esgin-level, unmasked) ring p\hat{k}_i, matching the proven
    // test_rsign_batch fixture: index 1 is the only one with known opening
    // randomness, and is the signer.
    const std::vector<PolynomialVector> base_ring{
        zero_commitment, witness_commitment, zero_commitment, zero_commitment};
    const std::size_t signer_index = 1;

    std::vector<lattice_lrs::ots::DilithiumPublicKey> ovks;
    Protocol2PublicList ring;
    LinkableSecretKey signer_secret_key{};
    for (std::size_t i = 0; i < base_ring.size(); ++i) {
        lattice_lrs::ots::DilithiumKeyPair ots_keys = lattice_lrs::ots::GenerateKeyPair();
        ring.push_back(MaskPublicKey(parameters, base_ring[i], ots_keys.public_key));
        ovks.push_back(ots_keys.public_key);
        if (i == signer_index) {
            signer_secret_key = LinkableSecretKey{
                SecretKey{witness_randomness}, ots_keys.secret_key,
                ots_keys.public_key};
        }
    }

    Protocol2Parameters proof{2, 2, PositiveRational(z(1), z(1)),
                             PositiveRational(z(1000000000), z(1))};

    return Fixture{std::move(public_parameters), std::move(proof),
                  std::move(ring), std::move(ovks), signer_index,
                  std::move(signer_secret_key)};
}

LinkableSignature sign_with_fresh_doubles(
    const Fixture& fixture, OneTimeOtsKeyGuard& guard,
    const std::vector<std::uint8_t>& message, ZeroByteSource& random) {
    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({false, true, true}, {false, true});
    TestEncoder encoder;
    return LRSignForTesting(fixture.public_parameters, fixture.proof_parameters,
                            fixture.ring, fixture.signer_index, guard, message,
                            encoder, gaussian, auxiliary, rejection, random);
}

bool verify_with_fresh_double(const Fixture& fixture,
                             const std::vector<std::uint8_t>& message,
                             const LinkableSignature& signature) {
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    TestEncoder encoder;
    return LRVerifyForTesting(fixture.public_parameters,
                             fixture.proof_parameters, fixture.ring, message,
                             signature, encoder, auxiliary);
}

void test_valid_signature_verifies() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);

    require(verify_with_fresh_double(fixture, message, signature),
            "a freshly produced linkable signature must verify");
}

void test_modified_message_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);

    require(!verify_with_fresh_double(fixture, {0x41, 0x43}, signature),
            "verification must fail once the signed message is modified");
}

void test_modified_ots_signature_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);
    signature.ots_signature.bytes[0] ^= 0x01U;

    require(!verify_with_fresh_double(fixture, message, signature),
            "verification must fail once \\tilde{sigma} is tampered");
}

void test_modified_ots_public_key_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);
    signature.ots_public_key.bytes[0] ^= 0x01U;

    require(!verify_with_fresh_double(fixture, message, signature),
            "verification must fail once ovk in the signature is tampered "
            "(it changes both the Dilithium verification key and the "
            "recomputed T\\hat{}')");
}

void test_modified_ring_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);

    Protocol2PublicList tampered_ring = fixture.ring;
    tampered_ring[0][0] = tampered_ring[0][0] +
                         Polynomial(tampered_ring[0][0].degree(),
                                    tampered_ring[0][0].modulus(), {z(1)});

    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    TestEncoder encoder;
    require(!LRVerifyForTesting(fixture.public_parameters,
                               fixture.proof_parameters, tampered_ring,
                               message, signature, encoder, auxiliary),
            "verification must fail once a non-signer ring entry is modified "
            "(it changes both T fed to OTS.Vrfy and the recomputed T\\hat{}')");
}

void test_invalid_base_signature_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);
    // Corrupt \hat{sigma} itself (not the OTS layer): flip a coefficient in
    // the first response's z vector.
    signature.base_signature.responses[0].z[0] =
        signature.base_signature.responses[0].z[0] +
        Polynomial(signature.base_signature.responses[0].z[0].degree(),
                  signature.base_signature.responses[0].z[0].modulus(), {z(1)});

    require(!verify_with_fresh_double(fixture, message, signature),
            "verification must fail once the underlying Esgin signature "
            "\\hat{sigma} is invalid, even if the OTS layer is untouched "
            "(note: this also changes the OTS payload, since \\hat{sigma} "
            "is part of what OTS signs, so both checks would reject)");
}

void test_ots_key_reuse_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message_one{0x41, 0x42};
    const std::vector<std::uint8_t> message_two{0x51, 0x52};

    LinkableSignature first_signature =
        sign_with_fresh_doubles(fixture, guard, message_one, random);
    require(verify_with_fresh_double(fixture, message_one, first_signature),
            "the first use of the OTS key must still succeed and verify");

    bool reuse_rejected = false;
    try {
        (void)sign_with_fresh_doubles(fixture, guard, message_two, random);
    } catch (const OneTimeKeyReuseError&) {
        reuse_rejected = true;
    }
    require(reuse_rejected,
            "a second LRSign call against the same OneTimeOtsKeyGuard must "
            "throw OneTimeKeyReuseError and must not produce a second "
            "signature");
}

void test_empty_ring_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({true}, {true});
    TestEncoder encoder;

    bool threw = false;
    try {
        (void)LRSignForTesting(fixture.public_parameters,
                              fixture.proof_parameters, Protocol2PublicList{},
                              0, guard, message, encoder, gaussian, auxiliary,
                              rejection, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "LRSign must reject an empty ring T");
    require(!guard.is_consumed(),
            "a rejected LRSign call (before the key is consumed) must not "
            "mark the one-time guard as used");
}

void test_out_of_range_signer_index_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    RunIndexedGaussian gaussian;
    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    ScriptedRejection rejection({true}, {true});
    TestEncoder encoder;

    bool threw = false;
    try {
        (void)LRSignForTesting(fixture.public_parameters,
                              fixture.proof_parameters, fixture.ring,
                              fixture.ring.size(), guard, message, encoder,
                              gaussian, auxiliary, rejection, random);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "LRSign must reject a signer_index outside the ring");
}

void test_malformed_signature_structure_rejected() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);
    // Drop one repetition's worth of transcript data -- a structurally
    // malformed \hat{sigma} (wrong repetition count).
    signature.base_signature.first_messages.pop_back();

    require(!verify_with_fresh_double(fixture, message, signature),
            "verification must reject a structurally malformed base "
            "signature instead of throwing");
}

void test_empty_ring_rejected_by_verify() {
    ZeroByteSource random;
    Fixture fixture = make_fixture(random);
    OneTimeOtsKeyGuard guard(fixture.signer_secret_key);
    const std::vector<std::uint8_t> message{0x41, 0x42};

    LinkableSignature signature =
        sign_with_fresh_doubles(fixture, guard, message, random);

    InsecureIdAuxiliaryCommitmentForTesting auxiliary;
    TestEncoder encoder;
    require(!LRVerifyForTesting(fixture.public_parameters,
                               fixture.proof_parameters, Protocol2PublicList{},
                               message, signature, encoder, auxiliary),
            "LRVerify must reject an empty ring T rather than throwing");
}

}  // namespace

int main() {
    const std::pair<const char*, void (*)()> cases[] = {
        {"valid_signature_verifies", test_valid_signature_verifies},
        {"modified_message_rejected", test_modified_message_rejected},
        {"modified_ots_signature_rejected", test_modified_ots_signature_rejected},
        {"modified_ots_public_key_rejected",
         test_modified_ots_public_key_rejected},
        {"modified_ring_rejected", test_modified_ring_rejected},
        {"invalid_base_signature_rejected", test_invalid_base_signature_rejected},
        {"ots_key_reuse_rejected", test_ots_key_reuse_rejected},
        {"empty_ring_rejected", test_empty_ring_rejected},
        {"out_of_range_signer_index_rejected",
         test_out_of_range_signer_index_rejected},
        {"malformed_signature_structure_rejected",
         test_malformed_signature_structure_rejected},
        {"empty_ring_rejected_by_verify", test_empty_ring_rejected_by_verify},
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
