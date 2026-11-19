#include "lattice_lrs/ots/dilithium_ots.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using lattice_lrs::ots::DilithiumKeyPair;
using lattice_lrs::ots::DilithiumPublicKey;
using lattice_lrs::ots::DilithiumSignature;
using lattice_lrs::ots::GenerateKeyPair;
using lattice_lrs::ots::Sign;
using lattice_lrs::ots::Verify;
using lattice_lrs::ots::kDilithiumPublicKeyBytes;
using lattice_lrs::ots::kDilithiumSecretKeyBytes;
using lattice_lrs::ots::kDilithiumSignatureBytes;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint8_t> to_bytes(const std::string& text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void test_expected_sizes() {
    // Dilithium5 (NIST Round 3 submission) published sizes.
    require(kDilithiumPublicKeyBytes == 2592, "public key size must be 2592 bytes");
    require(kDilithiumSecretKeyBytes == 4864, "secret key size must be 4864 bytes");
    require(kDilithiumSignatureBytes == 4595, "signature size must be 4595 bytes");
}

void test_key_generation() {
    const DilithiumKeyPair key_pair = GenerateKeyPair();
    require(key_pair.public_key.bytes.size() == kDilithiumPublicKeyBytes,
            "generated public key has wrong size");
    require(key_pair.secret_key.bytes.size() == kDilithiumSecretKeyBytes,
            "generated secret key has wrong size");

    const DilithiumKeyPair second_key_pair = GenerateKeyPair();
    require(key_pair.public_key.bytes != second_key_pair.public_key.bytes,
            "two independently generated public keys must not collide");
}

void test_valid_signature_verifies() {
    const DilithiumKeyPair key_pair = GenerateKeyPair();
    const std::vector<std::uint8_t> message =
        to_bytes("lattice_lrs dilithium_ots valid-signature test");

    const DilithiumSignature signature = Sign(key_pair.secret_key, message);
    require(signature.bytes.size() == kDilithiumSignatureBytes,
            "signature has wrong size");
    require(Verify(key_pair.public_key, message, signature),
            "valid signature must verify under its own public key");
}

void test_modified_message_rejected() {
    const DilithiumKeyPair key_pair = GenerateKeyPair();
    std::vector<std::uint8_t> message =
        to_bytes("lattice_lrs dilithium_ots message-tamper test");
    const DilithiumSignature signature = Sign(key_pair.secret_key, message);

    message[0] ^= 0x01U;
    require(!Verify(key_pair.public_key, message, signature),
            "signature must not verify once the message is modified");
}

void test_modified_signature_rejected() {
    const DilithiumKeyPair key_pair = GenerateKeyPair();
    const std::vector<std::uint8_t> message =
        to_bytes("lattice_lrs dilithium_ots signature-tamper test");
    DilithiumSignature signature = Sign(key_pair.secret_key, message);

    signature.bytes[0] ^= 0x01U;
    require(!Verify(key_pair.public_key, message, signature),
            "modified signature must not verify under the original message");
}

void test_wrong_public_key_rejected() {
    const DilithiumKeyPair signer = GenerateKeyPair();
    const DilithiumKeyPair other = GenerateKeyPair();
    const std::vector<std::uint8_t> message =
        to_bytes("lattice_lrs dilithium_ots wrong-key test");

    const DilithiumSignature signature = Sign(signer.secret_key, message);
    require(!Verify(other.public_key, message, signature),
            "signature must not verify under an unrelated public key");
}

void test_empty_message_round_trip() {
    const DilithiumKeyPair key_pair = GenerateKeyPair();
    const std::vector<std::uint8_t> empty_message;

    const DilithiumSignature signature = Sign(key_pair.secret_key, empty_message);
    require(Verify(key_pair.public_key, empty_message, signature),
            "signing and verifying the empty message must round-trip");
}

}  // namespace

int main() {
    const std::pair<const char*, void (*)()> cases[] = {
        {"expected_sizes", test_expected_sizes},
        {"key_generation", test_key_generation},
        {"valid_signature_verifies", test_valid_signature_verifies},
        {"modified_message_rejected", test_modified_message_rejected},
        {"modified_signature_rejected", test_modified_signature_rejected},
        {"wrong_public_key_rejected", test_wrong_public_key_rejected},
        {"empty_message_round_trip", test_empty_message_round_trip},
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
