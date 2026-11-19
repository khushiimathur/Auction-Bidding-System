#include "lattice_lrs/ots/dilithium_ots.hpp"

// Pulled in via the lattice_lrs_dilithium CMake target, which compiles the
// vendored Round 3 reference sources with -DDILITHIUM_MODE=5. This gives us
// the pqcrystals_dilithium5_ref_* symbols declared in api.h.
extern "C" {
#include "api.h"
}

namespace lattice_lrs::ots {

namespace {

// Fail the build loudly if the vendored source's declared sizes ever drift
// from the constants restated in the public header, instead of silently
// mismatching buffer sizes at runtime.
static_assert(kDilithiumPublicKeyBytes == pqcrystals_dilithium5_PUBLICKEYBYTES,
              "dilithium_ots.hpp public-key size is out of sync with api.h");
static_assert(kDilithiumSecretKeyBytes == pqcrystals_dilithium5_SECRETKEYBYTES,
              "dilithium_ots.hpp secret-key size is out of sync with api.h");
static_assert(kDilithiumSignatureBytes == pqcrystals_dilithium5_BYTES,
              "dilithium_ots.hpp signature size is out of sync with api.h");

}  // namespace

DilithiumKeyPair GenerateKeyPair() {
    DilithiumKeyPair result;
    if (pqcrystals_dilithium5_ref_keypair(result.public_key.bytes.data(),
                                          result.secret_key.bytes.data()) != 0) {
        throw DilithiumOtsError("Dilithium5 key-pair generation failed");
    }
    return result;
}

DilithiumSignature Sign(const DilithiumSecretKey& secret_key,
                         const std::vector<std::uint8_t>& message) {
    DilithiumSignature signature;
    std::size_t signature_length = 0;
    const std::uint8_t* message_data =
        message.empty() ? nullptr : message.data();
    if (pqcrystals_dilithium5_ref_signature(
            signature.bytes.data(), &signature_length, message_data,
            message.size(), secret_key.bytes.data()) != 0) {
        throw DilithiumOtsError("Dilithium5 signing failed");
    }
    if (signature_length != kDilithiumSignatureBytes) {
        throw DilithiumOtsError(
            "Dilithium5 produced a signature of unexpected length");
    }
    return signature;
}

bool Verify(const DilithiumPublicKey& public_key,
            const std::vector<std::uint8_t>& message,
            const DilithiumSignature& signature) {
    const std::uint8_t* message_data =
        message.empty() ? nullptr : message.data();
    return pqcrystals_dilithium5_ref_verify(
               signature.bytes.data(), signature.bytes.size(), message_data,
               message.size(), public_key.bytes.data()) == 0;
}

}  // namespace lattice_lrs::ots
