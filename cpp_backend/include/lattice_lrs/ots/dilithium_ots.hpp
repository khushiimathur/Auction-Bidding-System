#pragma once

// Standalone wrapper around the official CRYSTALS-Dilithium reference
// implementation, compiled as the "Dilithium5" parameter set from the NIST
// Round 3 submission (vendored under dilithium/upstream-round3/ref).
//
// Provenance and version rationale (see project audit notes): the
// Wang-Chen-Ma linkable ring signature paper instantiates its one-time
// signature component with the "very high" parameter set from the original
// 2018 CRYSTALS-Dilithium paper. That exact source is not vendored in this
// repository; neither the Round 2 nor the Round 3 submissions are
// byte-identical to it (both rounds changed parameters/encodings relative to
// the original paper). Round 3's highest-security parameter set
// (DILITHIUM_MODE=5, "Dilithium5") is used here as the closest available,
// actively-specified analogue -- this is a deliberate, documented
// substitution, not an assumption that Round 3 reproduces the paper's exact
// benchmark.
//
// This header exposes only KeyGen/Sign/Verify over the detached-signature
// API (pqcrystals_dilithium5_ref_keypair/_signature/_verify). It does not
// implement H0, public-key masking, linkable signing/verification, or Link;
// those belong to later phases of the WCM integration and build strictly on
// top of this wrapper.
//
// Security note: this is a *one-time* signature use in the WCM construction
// (each ring-signature-key owner generates a fresh Dilithium keypair per
// linkability epoch/use). This wrapper does not enforce one-time usage --
// that policy lives in the calling linkable-ring-signature layer.

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lattice_lrs::ots {

// Sizes are taken verbatim from the vendored Dilithium5 api.h constants
// (pqcrystals_dilithium5_PUBLICKEYBYTES / _SECRETKEYBYTES / _BYTES) via the
// .cpp translation unit; they are restated here as named constants so this
// header does not need to include the C API to be usable from C++ call
// sites.
inline constexpr std::size_t kDilithiumPublicKeyBytes = 2592;
inline constexpr std::size_t kDilithiumSecretKeyBytes = 4864;
inline constexpr std::size_t kDilithiumSignatureBytes = 4595;

struct DilithiumPublicKey {
    std::array<std::uint8_t, kDilithiumPublicKeyBytes> bytes{};
};

struct DilithiumSecretKey {
    std::array<std::uint8_t, kDilithiumSecretKeyBytes> bytes{};
};

struct DilithiumSignature {
    std::array<std::uint8_t, kDilithiumSignatureBytes> bytes{};
};

struct DilithiumKeyPair {
    DilithiumPublicKey public_key;
    DilithiumSecretKey secret_key;
};

class DilithiumOtsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Generates a fresh Dilithium5 key pair. Internally calls the reference
// implementation's own randombytes(), which on this platform reads from
// /dev/urandom (see dilithium/upstream-round3/ref/randombytes.c). The
// reference detached-signature API exposes no seed/RNG injection point, so
// this wrapper cannot route key generation through the project's
// sampling::RandomSource abstraction; this is a known limitation, not an
// oversight.
DilithiumKeyPair GenerateKeyPair();

// Produces a detached signature over an arbitrary byte message using the
// reference implementation's randomized signing (again via its internal
// randombytes(), not the project's RandomSource).
DilithiumSignature Sign(const DilithiumSecretKey& secret_key,
                         const std::vector<std::uint8_t>& message);

// Verifies a detached signature. Returns true iff the signature is valid
// for exactly this (message, public_key) pair.
bool Verify(const DilithiumPublicKey& public_key,
            const std::vector<std::uint8_t>& message,
            const DilithiumSignature& signature);

}  // namespace lattice_lrs::ots
