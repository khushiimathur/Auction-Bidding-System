#pragma once

// A real-cryptography "cryptographic playground" for the Streamlit demo:
// raw lrs::LRKeygenForTesting / LRSignForTesting / LRVerifyForTesting /
// LinkForTesting at demo_parameters.hpp's shared TestOnly dimensions --
// no auction semantics (no duplicate detection, no per-bidder one-time
// guard reuse policy). This exists because SealedBidAuction's SubmitBid
// bundles signing, verification, AND duplicate detection into one call;
// the playground needs each step exposed separately (sign, THEN verify,
// THEN optionally tamper and re-verify, THEN link two independently
// produced signatures) so a UI can walk through them one at a time.
//
// Every operation here is the same real algorithm SealedBidAuction and
// ProductionLRSignContext use -- composition and lifetime management
// only, no new cryptographic algorithm, and no mock.

#include "lattice_lrs/lrs/link.hpp"
#include "lattice_lrs/lrs/linkable_ring_signature.hpp"
#include "lattice_lrs/proofs/bernoulli_exponential.hpp"
#include "lattice_lrs/proofs/production_gaussian_provider.hpp"
#include "lattice_lrs/proofs/shake256_auxiliary_commitment.hpp"
#include "lattice_lrs/ring_signature/canonical_rsign_transcript.hpp"
#include "lattice_lrs/ring_signature/production_rejection_provider.hpp"
#include "lattice_lrs/ring_signature/ring_signature.hpp"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace lattice_lrs::demo {

enum class TamperMode {
    None,
    Message,
    Signature,
    Ring,
};

struct SignedRecord {
    std::size_t signer_index = 0;
    std::vector<std::uint8_t> message;
    lrs::LinkableSignature signature;
    std::string ovk_fingerprint;
};

struct VerifyResult {
    bool accepted = false;
    std::string tamper_mode;  // echoes what was actually tested
};

class PlaygroundSession final {
public:
    // Generates a fresh ring of lattice_lrs::auction::kDemoRingSize real
    // key pairs via lrs::LRKeygenForTesting. Every call to Create()
    // produces an entirely independent ring and OTS keys -- there is no
    // shared state between playground "runs", mirroring how each
    // SealedBidAuction::Create() call is independent.
    static PlaygroundSession Create(sampling::RandomSource& random);

    PlaygroundSession(const PlaygroundSession&) = delete;
    PlaygroundSession& operator=(const PlaygroundSession&) = delete;
    PlaygroundSession(PlaygroundSession&&) = default;
    PlaygroundSession& operator=(PlaygroundSession&&) = delete;

    std::size_t ring_size() const noexcept { return ring_.size(); }

    // Fingerprints of the ring's actual PUBLIC KEYS (pk_i =
    // p̂k_i + H'(ovk_i)) -- the ring LRSign/LRVerify operate over, and
    // the same quantity auction::SealedBidAuction::RingFingerprints()
    // reports. These are fixed at Create() time, before any signature.
    std::vector<std::string> RingFingerprints() const;

    // Real LRSignForTesting. Returns the new signature's id (used to
    // refer to it in Verify/Link below), the SIGNER's public key
    // fingerprint (pk, unchanged by signing -- shown so a UI can point
    // out "this is who signed" alongside the one-time ovk tag), and the
    // one-time ovk fingerprint that Link actually compares.
    struct SignOutcome {
        std::size_t signature_id = 0;
        std::string pk_fingerprint;
        std::string ovk_fingerprint;
    };
    SignOutcome Sign(std::size_t signer_index,
                     const std::vector<std::uint8_t>& message,
                     sampling::RandomSource& random);

    // Real LRVerifyForTesting against the ORIGINAL message/ring, or a
    // deliberately mutated copy per `mode` (TamperMode::None re-verifies
    // the untouched signature/message/ring -- this must always accept).
    VerifyResult Verify(std::size_t signature_id, TamperMode mode) const;

    // Real LinkForTesting between two previously produced signatures
    // (each re-verified internally by Link itself, per WCM's own
    // algorithm; see link.hpp).
    lrs::LinkOutcome Link(std::size_t signature_id_a,
                         std::size_t signature_id_b) const;

private:
    PlaygroundSession(ring_signature::PublicParameters public_parameters,
                     proofs::Protocol2Parameters proof_parameters,
                     std::vector<lrs::LinkableKeyPair> keys);

    const SignedRecord& Get(std::size_t signature_id) const;

    ring_signature::PublicParameters public_parameters_;
    proofs::Protocol2Parameters proof_parameters_;
    std::vector<lrs::LinkableKeyPair> keys_;
    proofs::Protocol2PublicList ring_;

    ring_signature::CanonicalRSignTranscriptEncoder transcript_encoder_;
    proofs::Shake256AuxiliaryCommitmentProvider auxiliary_commitment_;
    proofs::ExactBernoulliExponentialProvider rejection_exponential_;
    ring_signature::Section6BatchRejectionProvider rejection_;
    proofs::SigmaSection6GaussianProviderBundle gaussian_bundle_;

    std::map<std::size_t, SignedRecord> signatures_;
    std::size_t next_signature_id_ = 1;
};

}  // namespace lattice_lrs::demo
