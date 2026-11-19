#pragma once

#include "lattice_lrs/ring_signature/ring_signature.hpp"

namespace lattice_lrs::ring_signature {

class CanonicalRSignTranscriptEncoder final
    : public RSignTranscriptEncoder {
public:
    std::vector<std::uint8_t> encode(
        const commitment::CommitmentKey& key,
        const std::vector<std::uint8_t>& message,
        const proofs::Protocol2PublicList& ring,
        const std::vector<proofs::Protocol2FirstMessage>& first_messages)
        const override;
};

class Shake256CToChallenges final : public HashToChallenges {
public:
    ChallengeVector hash(
        const std::vector<std::uint8_t>& input,
        const ChallengeSet& challenge_set,
        std::size_t output_count) const override;
};

}  // namespace lattice_lrs::ring_signature
