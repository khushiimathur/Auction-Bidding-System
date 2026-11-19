#include "lattice_lrs/lrs/link.hpp"

namespace lattice_lrs::lrs {
namespace {

// Implements exactly WCM Section 3.1's Link algorithm: both signatures must
// independently verify before ovk1/ovk2 are even compared. Neither messages,
// rings, signer indices, nor the Esgin base signatures participate in the
// comparison -- only the complete OTS public-key byte encoding.
LinkOutcome link_impl(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring1,
    const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1,
    const proofs::Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment,
    bool allow_test_only) {
    const bool first_verifies =
        allow_test_only
            ? LRVerifyForTesting(public_parameters, proof_parameters, ring1,
                                 message1, signature1, transcript_encoder,
                                 auxiliary_commitment)
            : LRVerify(public_parameters, proof_parameters, ring1, message1,
                      signature1, transcript_encoder, auxiliary_commitment);
    const bool second_verifies =
        allow_test_only
            ? LRVerifyForTesting(public_parameters, proof_parameters, ring2,
                                 message2, signature2, transcript_encoder,
                                 auxiliary_commitment)
            : LRVerify(public_parameters, proof_parameters, ring2, message2,
                      signature2, transcript_encoder, auxiliary_commitment);

    if (!first_verifies || !second_verifies) {
        return LinkOutcome::Rejected;
    }

    // Complete canonical encoding comparison: ots::DilithiumPublicKey::bytes
    // is a fixed-size std::array<std::uint8_t, kDilithiumPublicKeyBytes>,
    // and std::array's built-in operator== compares every element -- there
    // is no partial-field or display-string comparison here.
    return signature1.ots_public_key.bytes == signature2.ots_public_key.bytes
               ? LinkOutcome::Linked
               : LinkOutcome::Unlinked;
}

}  // namespace

LinkOutcome Link(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring1,
    const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1,
    const proofs::Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    return link_impl(public_parameters, proof_parameters, ring1, message1,
                     signature1, ring2, message2, signature2,
                     transcript_encoder, auxiliary_commitment, false);
}

LinkOutcome LinkForTesting(
    const ring_signature::PublicParameters& public_parameters,
    const proofs::Protocol2Parameters& proof_parameters,
    const proofs::Protocol2PublicList& ring1,
    const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1,
    const proofs::Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2,
    const ring_signature::RSignTranscriptEncoder& transcript_encoder,
    const proofs::Protocol2AuxiliaryCommitmentProvider& auxiliary_commitment) {
    return link_impl(public_parameters, proof_parameters, ring1, message1,
                     signature1, ring2, message2, signature2,
                     transcript_encoder, auxiliary_commitment, true);
}

}  // namespace lattice_lrs::lrs
