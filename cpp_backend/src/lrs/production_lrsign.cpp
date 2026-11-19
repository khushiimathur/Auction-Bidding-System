#include "lattice_lrs/lrs/production_lrsign.hpp"

#include <stdexcept>

namespace lattice_lrs::lrs {

ProductionLRSignContext::ProductionLRSignContext(
    ring_signature::ParameterProfile profile,
    ring_signature::PublicParameters public_parameters)
    : profile_(std::move(profile)),
      public_parameters_(std::move(public_parameters)),
      proof_parameters_(profile_.protocol2_parameters()),
      transcript_encoder_(),
      auxiliary_commitment_(),
      rejection_exponential_(),
      rejection_(rejection_exponential_),
      gaussian_bundle_() {}

ProductionLRSignContext ProductionLRSignContext::Create(
    const ring_signature::ParameterProfile& profile,
    sampling::RandomSource& random) {
    profile.validate();

    auto hash_to_challenges =
        std::make_shared<const ring_signature::Shake256CToChallenges>();
    ring_signature::PublicParameters public_parameters =
        ring_signature::RSetup(profile, hash_to_challenges, random);

    if (public_parameters.is_test_only()) {
        throw std::invalid_argument(
            "ProductionLRSignContext::Create: refusing test-only "
            "PublicParameters in a production context");
    }

    return ProductionLRSignContext(profile, std::move(public_parameters));
}

std::size_t ProductionLRSignContext::expected_ring_size() const {
    return profile_.ring_size();
}

LinkableKeyPair ProductionLRSignContext::GenerateKeyPair(
    sampling::RandomSource& random) const {
    return LRKeygen(public_parameters_, random);
}

LinkableSignature ProductionLRSignContext::Sign(
    const proofs::Protocol2PublicList& ring, std::size_t signer_index,
    OneTimeOtsKeyGuard& signer_key_guard,
    const std::vector<std::uint8_t>& message, sampling::RandomSource& random) {
    return LRSign(public_parameters_, proof_parameters_, ring, signer_index,
                 signer_key_guard, message, transcript_encoder_,
                 gaussian_bundle_.provider(), auxiliary_commitment_,
                 rejection_, random);
}

bool ProductionLRSignContext::Verify(
    const proofs::Protocol2PublicList& ring,
    const std::vector<std::uint8_t>& message,
    const LinkableSignature& signature) const {
    return LRVerify(public_parameters_, proof_parameters_, ring, message,
                    signature, transcript_encoder_, auxiliary_commitment_);
}

LinkOutcome ProductionLRSignContext::Link(
    const proofs::Protocol2PublicList& ring1,
    const std::vector<std::uint8_t>& message1,
    const LinkableSignature& signature1,
    const proofs::Protocol2PublicList& ring2,
    const std::vector<std::uint8_t>& message2,
    const LinkableSignature& signature2) const {
    return lattice_lrs::lrs::Link(public_parameters_, proof_parameters_, ring1,
                                  message1, signature1, ring2, message2,
                                  signature2, transcript_encoder_,
                                  auxiliary_commitment_);
}

}  // namespace lattice_lrs::lrs
