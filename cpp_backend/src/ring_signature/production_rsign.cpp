#include "lattice_lrs/ring_signature/production_rsign.hpp"

#include <stdexcept>

namespace lattice_lrs::ring_signature {

ProductionRSignContext::ProductionRSignContext(
    ParameterProfile profile, PublicParameters public_parameters)
    : profile_(std::move(profile)),
      public_parameters_(std::move(public_parameters)),
      proof_parameters_(profile_.protocol2_parameters()),
      transcript_encoder_(),
      auxiliary_commitment_(),
      rejection_exponential_(),
      rejection_(rejection_exponential_),
      gaussian_bundle_() {}

ProductionRSignContext ProductionRSignContext::Create(
    const ParameterProfile& profile, sampling::RandomSource& random) {
    // Throws std::invalid_argument for an internally inconsistent profile
    // (dimension/q/B/T_com bounds) -- see ParameterProfile::validate().
    profile.validate();

    auto hash_to_challenges = std::make_shared<const Shake256CToChallenges>();
    // RSetup (never RSetupForTesting): this is the only call in this file
    // that constructs PublicParameters, and it always produces non-test-
    // only parameters by construction.
    PublicParameters public_parameters =
        RSetup(profile, hash_to_challenges, random);

    if (public_parameters.is_test_only()) {
        // Unreachable in practice (RSetup never produces this), kept as a
        // defensive, explicit rejection rather than silently proceeding
        // if that invariant were ever violated upstream.
        throw std::invalid_argument(
            "ProductionRSignContext::Create: refusing test-only "
            "PublicParameters in a production context");
    }

    return ProductionRSignContext(profile, std::move(public_parameters));
}

std::size_t ProductionRSignContext::expected_ring_size() const {
    return profile_.ring_size();
}

KeyPair ProductionRSignContext::GenerateKeyPair(
    sampling::RandomSource& random) const {
    return RKeygen(public_parameters_, random);
}

RSignSignature ProductionRSignContext::Sign(
    const proofs::Protocol2PublicList& ring,
    const proofs::Protocol2Witness& witness,
    const std::vector<std::uint8_t>& message, sampling::RandomSource& random) {
    return RSign(public_parameters_, proof_parameters_, ring, witness, message,
                transcript_encoder_, gaussian_bundle_.provider(),
                auxiliary_commitment_, rejection_, random);
}

bool ProductionRSignContext::Verify(const proofs::Protocol2PublicList& ring,
                                    const std::vector<std::uint8_t>& message,
                                    const RSignSignature& signature) const {
    return RVerify(public_parameters_, proof_parameters_, ring, message,
                   signature, transcript_encoder_, auxiliary_commitment_);
}

}  // namespace lattice_lrs::ring_signature
