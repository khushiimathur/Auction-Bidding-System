#pragma once

// A Merkle tree over an auction's PUBLIC submission log, for a
// tamper-evident, time-ordered audit record (the synopsis's "Public
// Result" / "Merkle tree and hash-chain audit log" step).
//
// This is a NEW module -- no existing repository branch has a Merkle
// implementation to reuse (checked: none of feature/ot-prototype,
// feature/shamir-threshold, feature/post-quantum-ring-signatures, or
// features contain one). It is built on the already-linked, unmodified
// `sha3_256` function from the vendored Dilithium reference fips202.c
// (the same library sealed_bid_auction.cpp already links against for
// its own shake256 fingerprints) -- no new hash primitive is
// implemented here.
//
// --- What gets hashed, precisely ---
// Each leaf is computed ONLY from fields already public in
// SubmissionPublicView: the ovk fingerprint, the LPCom commitment hex,
// accepted/reason, and the submission's position in the log. It NEVER
// includes the bidder's ring index, the plaintext bid amount, the
// LPCom opening (v, r), or any Shamir settlement material -- those
// never leave their existing, already-documented privacy boundaries
// (see sealed_bid_auction.hpp and shamir_secret_sharing/settlement_seal.py).
// Auditing this log's integrity is therefore conceptually SEPARATE from
// LPCom's hiding/binding or Shamir's threshold control: a verifier can
// confirm "this submission is in the published log, unmodified since
// publication" without learning anything LPCom/Shamir already keep private.
//
// --- Domain separation (same convention as the Merkle construction
// inspected earlier from the user's own commitment-code prototype:
// 0x00 for leaves, 0x01 for internal nodes, to prevent a leaf hash
// from ever being reinterpreted as an internal node hash or vice
// versa) ---

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lattice_lrs::audit {

// One record this tree is built over -- exactly the public, already-
// disclosed fields of one auction log entry, nothing more.
struct AuditRecord {
    std::size_t log_index = 0;
    std::string ovk_fingerprint;
    std::string lpcom_commitment_hex;
    bool accepted = false;
    std::string reason;
};

struct AuditProofStep {
    std::array<std::uint8_t, 32> sibling_hash{};
    bool sibling_is_left = false;
};

// Builds the tree over `records` (in the given order -- the order IS
// part of what gets committed to, matching "time ordered record").
// Throws std::invalid_argument if records is empty.
class MerkleAuditTree {
public:
    explicit MerkleAuditTree(std::vector<AuditRecord> records);

    // 64-character lowercase hex SHA3-256 root.
    std::string RootHex() const;

    // Inclusion proof for records[index] (the index as given to the
    // constructor, i.e. position in `records`, not log_index -- callers
    // pass the same list in the same order to both). Throws
    // std::out_of_range for an invalid index.
    std::vector<AuditProofStep> ProofFor(std::size_t index) const;

    // Recomputes the leaf hash for `record` and walks `proof` up to a
    // root; returns true iff that root equals `expected_root_hex`.
    // Static and self-contained so a verifier never needs the whole
    // tree or the other records -- only the one record, its proof, and
    // the published root.
    static bool VerifyProof(const AuditRecord& record,
                           const std::vector<AuditProofStep>& proof,
                           const std::string& expected_root_hex);

    // Hex (de)serialization for a single 32-byte hash, for callers
    // (e.g. the CLI layer) that need to transmit a proof step's
    // sibling hash as text.
    static std::string HashToHex(const std::array<std::uint8_t, 32>& hash);
    static std::array<std::uint8_t, 32> HashFromHex(const std::string& hex);

private:
    std::vector<std::vector<std::array<std::uint8_t, 32>>> levels_;
};

}  // namespace lattice_lrs::audit
