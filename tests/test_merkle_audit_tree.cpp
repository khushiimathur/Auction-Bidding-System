// Unit tests for lattice_lrs::audit::MerkleAuditTree -- the new
// hash-chain/audit-log module (synopsis's "Public Result" step). Real
// SHA3-256 throughout (the vendored, unmodified fips202.c), no mocks.

#include "lattice_lrs/audit/merkle_tree.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

using namespace lattice_lrs::audit;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::vector<AuditRecord> sample_records(std::size_t count) {
    std::vector<AuditRecord> records;
    for (std::size_t i = 0; i < count; ++i) {
        AuditRecord record;
        record.log_index = i;
        record.ovk_fingerprint = "ovkfp" + std::to_string(i);
        record.lpcom_commitment_hex = "commit" + std::to_string(i);
        record.accepted = (i % 2 == 0);
        record.reason = record.accepted ? "accepted" : "rejected: duplicate";
        records.push_back(record);
    }
    return records;
}

void test_empty_records_rejected() {
    bool threw = false;
    try {
        MerkleAuditTree tree(std::vector<AuditRecord>{});
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    require(threw, "an empty record list must be rejected");
}

void test_single_record_root_and_proof() {
    MerkleAuditTree tree(sample_records(1));
    const std::string root = tree.RootHex();
    require(root.size() == 64, "root must be a 64-hex-char SHA3-256 digest");

    const auto proof = tree.ProofFor(0);
    require(MerkleAuditTree::VerifyProof(sample_records(1)[0], proof, root),
           "a single-record tree's own record must verify against its root");
}

void test_valid_inclusion_proofs_for_all_sizes() {
    for (std::size_t count : {2, 3, 4, 5, 7, 8, 16, 17}) {
        auto records = sample_records(count);
        MerkleAuditTree tree(records);
        const std::string root = tree.RootHex();
        for (std::size_t i = 0; i < count; ++i) {
            const auto proof = tree.ProofFor(i);
            require(MerkleAuditTree::VerifyProof(records[i], proof, root),
                   "record " + std::to_string(i) + " of " + std::to_string(count) +
                       " must verify");
        }
    }
}

void test_tampered_record_fails_verification() {
    auto records = sample_records(5);
    MerkleAuditTree tree(records);
    const std::string root = tree.RootHex();
    const auto proof = tree.ProofFor(2);

    AuditRecord tampered = records[2];
    tampered.lpcom_commitment_hex = "a-different-commitment";
    require(!MerkleAuditTree::VerifyProof(tampered, proof, root),
           "a tampered record must fail verification against the real root");
}

void test_tampered_reason_or_accepted_flag_fails_verification() {
    auto records = sample_records(4);
    MerkleAuditTree tree(records);
    const std::string root = tree.RootHex();
    const auto proof = tree.ProofFor(1);

    AuditRecord tampered_reason = records[1];
    tampered_reason.reason = "accepted";  // flip the actual reason text
    require(!MerkleAuditTree::VerifyProof(tampered_reason, proof, root),
           "a tampered reason must fail verification");

    AuditRecord tampered_flag = records[1];
    tampered_flag.accepted = !tampered_flag.accepted;
    require(!MerkleAuditTree::VerifyProof(tampered_flag, proof, root),
           "a tampered accepted flag must fail verification");
}

void test_proof_from_wrong_index_fails_verification() {
    auto records = sample_records(6);
    MerkleAuditTree tree(records);
    const std::string root = tree.RootHex();

    const auto proof_for_index_0 = tree.ProofFor(0);
    require(!MerkleAuditTree::VerifyProof(records[3], proof_for_index_0, root),
           "record 3 must not verify against a proof generated for index 0");
}

void test_wrong_root_fails_verification() {
    auto records_a = sample_records(4);
    auto records_b = sample_records(5);  // a different log entirely
    MerkleAuditTree tree_a(records_a);
    MerkleAuditTree tree_b(records_b);

    const auto proof = tree_a.ProofFor(0);
    require(!MerkleAuditTree::VerifyProof(records_a[0], proof, tree_b.RootHex()),
           "a correct record/proof must fail against a DIFFERENT tree's root");
}

void test_out_of_range_proof_index_throws() {
    MerkleAuditTree tree(sample_records(3));
    bool threw = false;
    try {
        tree.ProofFor(99);
    } catch (const std::out_of_range&) {
        threw = true;
    }
    require(threw, "an out-of-range proof index must throw");
}

void test_malformed_root_hex_is_rejected_not_crashed() {
    auto records = sample_records(2);
    MerkleAuditTree tree(records);
    const auto proof = tree.ProofFor(0);
    require(!MerkleAuditTree::VerifyProof(records[0], proof, "not-a-valid-hex-root"),
           "a malformed expected root must be rejected, not crash");
}

void test_hash_hex_round_trip() {
    auto records = sample_records(3);
    MerkleAuditTree tree(records);
    const auto proof = tree.ProofFor(1);
    require(!proof.empty(), "a 3-leaf tree must have at least one proof step");
    const std::string hex = MerkleAuditTree::HashToHex(proof[0].sibling_hash);
    require(hex.size() == 64, "hash hex encoding must be 64 characters");
    const auto round_tripped = MerkleAuditTree::HashFromHex(hex);
    require(round_tripped == proof[0].sibling_hash,
           "hash hex round-trip must reproduce the exact bytes");
}

void test_order_matters_different_order_gives_different_root() {
    auto records = sample_records(4);
    MerkleAuditTree tree_forward(records);
    std::vector<AuditRecord> reordered = {records[1], records[0], records[2], records[3]};
    MerkleAuditTree tree_reordered(reordered);
    require(tree_forward.RootHex() != tree_reordered.RootHex(),
           "swapping log order must change the root (order is part of the commitment)");
}

}  // namespace

int main() {
    try {
        test_empty_records_rejected();
        test_single_record_root_and_proof();
        test_valid_inclusion_proofs_for_all_sizes();
        test_tampered_record_fails_verification();
        test_tampered_reason_or_accepted_flag_fails_verification();
        test_proof_from_wrong_index_fails_verification();
        test_wrong_root_fails_verification();
        test_out_of_range_proof_index_throws();
        test_malformed_root_hex_is_rejected_not_crashed();
        test_hash_hex_round_trip();
        test_order_matters_different_order_gives_different_root();
    } catch (const std::exception& error) {
        std::cerr << "merkle_audit_tree test failure: " << error.what() << std::endl;
        return 1;
    }
    std::cout << "All merkle_audit_tree tests passed." << std::endl;
    return 0;
}
