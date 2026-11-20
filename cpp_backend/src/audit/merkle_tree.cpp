#include "lattice_lrs/audit/merkle_tree.hpp"

extern "C" {
#include "fips202.h"
}

#include <stdexcept>

namespace lattice_lrs::audit {
namespace {

using Hash = std::array<std::uint8_t, 32>;

void append_size(std::vector<std::uint8_t>& output, std::size_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(
            static_cast<std::uint64_t>(value) >> shift));
    }
}

void append_string(std::vector<std::uint8_t>& output, const std::string& text) {
    append_size(output, text.size());
    output.insert(output.end(), text.begin(), text.end());
}

std::string to_hex(const Hash& hash) {
    static const char* kDigits = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (std::uint8_t byte : hash) {
        result.push_back(kDigits[byte >> 4]);
        result.push_back(kDigits[byte & 0x0F]);
    }
    return result;
}

bool from_hex_digit(char c, std::uint8_t& value) {
    if (c >= '0' && c <= '9') { value = static_cast<std::uint8_t>(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { value = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { value = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
    return false;
}

Hash from_hex(const std::string& hex) {
    Hash hash{};
    if (hex.size() != 64) {
        throw std::invalid_argument("MerkleAuditTree: malformed 64-hex-char hash");
    }
    for (std::size_t i = 0; i < 32; ++i) {
        std::uint8_t high = 0;
        std::uint8_t low = 0;
        if (!from_hex_digit(hex[2 * i], high) || !from_hex_digit(hex[2 * i + 1], low)) {
            throw std::invalid_argument("MerkleAuditTree: malformed hex digit");
        }
        hash[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return hash;
}

// Domain-separated leaf hash: 0x00 || length-prefixed fields, exactly
// the public fields of one log entry (see AuditRecord's own doc
// comment for what is and is not included).
Hash hash_leaf(const AuditRecord& record) {
    std::vector<std::uint8_t> encoded;
    encoded.push_back(0x00);
    append_size(encoded, record.log_index);
    append_string(encoded, record.ovk_fingerprint);
    append_string(encoded, record.lpcom_commitment_hex);
    encoded.push_back(record.accepted ? 0x01 : 0x00);
    append_string(encoded, record.reason);

    Hash hash{};
    sha3_256(hash.data(), encoded.data(), encoded.size());
    return hash;
}

// Domain-separated internal-node hash: 0x01 || left || right.
Hash hash_internal(const Hash& left, const Hash& right) {
    std::vector<std::uint8_t> encoded;
    encoded.reserve(1 + 32 + 32);
    encoded.push_back(0x01);
    encoded.insert(encoded.end(), left.begin(), left.end());
    encoded.insert(encoded.end(), right.begin(), right.end());

    Hash hash{};
    sha3_256(hash.data(), encoded.data(), encoded.size());
    return hash;
}

}  // namespace

MerkleAuditTree::MerkleAuditTree(std::vector<AuditRecord> records) {
    if (records.empty()) {
        throw std::invalid_argument("MerkleAuditTree: at least one record is required");
    }

    std::vector<Hash> leaves;
    leaves.reserve(records.size());
    for (const AuditRecord& record : records) {
        leaves.push_back(hash_leaf(record));
    }
    levels_.push_back(std::move(leaves));

    while (levels_.back().size() > 1) {
        const std::vector<Hash>& current = levels_.back();
        std::vector<Hash> next;
        next.reserve((current.size() + 1) / 2);
        for (std::size_t i = 0; i < current.size(); i += 2) {
            const Hash& left = current[i];
            // Odd level size: duplicate the last node (same convention
            // as the inspected prototype's own odd-node handling).
            const Hash& right = (i + 1 < current.size()) ? current[i + 1] : current[i];
            next.push_back(hash_internal(left, right));
        }
        levels_.push_back(std::move(next));
    }
}

std::string MerkleAuditTree::RootHex() const {
    return to_hex(levels_.back().front());
}

std::vector<AuditProofStep> MerkleAuditTree::ProofFor(std::size_t index) const {
    if (index >= levels_.front().size()) {
        throw std::out_of_range("MerkleAuditTree::ProofFor: index out of range");
    }

    std::vector<AuditProofStep> proof;
    std::size_t current_index = index;
    for (std::size_t level = 0; level + 1 < levels_.size(); ++level) {
        const std::vector<Hash>& nodes = levels_[level];
        AuditProofStep step;
        if (current_index % 2 == 0) {
            std::size_t sibling_index = current_index + 1;
            step.sibling_is_left = false;
            if (sibling_index >= nodes.size()) sibling_index = current_index;
            step.sibling_hash = nodes[sibling_index];
        } else {
            step.sibling_is_left = true;
            step.sibling_hash = nodes[current_index - 1];
        }
        proof.push_back(step);
        current_index /= 2;
    }
    return proof;
}

std::string MerkleAuditTree::HashToHex(const std::array<std::uint8_t, 32>& hash) {
    return to_hex(hash);
}

std::array<std::uint8_t, 32> MerkleAuditTree::HashFromHex(const std::string& hex) {
    return from_hex(hex);
}

bool MerkleAuditTree::VerifyProof(const AuditRecord& record,
                                 const std::vector<AuditProofStep>& proof,
                                 const std::string& expected_root_hex) {
    Hash current = hash_leaf(record);
    for (const AuditProofStep& step : proof) {
        current = step.sibling_is_left ? hash_internal(step.sibling_hash, current)
                                       : hash_internal(current, step.sibling_hash);
    }
    Hash expected;
    try {
        expected = from_hex(expected_root_hex);
    } catch (const std::invalid_argument&) {
        return false;
    }
    return current == expected;
}

}  // namespace lattice_lrs::audit
