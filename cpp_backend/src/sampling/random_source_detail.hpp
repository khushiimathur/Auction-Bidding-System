#pragma once

// Internal, platform-neutral helpers for the OS-backed RandomSource.
// This header is private to the backend and is exposed to the dedicated test
// target only so platform error paths can be fault-injected on any host.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace lattice_lrs::sampling::detail {

struct ReadResult {
    std::ptrdiff_t count;
    int error_code;
};

template <typename Reader>
void fill_from_partial_reader(std::uint8_t* output, std::size_t length,
                              int interrupted_error, Reader&& reader) {
    std::size_t offset = 0;
    while (offset < length) {
        const std::size_t remaining = length - offset;
        const ReadResult result = reader(output + offset, remaining);
        if (result.count > 0) {
            const auto received = static_cast<std::size_t>(result.count);
            if (received > remaining) {
                throw std::runtime_error("operating-system entropy request failed");
            }
            offset += received;
        } else if (result.count < 0 && result.error_code == interrupted_error) {
            continue;
        } else {
            // A zero-byte result for a nonempty request is not completion.
            throw std::runtime_error("operating-system entropy request failed");
        }
    }
}

template <typename Generator>
void fill_in_chunks_with_nt_status(std::uint8_t* output, std::size_t length,
                                   std::size_t max_chunk, Generator&& generate) {
    if (max_chunk == 0) {
        throw std::invalid_argument("random request chunk size must be positive");
    }

    std::size_t offset = 0;
    while (offset < length) {
        const std::size_t chunk = std::min(length - offset, max_chunk);
        const std::int32_t status = generate(output + offset, chunk);
        // NT_SUCCESS(status) is true for nonnegative NTSTATUS values.
        if (status < 0) {
            throw std::runtime_error("operating-system entropy request failed");
        }
        offset += chunk;
    }
}

template <typename Generator>
void fill_all_or_fail(std::uint8_t* output, std::size_t length,
                      Generator&& generate) {
    if (length != 0 && !generate(output, length)) {
        throw std::runtime_error("operating-system entropy request failed");
    }
}

}  // namespace lattice_lrs::sampling::detail
