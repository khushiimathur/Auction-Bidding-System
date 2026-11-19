#include "sampling/random_source_detail.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Operation>
void require_runtime_error(Operation&& operation, const std::string& message) {
    bool threw = false;
    try {
        operation();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    require(threw, message);
}

void test_linux_partial_reads_and_eintr() {
    std::array<std::uint8_t, 5> output{};
    std::vector<std::size_t> requests;
    std::size_t call = 0;

    lattice_lrs::sampling::detail::fill_from_partial_reader(
        output.data(), output.size(), EINTR,
        [&](std::uint8_t* destination, std::size_t requested) {
            requests.push_back(requested);
            if (call++ == 0) {
                return lattice_lrs::sampling::detail::ReadResult{-1, EINTR};
            }
            if (call == 2) {
                destination[0] = 0x21;
                destination[1] = 0x22;
                return lattice_lrs::sampling::detail::ReadResult{2, 0};
            }
            destination[0] = 0x23;
            destination[1] = 0x24;
            destination[2] = 0x25;
            return lattice_lrs::sampling::detail::ReadResult{3, 0};
        });

    require(requests == std::vector<std::size_t>({5, 5, 3}),
            "Linux retry must preserve offset after EINTR and partial reads");
    require(output == std::array<std::uint8_t, 5>{0x21, 0x22, 0x23, 0x24, 0x25},
            "Linux partial-read helper must fill the complete output buffer");
}

void test_linux_zero_and_os_error_fail_closed() {
    std::array<std::uint8_t, 4> output{};
    require_runtime_error([&] {
        lattice_lrs::sampling::detail::fill_from_partial_reader(
            output.data(), output.size(), EINTR,
            [](std::uint8_t*, std::size_t) {
                return lattice_lrs::sampling::detail::ReadResult{0, 0};
            });
    }, "Linux zero-byte return for nonempty request must throw");

    require_runtime_error([&] {
        lattice_lrs::sampling::detail::fill_from_partial_reader(
            output.data(), output.size(), EINTR,
            [](std::uint8_t*, std::size_t) {
                return lattice_lrs::sampling::detail::ReadResult{-1, EIO};
            });
    }, "Linux OS error other than EINTR must throw");
}

void test_windows_chunking_and_bcrypt_failure() {
    std::array<std::uint8_t, 10> output{};
    std::vector<std::size_t> requests;
    lattice_lrs::sampling::detail::fill_in_chunks_with_nt_status(
        output.data(), output.size(), 4,
        [&](std::uint8_t* destination, std::size_t count) {
            requests.push_back(count);
            for (std::size_t i = 0; i < count; ++i) {
                destination[i] = static_cast<std::uint8_t>(requests.size());
            }
            // Include a positive NTSTATUS, which NT_SUCCESS treats as success.
            return requests.size() == 2 ? 1 : 0;
        });
    require(requests == std::vector<std::size_t>({4, 4, 2}),
            "Windows helper must split requests at the ULONG-sized limit");
    require(output[0] == 1 && output[4] == 2 && output[8] == 3,
            "Windows helper must advance output pointer between chunks");

    std::size_t calls = 0;
    require_runtime_error([&] {
        lattice_lrs::sampling::detail::fill_in_chunks_with_nt_status(
            output.data(), output.size(), 4,
            [&](std::uint8_t*, std::size_t) {
                return calls++ == 0 ? 0 : -1;
            });
    }, "negative BCrypt status must throw instead of returning partial output");
    require(calls == 2, "Windows helper must stop at the first failed chunk");
}

void test_macos_sec_random_status_handling() {
    std::array<std::uint8_t, 4> output{};
    bool invoked = false;
    lattice_lrs::sampling::detail::fill_all_or_fail(
        output.data(), output.size(),
        [&](std::uint8_t* destination, std::size_t count) {
            invoked = true;
            for (std::size_t i = 0; i < count; ++i) {
                destination[i] = static_cast<std::uint8_t>(i + 1);
            }
            return true;
        });
    require(invoked && output[0] == 1 && output[3] == 4,
            "macOS helper must accept successful SecRandomCopyBytes status");

    require_runtime_error([&] {
        lattice_lrs::sampling::detail::fill_all_or_fail(
            output.data(), output.size(), [](std::uint8_t*, std::size_t) {
                return false;
            });
    }, "non-success SecRandomCopyBytes status must throw");

    invoked = false;
    lattice_lrs::sampling::detail::fill_all_or_fail(
        nullptr, 0, [&](std::uint8_t*, std::size_t) {
            invoked = true;
            return true;
        });
    require(!invoked, "zero-length request must not invoke the OS provider");
}

}  // namespace

int main() {
    try {
        test_linux_partial_reads_and_eintr();
        test_linux_zero_and_os_error_fail_closed();
        test_windows_chunking_and_bcrypt_failure();
        test_macos_sec_random_status_handling();
    } catch (const std::exception& error) {
        std::cerr << "random source platform helper test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
