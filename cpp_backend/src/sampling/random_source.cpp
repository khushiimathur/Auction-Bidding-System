#include "lattice_lrs/sampling/random_source.hpp"
#include "random_source_detail.hpp"

#include <cerrno>
#include <limits>
#include <stdexcept>

#if defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#else
#error "SystemRandomSource supports macOS, Windows, and Linux only"
#endif

namespace lattice_lrs::sampling {

void SystemRandomSource::fill_bytes(std::uint8_t* output, std::size_t length) {
    if (length != 0 && output == nullptr) {
        throw std::invalid_argument("random output buffer must not be null");
    }

#if defined(__APPLE__)
    // SecRandomCopyBytes is Apple's operating-system cryptographic RNG and
    // returns an error status if bytes cannot be provided.
    detail::fill_all_or_fail(output, length, [](std::uint8_t* destination,
                                                std::size_t count) {
        return SecRandomCopyBytes(kSecRandomDefault, count, destination) == errSecSuccess;
    });
#elif defined(__linux__)
    detail::fill_from_partial_reader(output, length, EINTR,
        [](std::uint8_t* destination, std::size_t count) {
            const ssize_t received = getrandom(destination, count, 0);
            const int error_code = received < 0 ? errno : 0;
            return detail::ReadResult{static_cast<std::ptrdiff_t>(received), error_code};
        });
#elif defined(_WIN32)
    const std::size_t max_request =
        static_cast<std::size_t>(std::numeric_limits<ULONG>::max());
    detail::fill_in_chunks_with_nt_status(output, length, max_request,
        [](std::uint8_t* destination, std::size_t count) {
            const NTSTATUS status = BCryptGenRandom(
                nullptr, destination, static_cast<ULONG>(count),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            return static_cast<std::int32_t>(status);
        });
#endif
}

}  // namespace lattice_lrs::sampling
