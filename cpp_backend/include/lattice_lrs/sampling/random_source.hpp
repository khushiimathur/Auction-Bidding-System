#pragma once

#include <cstddef>
#include <cstdint>

namespace lattice_lrs::sampling {

// Injectable byte source. Production callers should use SystemRandomSource;
// deterministic implementations belong in tests only.
class RandomSource {
public:
    virtual ~RandomSource() = default;
    virtual void fill_bytes(std::uint8_t* output, std::size_t length) = 0;
};

// Uses the operating system's cryptographic random facility and throws if it
// cannot obtain all requested bytes.
class SystemRandomSource final : public RandomSource {
public:
    void fill_bytes(std::uint8_t* output, std::size_t length) override;
};

}  // namespace lattice_lrs::sampling
