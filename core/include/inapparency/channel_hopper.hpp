#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace inapparency {

// Decides which 2.4 GHz channel to listen on and when to move on. It only
// makes decisions; the platform adapter does the actual radio switch.
//
// It also keeps track of how long each channel was actually watched, since a
// rule's counts only mean something relative to that.
class ChannelHopper {
public:
    static constexpr std::size_t kMaxChannels = 14;
    static constexpr std::uint32_t kMinDwellMs = 50;

    ChannelHopper();

    // Returns false (and keeps the old setup) if the list is empty, has a
    // channel outside 1-14, or the dwell time is too short.
    bool configure(std::span<const std::uint8_t> channels, std::uint32_t dwell_ms);

    // Stay on one channel. Returns false for a channel outside 1-14.
    bool lock(std::uint8_t channel);
    void unlock();
    bool locked() const { return locked_; }

    // Call regularly. Returns a channel when it's time to switch to it,
    // nothing otherwise. The first call always returns a channel.
    std::optional<std::uint8_t> poll(std::uint64_t now_ms);

    std::optional<std::uint8_t> current() const { return current_; }
    std::uint32_t dwell_ms() const { return dwell_ms_; }
    std::span<const std::uint8_t> channels() const { return {channels_.data(), count_}; }

    // Total time spent on a channel so far, including the ongoing stay.
    std::uint64_t time_on(std::uint8_t channel, std::uint64_t now_ms) const;

    static bool valid_channel(std::uint8_t channel) { return channel >= 1 && channel <= 14; }

private:
    void switch_to(std::uint8_t channel, std::uint64_t now_ms);

    std::array<std::uint8_t, kMaxChannels> channels_{};
    std::size_t count_ = 0;
    std::size_t index_ = 0;
    std::uint32_t dwell_ms_ = 500;

    bool locked_ = false;
    std::uint8_t lock_channel_ = 0;

    std::optional<std::uint8_t> current_;
    std::uint64_t since_ms_ = 0;
    std::array<std::uint64_t, kMaxChannels + 1> time_on_{};
};

// Parses "1,6,11" style lists. Spaces are allowed, duplicates are kept out.
// Returns how many channels were written, or nothing if the text is invalid.
std::optional<std::size_t> parse_channel_list(std::string_view text, std::span<std::uint8_t> out);

} // namespace inapparency
