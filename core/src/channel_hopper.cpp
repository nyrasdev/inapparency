#include "inapparency/channel_hopper.hpp"

namespace inapparency {

ChannelHopper::ChannelHopper() {
    // Most networks sit on 1, 6 or 11.
    channels_[0] = 1;
    channels_[1] = 6;
    channels_[2] = 11;
    count_ = 3;
}

bool ChannelHopper::configure(std::span<const std::uint8_t> channels, std::uint32_t dwell_ms) {
    if (channels.empty() || channels.size() > kMaxChannels || dwell_ms < kMinDwellMs) {
        return false;
    }
    for (auto c : channels) {
        if (!valid_channel(c)) {
            return false;
        }
    }
    for (std::size_t i = 0; i < channels.size(); ++i) {
        channels_[i] = channels[i];
    }
    count_ = channels.size();
    index_ = 0;
    dwell_ms_ = dwell_ms;
    if (!locked_) {
        current_.reset(); // next poll starts the new list
    }
    return true;
}

bool ChannelHopper::lock(std::uint8_t channel) {
    if (!valid_channel(channel)) {
        return false;
    }
    locked_ = true;
    lock_channel_ = channel;
    return true;
}

void ChannelHopper::unlock() {
    locked_ = false;
}

void ChannelHopper::switch_to(std::uint8_t channel, std::uint64_t now_ms) {
    if (current_ && now_ms > since_ms_) {
        time_on_[*current_] += now_ms - since_ms_;
    }
    current_ = channel;
    since_ms_ = now_ms;
}

std::optional<std::uint8_t> ChannelHopper::poll(std::uint64_t now_ms) {
    if (locked_) {
        if (current_ != lock_channel_) {
            switch_to(lock_channel_, now_ms);
            return lock_channel_;
        }
        return std::nullopt;
    }

    if (!current_) {
        index_ = 0;
        switch_to(channels_[0], now_ms);
        return current_;
    }
    if (count_ == 1 && *current_ == channels_[0]) {
        return std::nullopt;
    }
    if (now_ms < since_ms_ || now_ms - since_ms_ < dwell_ms_) {
        return std::nullopt;
    }

    index_ = (index_ + 1) % count_;
    std::uint8_t next = channels_[index_];
    if (next == *current_) {
        // Same channel again (single-entry list): just restart the stay.
        switch_to(next, now_ms);
        return std::nullopt;
    }
    switch_to(next, now_ms);
    return next;
}

std::uint64_t ChannelHopper::time_on(std::uint8_t channel, std::uint64_t now_ms) const {
    if (!valid_channel(channel)) {
        return 0;
    }
    std::uint64_t total = time_on_[channel];
    if (current_ && *current_ == channel && now_ms > since_ms_) {
        total += now_ms - since_ms_;
    }
    return total;
}

std::optional<std::size_t> parse_channel_list(std::string_view text, std::span<std::uint8_t> out) {
    std::size_t count = 0;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && text[i] == ' ') {
            ++i;
        }
        unsigned value = 0;
        std::size_t digits = 0;
        while (i < text.size() && text[i] >= '0' && text[i] <= '9' && digits < 3) {
            value = value * 10 + static_cast<unsigned>(text[i] - '0');
            ++i;
            ++digits;
        }
        if (digits == 0 || value < 1 || value > 14) {
            return std::nullopt;
        }
        while (i < text.size() && text[i] == ' ') {
            ++i;
        }
        if (i < text.size()) {
            if (text[i] != ',') {
                return std::nullopt;
            }
            ++i;
            if (i == text.size()) {
                return std::nullopt; // trailing comma
            }
        }

        auto channel = static_cast<std::uint8_t>(value);
        bool duplicate = false;
        for (std::size_t j = 0; j < count; ++j) {
            duplicate = duplicate || out[j] == channel;
        }
        if (!duplicate) {
            if (count == out.size()) {
                return std::nullopt;
            }
            out[count++] = channel;
        }
    }
    if (count == 0) {
        return std::nullopt;
    }
    return count;
}

} // namespace inapparency
