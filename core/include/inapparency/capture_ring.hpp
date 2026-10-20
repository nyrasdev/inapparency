#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include "inapparency/observation.hpp"

namespace inapparency {

struct CaptureMetadata {
    std::uint64_t timestamp_ms = 0;
    std::optional<std::uint8_t> channel;
    std::optional<std::int8_t> rssi_dbm;
    std::optional<std::size_t> original_length;
    bool includes_fcs = false;
};

// Hands frames from the radio callback to the processing task.
//
// One producer, one consumer, no locks and no allocation. The radio side
// copies a frame in and moves on; it never waits for detection. When the
// ring is full the new frame is dropped and counted, so a slow consumer
// shows up in the stats instead of stalling the radio.
//
// Frames longer than MaxFrame are cut and marked as such through
// original_length, so the parser knows the capture was incomplete.
template <std::size_t Slots, std::size_t MaxFrame> class CaptureRing {
    static_assert(Slots >= 2 && (Slots & (Slots - 1)) == 0, "Slots must be a power of two");
    static_assert(MaxFrame >= 32);

public:
    // Producer side. Returns false when the frame was dropped.
    bool push(std::span<const std::uint8_t> bytes, const CaptureMetadata& meta) {
        const std::uint32_t head = head_.load(std::memory_order_relaxed);
        const std::uint32_t tail = tail_.load(std::memory_order_acquire);
        if (head - tail >= Slots) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        Slot& slot = slots_[head & (Slots - 1)];
        const std::size_t copied = bytes.size() < MaxFrame ? bytes.size() : MaxFrame;
        if (copied > 0) {
            std::memcpy(slot.bytes.data(), bytes.data(), copied);
        }
        slot.length = copied;
        slot.meta = meta;
        if (copied < bytes.size()) {
            std::size_t real = bytes.size();
            if (meta.original_length && *meta.original_length > real) {
                real = *meta.original_length;
            }
            slot.meta.original_length = real;
        }

        head_.store(head + 1, std::memory_order_release);
        const std::uint32_t used = head + 1 - tail;
        if (used > high_water_.load(std::memory_order_relaxed)) {
            high_water_.store(used, std::memory_order_relaxed);
        }
        return true;
    }

    // Consumer side. Fills `out` with a view into the oldest slot. The view
    // stays valid until release() is called.
    bool front(Observation& out) const {
        const std::uint32_t tail = tail_.load(std::memory_order_relaxed);
        const std::uint32_t head = head_.load(std::memory_order_acquire);
        if (head == tail) {
            return false;
        }
        const Slot& slot = slots_[tail & (Slots - 1)];
        out.timestamp_ms = slot.meta.timestamp_ms;
        out.bytes = std::span<const std::uint8_t>(slot.bytes.data(), slot.length);
        out.original_length = slot.meta.original_length;
        out.channel = slot.meta.channel;
        out.rssi_dbm = slot.meta.rssi_dbm;
        out.includes_fcs = slot.meta.includes_fcs;
        return true;
    }

    void release() {
        const std::uint32_t tail = tail_.load(std::memory_order_relaxed);
        if (tail != head_.load(std::memory_order_acquire)) {
            tail_.store(tail + 1, std::memory_order_release);
        }
    }

    std::size_t size() const {
        return head_.load(std::memory_order_acquire) - tail_.load(std::memory_order_acquire);
    }
    std::uint32_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
    std::uint32_t high_water() const { return high_water_.load(std::memory_order_relaxed); }
    static constexpr std::size_t capacity() { return Slots; }
    static constexpr std::size_t max_frame() { return MaxFrame; }

private:
    struct Slot {
        std::array<std::uint8_t, MaxFrame> bytes{};
        std::size_t length = 0;
        CaptureMetadata meta;
    };

    std::array<Slot, Slots> slots_{};
    std::atomic<std::uint32_t> head_{0};
    std::atomic<std::uint32_t> tail_{0};
    std::atomic<std::uint32_t> dropped_{0};
    std::atomic<std::uint32_t> high_water_{0};
};

} // namespace inapparency
