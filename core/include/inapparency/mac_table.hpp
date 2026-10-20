#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "inapparency/frame.hpp"

namespace inapparency {

// Fixed-capacity table keyed by MAC address. When it's full, the entry that
// was touched longest ago gets replaced. Lookups are linear, which is fine
// for the small sizes used on a microcontroller.
template <typename Value, std::size_t Capacity> class MacTable {
    static_assert(Capacity > 0);

public:
    const Value* find(const MacAddress& key) const {
        for (const auto& slot : slots_) {
            if (slot.used && slot.key == key) {
                return &slot.value;
            }
        }
        return nullptr;
    }

    Value* find(const MacAddress& key) {
        return const_cast<Value*>(std::as_const(*this).find(key));
    }

    // Finds the entry or creates a fresh one. `inserted` tells the caller
    // whether it has to initialize the value.
    Value& touch(const MacAddress& key, std::uint64_t now_ms, bool& inserted) {
        Slot* victim = nullptr;
        for (auto& slot : slots_) {
            if (slot.used && slot.key == key) {
                if (now_ms > slot.last_touch_ms) {
                    slot.last_touch_ms = now_ms;
                }
                inserted = false;
                return slot.value;
            }
            if (!slot.used) {
                if (victim == nullptr || victim->used) {
                    victim = &slot;
                }
            } else if (victim == nullptr ||
                       (victim->used && slot.last_touch_ms < victim->last_touch_ms)) {
                victim = &slot;
            }
        }

        if (victim->used) {
            ++evictions_;
        } else {
            ++size_;
        }
        victim->used = true;
        victim->key = key;
        victim->last_touch_ms = now_ms;
        victim->value = Value{};
        inserted = true;
        return victim->value;
    }

    std::size_t size() const { return size_; }
    static constexpr std::size_t capacity() { return Capacity; }
    std::uint32_t evictions() const { return evictions_; }

private:
    struct Slot {
        bool used = false;
        MacAddress key;
        std::uint64_t last_touch_ms = 0;
        Value value{};
    };

    std::array<Slot, Capacity> slots_{};
    std::size_t size_ = 0;
    std::uint32_t evictions_ = 0;
};

} // namespace inapparency
