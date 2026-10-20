#pragma once

#include <array>
#include <cstddef>

#include "inapparency/rule.hpp"

namespace inapparency {

// Hands every event to several outputs (serial, display, SD card...).
// Outputs are optional: if one isn't added, nothing else changes.
class EventFanout final : public EventSink {
public:
    static constexpr std::size_t kMaxOutputs = 4;

    // Returns false when full.
    bool add(EventSink& output) {
        if (count_ == kMaxOutputs) {
            return false;
        }
        outputs_[count_++] = &output;
        return true;
    }

    void emit(const DetectionEvent& event) override {
        for (std::size_t i = 0; i < count_; ++i) {
            outputs_[i]->emit(event);
        }
    }

    std::size_t size() const { return count_; }

private:
    std::array<EventSink*, kMaxOutputs> outputs_{};
    std::size_t count_ = 0;
};

} // namespace inapparency
