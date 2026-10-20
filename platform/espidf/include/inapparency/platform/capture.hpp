#pragma once

#include <cstdint>

#include "esp_err.h"
#include "inapparency/capture_ring.hpp"

namespace inapparency::platform {

// 32 frames in flight, up to 512 bytes each (about 17 KB). Management frames
// are almost always smaller; longer ones are cut and marked as cut.
using FrameRing = CaptureRing<32, 512>;

// Starts the radio in passive promiscuous mode, management frames only, and
// copies every received frame into `ring`.
//
// The radio is put in WIFI_MODE_NULL: it never associates, scans or sends
// anything. Only call once.
esp_err_t start_capture(FrameRing& ring);

esp_err_t set_channel(std::uint8_t channel);

// Frames handed over by the radio since start, including dropped ones.
std::uint32_t frames_received();

} // namespace inapparency::platform
