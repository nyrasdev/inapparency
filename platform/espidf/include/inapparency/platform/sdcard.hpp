#pragma once

#include "esp_err.h"

namespace inapparency::platform {

struct SdCardConfig {
    int mosi_gpio = 23;
    int miso_gpio = 19;
    int sck_gpio = 18;
    int cs_gpio = 5;
};

// Mount point used for the card.
inline constexpr const char* kSdMountPoint = "/sdcard";

// Mounts a FAT-formatted microSD card over SPI at kSdMountPoint. Never
// formats the card: if it can't be read, it's left alone and an error is
// returned. Call once, from the storage task.
esp_err_t mount_sd_card(const SdCardConfig& config);

} // namespace inapparency::platform
