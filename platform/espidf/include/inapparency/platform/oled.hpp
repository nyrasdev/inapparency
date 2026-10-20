#pragma once

#include <cstdint>

#include "esp_err.h"
#include "inapparency/display/framebuffer.hpp"

struct i2c_master_bus_t;
struct i2c_master_dev_t;

namespace inapparency::platform {

enum class OledController : std::uint8_t {
    Ssd1306, // most 0.96" 128x64 modules
    Sh1106,  // most 1.3" 128x64 modules
};

struct OledConfig {
    int sda_gpio = 21;
    int scl_gpio = 22;
    std::uint8_t address = 0x3C;
    OledController controller = OledController::Ssd1306;
    bool rotate_180 = false;
};

// 128x64 I2C OLED. Only ever touched from the display task.
class Oled {
public:
    // Fails with ESP_ERR_NOT_FOUND when nothing answers at the address, so
    // a missing screen is reported instead of hanging.
    esp_err_t begin(const OledConfig& config);
    esp_err_t show(const display::Framebuffer& fb);
    bool ready() const { return device_ != nullptr; }

private:
    esp_err_t command(const std::uint8_t* bytes, std::size_t length);

    OledConfig config_{};
    i2c_master_bus_t* bus_ = nullptr;
    i2c_master_dev_t* device_ = nullptr;
};

} // namespace inapparency::platform
