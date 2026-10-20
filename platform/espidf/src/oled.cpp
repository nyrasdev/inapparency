#include "inapparency/platform/oled.hpp"

#include <array>
#include <cstring>

#include "driver/i2c_master.h"

namespace inapparency::platform {
namespace {

constexpr int kTimeoutMs = 50;
constexpr std::uint8_t kCommandPrefix = 0x00;
constexpr std::uint8_t kDataPrefix = 0x40;
constexpr std::uint8_t kSh1106ColumnOffset = 2; // its RAM is 132 columns wide

} // namespace

esp_err_t Oled::command(const std::uint8_t* bytes, std::size_t length) {
    std::array<std::uint8_t, 32> buffer{};
    if (length + 1 > buffer.size()) {
        return ESP_ERR_INVALID_SIZE;
    }
    buffer[0] = kCommandPrefix;
    std::memcpy(buffer.data() + 1, bytes, length);
    return i2c_master_transmit(device_, buffer.data(), length + 1, kTimeoutMs);
}

esp_err_t Oled::begin(const OledConfig& config) {
    config_ = config;

    i2c_master_bus_config_t bus_config = {};
    bus_config.i2c_port = -1; // any free port
    bus_config.sda_io_num = static_cast<gpio_num_t>(config.sda_gpio);
    bus_config.scl_io_num = static_cast<gpio_num_t>(config.scl_gpio);
    bus_config.clk_source = I2C_CLK_SRC_DEFAULT;
    bus_config.glitch_ignore_cnt = 7;
    // Most modules have their own pull-ups; the internal ones help when not.
    bus_config.flags.enable_internal_pullup = 1;
    esp_err_t err = i2c_new_master_bus(&bus_config, &bus_);
    if (err != ESP_OK) {
        return err;
    }

    if (i2c_master_probe(bus_, config.address, kTimeoutMs) != ESP_OK) {
        i2c_del_master_bus(bus_);
        bus_ = nullptr;
        return ESP_ERR_NOT_FOUND;
    }

    i2c_device_config_t device_config = {};
    device_config.dev_addr_length = I2C_ADDR_BIT_LEN_7;
    device_config.device_address = config.address;
    device_config.scl_speed_hz = 400'000;
    err = i2c_master_bus_add_device(bus_, &device_config, &device_);
    if (err != ESP_OK) {
        device_ = nullptr;
        return err;
    }

    const bool sh1106 = config.controller == OledController::Sh1106;
    const std::uint8_t seg_remap = config.rotate_180 ? 0xA0 : 0xA1;
    const std::uint8_t com_scan = config.rotate_180 ? 0xC0 : 0xC8;
    const std::uint8_t init[] = {
        0xAE,            // display off
        0xD5,      0x80, // clock divide
        0xA8,      0x3F, // multiplex: 64 rows
        0xD3,      0x00, // no vertical offset
        0x40,            // start line 0
        0x8D,      0x14, // charge pump on (SSD1306; SH1106 ignores it)
        0x20,      0x00, // horizontal addressing (SSD1306 only)
        seg_remap,       // column order
        com_scan,        // row order
        0xDA,      0x12, // COM pins for 64-row panels
        0x81,      0x8F, // contrast
        0xD9,      0xF1, // pre-charge
        0xDB,      0x40, // VCOMH level
        0xA4,            // show RAM contents
        0xA6,            // not inverted
        0x2E,            // no scrolling
    };
    // SH1106 doesn't know 0x20/0x00; sending it is harmless, but skip it to
    // keep its state predictable.
    std::size_t skip_at = sh1106 ? 10 : sizeof init;
    err = command(init, skip_at);
    if (err == ESP_OK && sh1106) {
        err = command(init + 12, sizeof init - 12);
    }
    if (err != ESP_OK) {
        return err;
    }

    display::Framebuffer blank;
    err = show(blank); // clear the random power-on contents first
    if (err != ESP_OK) {
        return err;
    }
    const std::uint8_t on[] = {0xAF};
    return command(on, sizeof on);
}

esp_err_t Oled::show(const display::Framebuffer& fb) {
    if (device_ == nullptr) {
        return ESP_ERR_INVALID_STATE;
    }
    std::array<std::uint8_t, 1 + display::Framebuffer::kWidth> line{};
    line[0] = kDataPrefix;

    if (config_.controller == OledController::Ssd1306) {
        const std::uint8_t window[] = {0x21, 0x00, 0x7F, 0x22, 0x00, 0x07};
        esp_err_t err = command(window, sizeof window);
        if (err != ESP_OK) {
            return err;
        }
    }
    for (int page = 0; page < 8; ++page) {
        if (config_.controller == OledController::Sh1106) {
            const std::uint8_t position[] = {
                static_cast<std::uint8_t>(0xB0 + page),
                static_cast<std::uint8_t>(0x00 | (kSh1106ColumnOffset & 0x0F)),
                static_cast<std::uint8_t>(0x10 | (kSh1106ColumnOffset >> 4)),
            };
            esp_err_t err = command(position, sizeof position);
            if (err != ESP_OK) {
                return err;
            }
        }
        auto bytes = fb.page(page);
        std::memcpy(line.data() + 1, bytes.data(), bytes.size());
        esp_err_t err = i2c_master_transmit(device_, line.data(), line.size(), kTimeoutMs);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}

} // namespace inapparency::platform
