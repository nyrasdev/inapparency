#include "inapparency/platform/capture.hpp"

#include <atomic>

#include "esp_check.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_wifi.h"

namespace inapparency::platform {
namespace {

constexpr const char* kTag = "capture";

FrameRing* g_ring = nullptr;
std::atomic<std::uint32_t> g_received{0};

// Runs in the Wi-Fi driver's task. Keep it short: copy and leave.
void on_frame(void* buffer, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || g_ring == nullptr || buffer == nullptr) {
        return;
    }
    g_received.fetch_add(1, std::memory_order_relaxed);

    const auto* packet = static_cast<const wifi_promiscuous_pkt_t*>(buffer);
    const std::size_t length = packet->rx_ctrl.sig_len;

    CaptureMetadata meta;
    // esp_timer is a 64-bit microsecond clock, unlike rx_ctrl.timestamp
    // which wraps after about 71 minutes.
    meta.timestamp_ms = static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
    meta.channel = static_cast<std::uint8_t>(packet->rx_ctrl.channel);
    meta.rssi_dbm = static_cast<std::int8_t>(packet->rx_ctrl.rssi);
    // ESP-IDF documents sig_len as including the 4-byte FCS.
    meta.original_length = length;
    meta.includes_fcs = true;

    g_ring->push(std::span<const std::uint8_t>(packet->payload, length), meta);
}

} // namespace

esp_err_t start_capture(FrameRing& ring) {
    if (g_ring != nullptr) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&config), kTag, "wifi init failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), kTag, "set storage failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_NULL), kTag, "set mode failed");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), kTag, "wifi start failed");

    wifi_promiscuous_filter_t filter{};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    ESP_RETURN_ON_ERROR(esp_wifi_set_promiscuous_filter(&filter), kTag, "set filter failed");

    g_ring = &ring;
    ESP_RETURN_ON_ERROR(esp_wifi_set_promiscuous_rx_cb(&on_frame), kTag, "set callback failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_promiscuous(true), kTag, "promiscuous on failed");
    return ESP_OK;
}

esp_err_t set_channel(std::uint8_t channel) {
    return esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

std::uint32_t frames_received() {
    return g_received.load(std::memory_order_relaxed);
}

} // namespace inapparency::platform
