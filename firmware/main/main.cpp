#include <array>
#include <atomic>
#include <cstdio>

#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "inapparency/channel_hopper.hpp"
#include "inapparency/detector.hpp"
#include "inapparency/platform/capture.hpp"
#include "inapparency/rules/deauth_burst.hpp"
#include "inapparency/rules/malformed_frames.hpp"
#include "inapparency/serial/format.hpp"
#include "nvs_flash.h"
#include "sdkconfig.h"

namespace {

using namespace inapparency;

constexpr const char* kVersion = "0.1.0";

#if CONFIG_INAPPARENCY_OUTPUT_JSON
constexpr serial::Format kFormat = serial::Format::Json;
#else
constexpr serial::Format kFormat = serial::Format::Text;
#endif

// Everything lives in static storage: no heap use after boot.
platform::FrameRing g_ring;
Detector g_detector;
rules::DeauthBurstRule g_deauth_rule;
rules::MalformedFramesRule g_malformed_rule;
ChannelHopper g_hopper;
std::atomic<std::uint8_t> g_channel{0};

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

class SerialSink final : public EventSink {
public:
    void emit(const DetectionEvent& event) override {
        char line[384];
        serial::format_event(event, kFormat, line, sizeof line);
        std::fputs(line, stdout);
    }
};

void print_status() {
    serial::Status status;
    status.uptime_ms = now_ms();
    status.stats = &g_detector.stats();
    status.dropped = g_ring.dropped();
    status.queue_high_water = g_ring.high_water();
    if (std::uint8_t ch = g_channel.load(); ch != 0) {
        status.channel = ch;
    }
    status.free_heap = esp_get_free_heap_size();
    status.min_free_heap = esp_get_minimum_free_heap_size();

    char line[384];
    serial::format_status(status, kFormat, line, sizeof line);
    std::fputs(line, stdout);
}

// Pulls frames off the ring and runs detection. The only task that touches
// the detector, so it needs no locking.
void processing_task(void*) {
    SerialSink sink;
    const std::uint64_t status_every = CONFIG_INAPPARENCY_STATUS_INTERVAL_S * 1000ULL;
    std::uint64_t next_status = now_ms() + status_every;

    for (;;) {
        Observation observation;
        int handled = 0;
        while (handled < 64 && g_ring.front(observation)) {
            g_detector.process(observation, sink);
            g_ring.release();
            ++handled;
        }

        if (status_every > 0 && now_ms() >= next_status) {
            print_status();
            next_status += status_every;
        }
        if (handled == 0) {
            vTaskDelay(pdMS_TO_TICKS(5));
        }
    }
}

void print_banner() {
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    std::printf("\ninapparency %s | target %s rev %u | %u core(s) | esp-idf %s\n", kVersion,
                CONFIG_IDF_TARGET, static_cast<unsigned>(chip.revision),
                static_cast<unsigned>(chip.cores), esp_get_idf_version());
    std::printf("passive mode: listening only, nothing is transmitted\n");
}

bool configure_hopper() {
#if CONFIG_INAPPARENCY_FIXED_CHANNEL != 0
    g_hopper.lock(CONFIG_INAPPARENCY_FIXED_CHANNEL);
    std::printf("channel: fixed on %d\n", CONFIG_INAPPARENCY_FIXED_CHANNEL);
    return true;
#else
    std::array<std::uint8_t, ChannelHopper::kMaxChannels> list{};
    auto count = parse_channel_list(CONFIG_INAPPARENCY_HOP_CHANNELS, list);
    if (!count || !g_hopper.configure({list.data(), *count}, CONFIG_INAPPARENCY_HOP_DWELL_MS)) {
        std::printf("error: bad channel list \"%s\" (want something like 1,6,11)\n",
                    CONFIG_INAPPARENCY_HOP_CHANNELS);
        return false;
    }
    std::printf("channel: hopping %s every %d ms\n", CONFIG_INAPPARENCY_HOP_CHANNELS,
                CONFIG_INAPPARENCY_HOP_DWELL_MS);
    return true;
#endif
}

[[noreturn]] void halt(const char* why, esp_err_t err) {
    std::printf("error: %s (%s). detection is not running.\n", why, esp_err_to_name(err));
    for (;;) {
        vTaskDelay(portMAX_DELAY);
    }
}

} // namespace

extern "C" void app_main() {
    print_banner();

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        halt("nvs init failed", err);
    }

    g_detector.add_rule(g_deauth_rule);
    g_detector.add_rule(g_malformed_rule);
    std::printf("rules: %s, %s\n", g_deauth_rule.info().name, g_malformed_rule.info().name);

    if (!configure_hopper()) {
        halt("channel config", ESP_ERR_INVALID_ARG);
    }

    err = platform::start_capture(g_ring);
    if (err != ESP_OK) {
        halt("radio capture failed to start", err);
    }

    if (xTaskCreate(processing_task, "detect", 6144, nullptr, 5, nullptr) != pdPASS) {
        halt("could not start detection task", ESP_ERR_NO_MEM);
    }
    std::printf("monitoring started\n");

    // This task only moves the radio between channels.
    for (;;) {
        if (auto channel = g_hopper.poll(now_ms())) {
            if (platform::set_channel(*channel) == ESP_OK) {
                g_channel.store(*channel);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
