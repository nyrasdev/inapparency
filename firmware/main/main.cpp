#include <array>
#include <atomic>
#include <cstdio>
#include <type_traits>

#include "esp_chip_info.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "inapparency/channel_hopper.hpp"
#include "inapparency/correlator.hpp"
#include "inapparency/default_rules.hpp"
#include "inapparency/detector.hpp"
#include "inapparency/display/screens.hpp"
#include "inapparency/event_gate.hpp"
#include "inapparency/fanout.hpp"
#include "inapparency/platform/capture.hpp"
#include "inapparency/serial/format.hpp"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#if CONFIG_INAPPARENCY_DISPLAY
#include "inapparency/platform/oled.hpp"
#endif
#if CONFIG_INAPPARENCY_STORAGE
#include "inapparency/platform/sdcard.hpp"
#include "inapparency/storage/event_log.hpp"
#endif

namespace {

using namespace inapparency;

constexpr const char* kVersion = "0.1.0";

#if CONFIG_INAPPARENCY_OUTPUT_JSON
constexpr serial::Format kFormat = serial::Format::Json;
#else
constexpr serial::Format kFormat = serial::Format::Text;
#endif

#if CONFIG_INAPPARENCY_FIXED_CHANNEL != 0
constexpr bool kHopping = false;
#else
constexpr bool kHopping = true;
#endif

// Everything lives in static storage: no heap use after boot (apart from
// the SD card driver, which allocates once when the card is mounted).
platform::FrameRing g_ring;
Detector g_detector;
DefaultRules g_rules;
ChannelHopper g_hopper;
std::atomic<std::uint8_t> g_channel{0};
std::uint32_t g_boot_count = 0;

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(esp_timer_get_time()) / 1000U;
}

// ---------------------------------------------------------------------------
// Shared snapshot. The detection task writes it, the display and storage
// tasks read copies of it. Only small copies happen under the lock.

struct Snapshot {
    display::StatusView view;
    DetectorStats stats;
    std::uint32_t queue_peak = 0;
};

portMUX_TYPE g_snapshot_lock = portMUX_INITIALIZER_UNLOCKED;
Snapshot g_snapshot;
std::atomic<bool> g_storage_ok{false};

Snapshot read_snapshot() {
    portENTER_CRITICAL(&g_snapshot_lock);
    Snapshot copy = g_snapshot;
    portEXIT_CRITICAL(&g_snapshot_lock);
    return copy;
}

// ---------------------------------------------------------------------------
// Event outputs: detector -> correlator -> gate -> fanout -> outputs

class SerialSink final : public EventSink {
public:
    void emit(const DetectionEvent& event) override {
        char line[384];
        serial::format_event(event, kFormat, line, sizeof line);
        std::fputs(line, stdout);
    }
};

// Remembers the latest alert for the screen.
class SnapshotSink final : public EventSink {
public:
    void emit(const DetectionEvent& event) override {
        display::LastAlert alert;
        alert.severity = event.severity;
        alert.rule = event.rule_name;
        alert.confidence = event.confidence;
        alert.bssid = event.bssid;
        alert.at_ms = event.timestamp_ms;
        portENTER_CRITICAL(&g_snapshot_lock);
        // A lower-severity alert doesn't push a fresh high one off the screen.
        auto& last = g_snapshot.view.last_alert;
        const bool keep_old = last && last->severity > alert.severity &&
                              alert.at_ms - last->at_ms < display::kHighlightMs;
        if (!keep_old) {
            last = alert;
        }
        ++g_snapshot.view.alerts;
        portEXIT_CRITICAL(&g_snapshot_lock);
    }
};

SerialSink g_serial;
SnapshotSink g_snapshot_sink;
EventFanout g_fanout;
EventGate g_gate(g_fanout);
Correlator g_correlator(g_gate);

#if CONFIG_INAPPARENCY_STORAGE
static_assert(std::is_trivially_copyable_v<DetectionEvent>,
              "events are copied through a FreeRTOS queue");

constexpr UBaseType_t kStorageQueueLength = 16;
StaticQueue_t g_storage_queue_buffer;
std::uint8_t g_storage_queue_storage[kStorageQueueLength * sizeof(DetectionEvent)];
QueueHandle_t g_storage_queue = nullptr;
std::atomic<std::uint32_t> g_storage_dropped{0};

// Never waits: if the SD card is slow and the queue is full, the event is
// counted and dropped from the log (it was still printed on serial).
class StorageSink final : public EventSink {
public:
    void emit(const DetectionEvent& event) override {
        if (!g_storage_ok.load() || xQueueSend(g_storage_queue, &event, 0) != pdTRUE) {
            g_storage_dropped.fetch_add(1);
        }
    }
};
StorageSink g_storage_sink;
#endif

// ---------------------------------------------------------------------------

serial::Status make_status(const Snapshot& s) {
    serial::Status status;
    status.uptime_ms = s.view.uptime_ms;
    status.stats = &s.stats;
    status.dropped = s.view.dropped;
    status.queue_high_water = s.queue_peak;
    status.channel = s.view.channel;
    status.free_heap = esp_get_free_heap_size();
    status.min_free_heap = esp_get_minimum_free_heap_size();
    status.suppressed = s.view.suppressed;
    return status;
}

void publish_snapshot() {
    const std::uint8_t ch = g_channel.load();
    portENTER_CRITICAL(&g_snapshot_lock);
    g_snapshot.stats = g_detector.stats();
    g_snapshot.queue_peak = g_ring.high_water();
    auto& v = g_snapshot.view;
    v.uptime_ms = now_ms();
    v.frames = g_snapshot.stats.observations;
    v.suppressed = g_gate.stats().suppressed();
    v.dropped = g_ring.dropped();
    v.channel = ch != 0 ? std::optional<std::uint8_t>(ch) : std::nullopt;
    v.hopping = kHopping;
    v.storage_ok = g_storage_ok.load();
    portEXIT_CRITICAL(&g_snapshot_lock);
}

void print_status() {
    Snapshot s = read_snapshot();
    serial::Status status = make_status(s);
    status.stack_free = static_cast<std::uint32_t>(uxTaskGetStackHighWaterMark(nullptr)) *
                        static_cast<std::uint32_t>(sizeof(StackType_t));
    char line[384];
    serial::format_status(status, kFormat, line, sizeof line);
    std::fputs(line, stdout);
}

// Pulls frames off the ring and runs detection. The only task that touches
// the detector, so it needs no locking.
void processing_task(void*) {
    const std::uint64_t status_every = CONFIG_INAPPARENCY_STATUS_INTERVAL_S * 1000ULL;
    std::uint64_t next_status = now_ms() + status_every;
    std::uint64_t next_publish = 0;

    for (;;) {
        Observation observation;
        int handled = 0;
        while (handled < 64 && g_ring.front(observation)) {
            g_detector.process(observation, g_correlator);
            g_ring.release();
            ++handled;
        }

        const std::uint64_t now = now_ms();
        if (now >= next_publish) {
            publish_snapshot();
            next_publish = now + 250;
        }
        if (status_every > 0 && now >= next_status) {
            print_status();
            next_status += status_every;
        }
        if (handled == 0) {
            vTaskDelay(pdMS_TO_TICKS(5));
        }
    }
}

#if CONFIG_INAPPARENCY_DISPLAY
platform::Oled g_oled;
display::Framebuffer g_framebuffer;

void display_task(void*) {
    display::render_splash(g_framebuffer, kVersion);
    g_oled.show(g_framebuffer);
    vTaskDelay(pdMS_TO_TICKS(2000));

    std::uint32_t failures = 0;
    for (;;) {
        Snapshot s = read_snapshot();
        display::render_status(g_framebuffer, s.view);
        if (g_oled.show(g_framebuffer) != ESP_OK && ++failures == 10) {
            std::printf("warning: display stopped responding, still monitoring\n");
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

void start_display() {
    platform::OledConfig config;
    config.sda_gpio = CONFIG_INAPPARENCY_DISPLAY_SDA;
    config.scl_gpio = CONFIG_INAPPARENCY_DISPLAY_SCL;
    config.address = CONFIG_INAPPARENCY_DISPLAY_ADDRESS;
#if CONFIG_INAPPARENCY_DISPLAY_SH1106
    config.controller = platform::OledController::Sh1106;
#endif
#if CONFIG_INAPPARENCY_DISPLAY_ROTATE
    config.rotate_180 = true;
#endif
    esp_err_t err = g_oled.begin(config);
    if (err != ESP_OK) {
        std::printf("display: not found on SDA %d / SCL %d at 0x%02x (%s), continuing without it\n",
                    config.sda_gpio, config.scl_gpio, config.address, esp_err_to_name(err));
        return;
    }
    g_fanout.add(g_snapshot_sink);
    if (xTaskCreate(display_task, "display", 3072, nullptr, 2, nullptr) != pdPASS) {
        std::printf("display: could not start its task, continuing without it\n");
        return;
    }
    std::printf("display: on\n");
}
#endif

#if CONFIG_INAPPARENCY_STORAGE
storage::StdioFileSystem g_fs;

void storage_task(void*) {
    platform::SdCardConfig config;
    config.mosi_gpio = CONFIG_INAPPARENCY_SD_MOSI;
    config.miso_gpio = CONFIG_INAPPARENCY_SD_MISO;
    config.sck_gpio = CONFIG_INAPPARENCY_SD_SCK;
    config.cs_gpio = CONFIG_INAPPARENCY_SD_CS;
    esp_err_t err = platform::mount_sd_card(config);
    if (err != ESP_OK) {
        std::printf("storage: no usable SD card (%s), alerts only go to serial\n",
                    esp_err_to_name(err));
        vTaskDelete(nullptr);
        return;
    }

    storage::EventLogConfig log_config;
    log_config.directory = platform::kSdMountPoint;
    log_config.max_bytes = CONFIG_INAPPARENCY_LOG_MAX_KB * 1024U;
    log_config.keep = CONFIG_INAPPARENCY_LOG_KEEP;
    static storage::EventLog log(g_fs, log_config);

    const bool ok = log.write_boot(g_boot_count, kVersion, CONFIG_IDF_TARGET);
    g_storage_ok.store(ok);
    std::printf("storage: %s/inapp.log%s\n", platform::kSdMountPoint,
                ok ? "" : " (write failed, check the card)");

    const std::uint64_t status_every = CONFIG_INAPPARENCY_LOG_STATUS_INTERVAL_S * 1000ULL;
    std::uint64_t next_status = now_ms() + status_every;
    std::uint32_t failures_reported = 0;

    for (;;) {
        DetectionEvent event;
        if (xQueueReceive(g_storage_queue, &event, pdMS_TO_TICKS(1000)) == pdTRUE) {
            log.write_event(event);
        }
        if (status_every > 0 && now_ms() >= next_status) {
            Snapshot s = read_snapshot();
            log.write_status(make_status(s));
            next_status += status_every;
        }
        // Keep trying after a failure (the card may come back), but tell
        // the screen and serial once.
        const bool healthy = log.stats().failures == failures_reported;
        if (!healthy) {
            failures_reported = log.stats().failures;
            std::printf("storage: write failed (%lu so far)\n",
                        static_cast<unsigned long>(failures_reported));
        }
        g_storage_ok.store(healthy);
    }
}

void start_storage() {
    g_storage_queue = xQueueCreateStatic(kStorageQueueLength, sizeof(DetectionEvent),
                                         g_storage_queue_storage, &g_storage_queue_buffer);
    g_fanout.add(g_storage_sink);
    portENTER_CRITICAL(&g_snapshot_lock);
    g_snapshot.view.storage_enabled = true;
    portEXIT_CRITICAL(&g_snapshot_lock);
    if (xTaskCreate(storage_task, "storage", 4096, nullptr, 1, nullptr) != pdPASS) {
        std::printf("storage: could not start its task, continuing without it\n");
    }
}
#endif

// ---------------------------------------------------------------------------

std::uint32_t next_boot_count() {
    nvs_handle_t nvs;
    if (nvs_open("inapparency", NVS_READWRITE, &nvs) != ESP_OK) {
        return 0;
    }
    std::uint32_t count = 0;
    nvs_get_u32(nvs, "boots", &count);
    ++count;
    nvs_set_u32(nvs, "boots", count);
    nvs_commit(nvs);
    nvs_close(nvs);
    return count;
}

void print_banner() {
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    std::printf("\n  %s  inapparency %s\n\n", display::kLogo, kVersion);
    std::printf("target %s rev %u | %u core(s) | esp-idf %s | boot #%lu\n", CONFIG_IDF_TARGET,
                static_cast<unsigned>(chip.revision), static_cast<unsigned>(chip.cores),
                esp_get_idf_version(), static_cast<unsigned long>(g_boot_count));
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
    // Each hopped channel is heard 1/N of the time. Rules use this to scale
    // their thresholds instead of missing bursts.
    auto coverage = static_cast<std::uint8_t>(100 / *count);
    for (std::size_t i = 0; i < *count; ++i) {
        g_detector.set_channel_coverage(list[i], coverage);
    }
    std::printf("channel: hopping %s every %d ms (%u%% coverage each)\n",
                CONFIG_INAPPARENCY_HOP_CHANNELS, CONFIG_INAPPARENCY_HOP_DWELL_MS,
                static_cast<unsigned>(coverage));
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
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        halt("nvs init failed", err);
    }
    g_boot_count = next_boot_count();
    print_banner();

    if (!g_rules.attach(g_detector)) {
        halt("too many rules for the detector", ESP_ERR_NO_MEM);
    }
    std::printf("rules: %s, %s, %s, %s, %s + attack-chain\n", g_rules.deauth_burst.info().name,
                g_rules.malformed_frames.info().name, g_rules.ap_change.info().name,
                g_rules.evil_twin.info().name, g_rules.auth_flood.info().name);

    if (!configure_hopper()) {
        halt("channel config", ESP_ERR_INVALID_ARG);
    }

    // Outputs first, so nothing detected early gets lost. Optional modules
    // that fail to start are skipped; detection never depends on them.
    g_fanout.add(g_serial);
#if CONFIG_INAPPARENCY_DISPLAY
    start_display();
#endif
#if CONFIG_INAPPARENCY_STORAGE
    start_storage();
#endif

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
