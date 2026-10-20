#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "inapparency/event.hpp"
#include "inapparency/serial/format.hpp"

namespace inapparency::storage {

// The few file operations the log needs. Small enough to fake in tests and
// to put on top of anything (SD card, flash, a laptop's disk).
class FileSystem {
public:
    virtual ~FileSystem() = default;
    virtual bool append(const char* path, const char* data, std::size_t length) = 0;
    virtual std::optional<std::size_t> size(const char* path) = 0;
    virtual bool rename(const char* from, const char* to) = 0;
    virtual bool remove(const char* path) = 0;
};

// Plain stdio. Works on a laptop and on ESP-IDF once the SD card is mounted
// through VFS. Each append opens, writes, syncs and closes, so a power cut
// loses at most the line being written.
class StdioFileSystem final : public FileSystem {
public:
    bool append(const char* path, const char* data, std::size_t length) override;
    std::optional<std::size_t> size(const char* path) override;
    bool rename(const char* from, const char* to) override;
    bool remove(const char* path) override;
};

struct EventLogConfig {
    // Folder the files go in, e.g. "/sdcard". No trailing slash.
    const char* directory = ".";
    // Files are <name>.log, <name>1.log, <name>2.log... Kept short so they
    // fit FAT 8.3 names without long file name support.
    const char* name = "inapp";
    std::size_t max_bytes = 512 * 1024;
    // Older files kept besides the current one (0-9).
    std::uint8_t keep = 2;

    bool valid() const;
};

struct EventLogStats {
    std::uint64_t lines = 0;
    std::uint64_t bytes = 0;
    std::uint32_t rotations = 0;
    std::uint32_t failures = 0;
};

// Appends JSON lines (the same format as the serial JSON output) to a file
// and rotates it before it grows past max_bytes.
//
// Timestamps are uptime, not wall clock: boards have no real-time clock.
// A "boot" line marks each start so lines from different runs can be told
// apart.
class EventLog {
public:
    // An invalid config falls back to the defaults; check config_rejected().
    EventLog(FileSystem& fs, const EventLogConfig& config = {});

    bool write_boot(std::uint32_t boot_count, const char* version, const char* target);
    bool write_event(const DetectionEvent& event);
    bool write_status(const serial::Status& status);
    // `line` must end in '\n'.
    bool write_line(const char* line, std::size_t length);

    const EventLogStats& stats() const { return stats_; }
    bool config_rejected() const { return config_rejected_; }
    // Path of the current file, or of older file n (1 = newest old one).
    void path(std::uint8_t index, char* out, std::size_t capacity) const;

private:
    void rotate();

    FileSystem& fs_;
    EventLogConfig config_;
    bool config_rejected_ = false;
    std::optional<std::size_t> current_size_;
    EventLogStats stats_;
};

} // namespace inapparency::storage
