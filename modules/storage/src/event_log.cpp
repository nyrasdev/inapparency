#include "inapparency/storage/event_log.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>

#if defined(__unix__) || defined(__APPLE__) || defined(ESP_PLATFORM)
#include <sys/stat.h>
#include <unistd.h>
#define INAPPARENCY_HAVE_POSIX 1
#endif

namespace inapparency::storage {

bool StdioFileSystem::append(const char* path, const char* data, std::size_t length) {
    std::FILE* f = std::fopen(path, "a");
    if (f == nullptr) {
        return false;
    }
    bool ok = std::fwrite(data, 1, length, f) == length;
    ok = std::fflush(f) == 0 && ok;
#if INAPPARENCY_HAVE_POSIX
    ok = fsync(fileno(f)) == 0 && ok;
#endif
    ok = std::fclose(f) == 0 && ok;
    return ok;
}

std::optional<std::size_t> StdioFileSystem::size(const char* path) {
#if INAPPARENCY_HAVE_POSIX
    struct stat st {};
    if (stat(path, &st) != 0) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(st.st_size);
#else
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return std::nullopt;
    }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fclose(f);
    return n < 0 ? std::nullopt : std::optional<std::size_t>(static_cast<std::size_t>(n));
#endif
}

bool StdioFileSystem::rename(const char* from, const char* to) {
    return std::rename(from, to) == 0;
}

bool StdioFileSystem::remove(const char* path) {
    return std::remove(path) == 0;
}

bool EventLogConfig::valid() const {
    return directory != nullptr && name != nullptr && name[0] != '\0' && std::strlen(name) <= 7 &&
           std::strlen(directory) <= 40 && max_bytes >= 1024 && keep <= 9;
}

EventLog::EventLog(FileSystem& fs, const EventLogConfig& config) : fs_(fs), config_(config) {
    if (!config_.valid()) {
        config_ = EventLogConfig{};
        config_rejected_ = true;
    }
}

void EventLog::path(std::uint8_t index, char* out, std::size_t capacity) const {
    if (index == 0) {
        std::snprintf(out, capacity, "%s/%s.log", config_.directory, config_.name);
    } else {
        std::snprintf(out, capacity, "%s/%s%u.log", config_.directory, config_.name,
                      static_cast<unsigned>(index));
    }
}

void EventLog::rotate() {
    char from[64];
    char to[64];
    if (config_.keep == 0) {
        path(0, from, sizeof from);
        fs_.remove(from);
    } else {
        path(config_.keep, to, sizeof to);
        fs_.remove(to); // may not exist, that's fine
        for (std::uint8_t i = config_.keep; i > 0; --i) {
            path(static_cast<std::uint8_t>(i - 1), from, sizeof from);
            path(i, to, sizeof to);
            fs_.rename(from, to);
        }
    }
    current_size_ = 0;
    ++stats_.rotations;
}

bool EventLog::write_line(const char* line, std::size_t length) {
    char current[64];
    path(0, current, sizeof current);
    if (!current_size_) {
        current_size_ = fs_.size(current).value_or(0);
    }
    if (*current_size_ > 0 && *current_size_ + length > config_.max_bytes) {
        rotate();
    }
    if (!fs_.append(current, line, length)) {
        ++stats_.failures;
        current_size_.reset(); // re-check the size next time
        return false;
    }
    *current_size_ += length;
    ++stats_.lines;
    stats_.bytes += length;
    return true;
}

bool EventLog::write_event(const DetectionEvent& event) {
    char line[512];
    std::size_t n = serial::format_event(event, serial::Format::Json, line, sizeof line);
    return write_line(line, n);
}

bool EventLog::write_status(const serial::Status& status) {
    char line[512];
    std::size_t n = serial::format_status(status, serial::Format::Json, line, sizeof line);
    return write_line(line, n);
}

bool EventLog::write_boot(std::uint32_t boot_count, const char* version, const char* target) {
    char line[160];
    int n = std::snprintf(line, sizeof line,
                          "{\"type\":\"boot\",\"boot\":%" PRIu32
                          ",\"version\":\"%s\",\"target\":\"%s\"}\n",
                          boot_count, version, target);
    if (n <= 0) {
        return false;
    }
    return write_line(line, static_cast<std::size_t>(n) < sizeof line ? static_cast<std::size_t>(n)
                                                                      : sizeof line - 1);
}

} // namespace inapparency::storage
