#include "inapparency/serial/format.hpp"

#include <cinttypes>
#include <cstdarg>
#include <cstdio>

namespace inapparency::serial {
namespace {

// Appends printf-style text into a fixed buffer and remembers if it ran out.
class Writer {
public:
    Writer(char* out, std::size_t capacity) : out_(out), capacity_(capacity) {
        if (capacity_ > 0) {
            out_[0] = '\0';
        }
    }

#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    void
    add(const char* fmt, ...) {
        if (capacity_ == 0 || length_ + 1 >= capacity_) {
            return;
        }
        va_list args;
        va_start(args, fmt);
        int n = std::vsnprintf(out_ + length_, capacity_ - length_, fmt, args);
        va_end(args);
        if (n < 0) {
            return;
        }
        std::size_t room = capacity_ - length_ - 1;
        length_ += static_cast<std::size_t>(n) < room ? static_cast<std::size_t>(n) : room;
    }

    void json_string(const char* text) {
        add("\"");
        for (const char* p = text; *p != '\0'; ++p) {
            char c = *p;
            if (c == '"' || c == '\\') {
                add("\\%c", c);
            } else if (static_cast<unsigned char>(c) < 0x20) {
                add("\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
            } else {
                add("%c", c);
            }
        }
        add("\"");
    }

    // Makes sure the line ends with a newline even if it was cut.
    std::size_t finish() {
        if (capacity_ == 0) {
            return 0;
        }
        if (capacity_ == 1) {
            out_[0] = '\0';
            return 0;
        }
        if (length_ + 1 >= capacity_) {
            length_ = capacity_ - 2;
        }
        out_[length_++] = '\n';
        out_[length_] = '\0';
        return length_;
    }

private:
    char* out_;
    std::size_t capacity_;
    std::size_t length_ = 0;
};

const char* upper(Severity severity) {
    switch (severity) {
    case Severity::Info:
        return "INFO";
    case Severity::Low:
        return "LOW";
    case Severity::Medium:
        return "MEDIUM";
    case Severity::High:
        return "HIGH";
    case Severity::Critical:
        return "CRITICAL";
    }
    return "?";
}

void seconds(Writer& w, std::uint64_t ms) {
    w.add("%" PRIu64 ".%03u", ms / 1000, static_cast<unsigned>(ms % 1000));
}

} // namespace

std::size_t format_event(const DetectionEvent& event, Format format, char* out,
                         std::size_t capacity) {
    Writer w(out, capacity);

    if (format == Format::Text) {
        w.add("[");
        seconds(w, event.timestamp_ms);
        w.add("] %s %s confidence=%u evidence=%" PRIu32 "/%" PRIu32 "ms", upper(event.severity),
              event.rule_name, static_cast<unsigned>(event.confidence), event.evidence_count,
              event.window_ms);
        if (event.bssid) {
            w.add(" bssid=%s", event.bssid->to_string().data());
        }
        if (event.source && event.source != event.bssid) {
            w.add(" src=%s", event.source->to_string().data());
        }
        if (event.related_bssid) {
            w.add(" related=%s", event.related_bssid->to_string().data());
        }
        if (event.channel) {
            w.add(" ch=%u", static_cast<unsigned>(*event.channel));
        }
        if (event.coverage_percent) {
            w.add(" coverage=%u%%", static_cast<unsigned>(*event.coverage_percent));
        }
        w.add(" | %s", event.explanation);
        return w.finish();
    }

    w.add("{\"type\":\"event\",\"t_ms\":%" PRIu64 ",\"rule\":", event.timestamp_ms);
    w.json_string(event.rule_name);
    w.add(",\"rule_id\":%" PRIu32 ",\"severity\":\"%s\",\"confidence\":%u", event.rule_id,
          to_string(event.severity), static_cast<unsigned>(event.confidence));
    w.add(",\"evidence\":%" PRIu32 ",\"window_ms\":%" PRIu32, event.evidence_count,
          event.window_ms);
    if (event.bssid) {
        w.add(",\"bssid\":\"%s\"", event.bssid->to_string().data());
    }
    if (event.source) {
        w.add(",\"source\":\"%s\"", event.source->to_string().data());
    }
    if (event.related_bssid) {
        w.add(",\"related_bssid\":\"%s\"", event.related_bssid->to_string().data());
    }
    if (event.channel) {
        w.add(",\"channel\":%u", static_cast<unsigned>(*event.channel));
    }
    if (event.coverage_percent) {
        w.add(",\"coverage\":%u", static_cast<unsigned>(*event.coverage_percent));
    }
    w.add(",\"why\":");
    w.json_string(event.explanation);
    w.add("}");
    return w.finish();
}

std::size_t format_status(const Status& status, Format format, char* out, std::size_t capacity) {
    Writer w(out, capacity);
    DetectorStats empty;
    const DetectorStats& s = status.stats != nullptr ? *status.stats : empty;

    if (format == Format::Text) {
        w.add("[");
        seconds(w, status.uptime_ms);
        w.add("] status frames=%" PRIu64 " ok=%" PRIu64 " unsupported=%" PRIu64
              " truncated=%" PRIu64 " bad_version=%" PRIu64 " events=%" PRIu64 " dropped=%" PRIu32
              " queue_peak=%" PRIu32,
              s.observations, s.ok, s.unsupported, s.truncated, s.bad_version, s.events,
              status.dropped, status.queue_high_water);
        if (status.channel) {
            w.add(" ch=%u", static_cast<unsigned>(*status.channel));
        }
        if (status.free_heap) {
            w.add(" heap=%" PRIu32, *status.free_heap);
        }
        if (status.min_free_heap) {
            w.add(" heap_min=%" PRIu32, *status.min_free_heap);
        }
        if (status.stack_free) {
            w.add(" stack_free=%" PRIu32, *status.stack_free);
        }
        if (status.suppressed) {
            w.add(" suppressed=%" PRIu64, *status.suppressed);
        }
        return w.finish();
    }

    w.add("{\"type\":\"status\",\"uptime_ms\":%" PRIu64 ",\"frames\":%" PRIu64 ",\"ok\":%" PRIu64
          ",\"unsupported\":%" PRIu64 ",\"truncated\":%" PRIu64 ",\"bad_version\":%" PRIu64
          ",\"capture_truncated\":%" PRIu64 ",\"events\":%" PRIu64 ",\"dropped\":%" PRIu32
          ",\"queue_peak\":%" PRIu32,
          status.uptime_ms, s.observations, s.ok, s.unsupported, s.truncated, s.bad_version,
          s.capture_truncated, s.events, status.dropped, status.queue_high_water);
    if (status.channel) {
        w.add(",\"channel\":%u", static_cast<unsigned>(*status.channel));
    }
    if (status.free_heap) {
        w.add(",\"free_heap\":%" PRIu32, *status.free_heap);
    }
    if (status.min_free_heap) {
        w.add(",\"min_free_heap\":%" PRIu32, *status.min_free_heap);
    }
    if (status.stack_free) {
        w.add(",\"stack_free\":%" PRIu32, *status.stack_free);
    }
    if (status.suppressed) {
        w.add(",\"suppressed\":%" PRIu64, *status.suppressed);
    }
    w.add("}");
    return w.finish();
}

} // namespace inapparency::serial
