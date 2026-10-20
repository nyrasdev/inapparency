#pragma once

#include "inapparency/frame.hpp"
#include "inapparency/observation.hpp"

namespace inapparency {

enum class ParseStatus : std::uint8_t {
    Ok,
    Empty,       // no bytes at all
    Truncated,   // header or required fixed fields cut off
    BadVersion,  // protocol version is not 0
    Unsupported, // valid as far as we checked, but not a frame we parse yet
};

const char* to_string(ParseStatus status);

struct ParseResult {
    ParseStatus status = ParseStatus::Empty;
    ParsedFrame frame;

    // original_length said the frame was longer than what was captured.
    bool capture_truncated = false;

    bool ok() const { return status == ParseStatus::Ok; }
};

// Parses an 802.11 frame. Never reads outside observation.bytes, never
// allocates, and never treats an unknown frame as suspicious on its own.
//
// Right now only management frames are parsed past the frame control field.
// Control, data and extension frames come back as Unsupported with the frame
// control decoded, so they can still be counted.
ParseResult parse_frame(const Observation& observation);

} // namespace inapparency
