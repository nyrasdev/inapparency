#pragma once

// The version comes from the VERSION file at the repo root, passed in by the
// build. Everything (firmware, tools, logs) reads it from here.
#ifndef INAPPARENCY_VERSION
#define INAPPARENCY_VERSION "unknown"
#endif

namespace inapparency {
inline constexpr const char* kVersion = INAPPARENCY_VERSION;
} // namespace inapparency
