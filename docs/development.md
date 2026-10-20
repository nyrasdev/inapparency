# Development

## Requirements

- CMake 3.20+
- A C++20 compiler (GCC 12+ or Clang 15+)
- clang-format 18 for formatting

No ESP32 hardware is needed. The firmware needs ESP-IDF v5.4 to build
([firmware.md](firmware.md)), everything else just needs CMake.

## Build options

| Option | Default | What it does |
|---|---|---|
| `INAPPARENCY_BUILD_TESTS` | on when top-level | builds `inapparency_tests` |
| `INAPPARENCY_WERROR` | off | warnings become errors (CI turns it on) |
| `INAPPARENCY_SANITIZE` | off | AddressSanitizer + UBSan |
| `INAPPARENCY_BUILD_TOOLS` | on when top-level | builds `inapparency-replay` |

## Tests

```sh
cmake -S . -B build && cmake --build build -j
./build/tests/inapparency_tests          # everything
./build/tests/inapparency_tests rsn      # only tests whose name contains "rsn"
```

Tests use a tiny built-in harness (`tests/support/check.hpp`) so there are no
outside dependencies. Frames are made with `tests/support/frame_builder.hpp`.
They're synthetic byte buffers and never touch a real radio.

When adding a parser or detection feature, add both the case that should
trigger and the ordinary case that shouldn't.

`ctest` also runs `replay_demo`: it generates the demo capture, replays it
and checks that exactly the expected alerts come out.

## Replaying captures

```sh
./build/tools/replay/inapparency-replay capture.pcap          # text
./build/tools/replay/inapparency-replay --json capture.pcap   # JSON lines
```

Reads classic `.pcap` with radiotap (linktype 127) or plain 802.11
(linktype 105). For pcapng, re-save as pcap in Wireshark first.

## Formatting

```sh
find core modules platform tools tests firmware -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i
```

## Core rules

- No SDK or board code in `core/`.
- No allocation in the parse path. The parser only borrows the frame bytes.
- Every length from a frame gets checked before it's used.
- Missing metadata stays `std::nullopt`, never a made-up default.
