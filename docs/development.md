# Development

## Requirements

- CMake 3.20+
- A C++20 compiler (GCC 12+ or Clang 15+)
- clang-format 18 for formatting

No ESP32 hardware is needed for anything in the repo yet.

## Build options

| Option | Default | What it does |
|---|---|---|
| `INAPPARENCY_BUILD_TESTS` | on when top-level | builds `inapparency_tests` |
| `INAPPARENCY_WERROR` | off | warnings become errors (CI turns it on) |
| `INAPPARENCY_SANITIZE` | off | AddressSanitizer + UBSan |

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

## Formatting

```sh
find core tests -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i
```

## Core rules

- No SDK or board code in `core/`.
- No allocation in the parse path. The parser only borrows the frame bytes.
- Every length from a frame gets checked before it's used.
- Missing metadata stays `std::nullopt`, never a made-up default.
