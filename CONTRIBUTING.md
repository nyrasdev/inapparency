# Contributing

Thanks for wanting to help. Bug reports, hardware test results, new rules
and doc fixes are all welcome.

## The most useful thing right now

**Run it on your board and report back**, especially on an ESP32-S3, C3 or
C6. Use the
[hardware report](https://github.com/nyrasdev/inapparency/issues/new?template=hardware_report.yml)
template, even if everything just worked. See
[supported hardware](docs/supported-hardware.md) for the current list.

## Setting up

```sh
git clone https://github.com/nyrasdev/inapparency
cd inapparency
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DINAPPARENCY_WERROR=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

No board needed for any of that. To build the firmware you need ESP-IDF
v5.4, see [docs/firmware.md](docs/firmware.md).

## Before opening a pull request

- `ctest` passes, ideally with `-DINAPPARENCY_SANITIZE=ON` too
- Code is formatted:
  ```sh
  find core modules platform tools tests firmware -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i
  ```
- New behavior has tests: the case that should trigger **and** the ordinary
  traffic that shouldn't
- Docs are updated if behavior or settings changed
- One topic per pull request. Small ones get reviewed faster.

CI runs all of this, plus firmware builds for every chip.

## Ground rules for the code

- `core/` stays portable: no ESP-IDF, no board code, no I/O.
- No allocation while processing frames. State is fixed size and bounded.
- Never trust a length or field from a frame before checking it.
- Missing information stays missing (`std::nullopt`), never a made-up
  default.
- Hardware drivers go in `platform/`. Anything testable on a laptop goes in
  `core/` or `modules/` with tests.

## Adding a detection rule

Read [docs/detection-rules.md](docs/detection-rules.md) first. A new rule
needs:

1. A stable id that's never reused
2. Fixed-size state (`RollingCounter`, `MacTable`)
3. A config struct with `valid()` that falls back to defaults
4. Severity and confidence kept separate, with confidence capped at 95
5. An explanation string a non-expert can understand
6. Tests for what it catches **and** for realistic traffic it must ignore
7. A section in `detection-rules.md`, including known false positives

In the pull request, explain what evidence the rule uses, what it assumes,
and how you checked it.

## What won't be merged

inapparency is a passive, defensive monitor. Pull requests that add
transmitting (deauth, beacon spam, injection), credential capture, password
cracking, or anything meant to attack networks will be closed, however
they're framed. Test data has to be synthetic or captured on networks you're
allowed to capture.

## License

By contributing you agree your work is released under the
[MIT License](LICENSE).
