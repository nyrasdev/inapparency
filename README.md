# inapparency

> make the inapparent apparent.

A headless wireless security monitor for ESP32 boards. It watches 802.11
management traffic, runs it through its own parser and detection rules, and
tells you when something looks off and *why* it thinks so.

It's defensive and passive. It listens, it doesn't transmit.

> [!NOTE]
> Early days. Right now this is the portable core: the frame parser and the
> data types the rest of the system builds on. No detection rules or firmware
> yet. See the [roadmap](#roadmap).

## What works today

- Parses 802.11 management frames: header, addresses, sequence numbers,
  deauth/disassoc reason codes, beacon and probe fields
- Reads SSID, channel and RSN info from beacons, including whether a network
  supports or **requires PMF** (802.11w). That's what tells a forged deauth
  apart from a real one on WPA3 networks.
- Handles truncated, malformed and protected frames without crashing or
  reading out of bounds (tested with every prefix, single-byte mutations and
  ~40k random buffers under ASan/UBSan)
- Builds and tests on any machine with CMake and a C++20 compiler. No board
  needed.

## Build and test

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

With sanitizers:

```sh
cmake -S . -B build-asan -DINAPPARENCY_SANITIZE=ON
cmake --build build-asan -j && ctest --test-dir build-asan
```

More in [docs/development.md](docs/development.md).

## Layout

```
core/      portable C++ core, no hardware or SDK code in here
tests/     host tests and the synthetic frame builder
docs/      architecture notes and known limitations
```

Board adapters (`platform/`) and optional outputs (`modules/`) show up once
there's something real to put in them.

## Roadmap

1. **Foundation**: types, parser, tests, CI ← *here*
2. **Detection MVP**: rolling windows, deauth/disassoc bursts, malformed frames,
   structured events
3. **First ESP32 adapter**: ESP-IDF, promiscuous capture, serial output
4. **Reliability**: dedup, rate limiting, bounded everything
5. **More boards**: S3, C3, C6, and maybe C5 for 5 GHz
6. **Optional modules**: storage, display, export
7. **Smarter detection**: baselines, AP change tracking, correlating rules
8. **Public release**

## Limitations

A single ESP32 radio sees one 2.4 GHz channel at a time and misses what it
can't hear. No alerts doesn't mean a network is safe. Read
[docs/limitations.md](docs/limitations.md) before trusting it with anything.

## Use it responsibly

Only monitor networks you own or have permission to watch. This project
doesn't send forged frames, crack anything or collect credentials, and it
won't.

## License

MIT, see [LICENSE](LICENSE).
