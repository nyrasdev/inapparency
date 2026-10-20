# inapparency

> make the inapparent apparent.

A headless wireless security monitor for ESP32 boards. It watches 802.11
management traffic, runs it through its own parser and detection rules, and
tells you when something looks off and *why* it thinks so.

It's defensive and passive. It listens, it doesn't transmit.

> [!NOTE]
> Early days. The detection core works and is tested on synthetic traffic.
> The firmware compiles for ESP32, S3, C3 and C6 but **hasn't run on a real
> board yet**. See [supported hardware](docs/supported-hardware.md).

## What works today

- Parses 802.11 management frames: header, addresses, sequence numbers,
  deauth/disassoc reason codes, beacon and probe fields
- Reads SSID, channel and RSN info from beacons, including whether a network
  supports or **requires PMF** (802.11w). That's what tells a forged deauth
  apart from a real one on WPA3 networks.
- Handles truncated, malformed and protected frames without crashing or
  reading out of bounds (tested with every prefix, single-byte mutations and
  ~40k random buffers under ASan/UBSan)
- **Two detection rules** ([details](docs/detection-rules.md)):
  - `deauth-burst`: deauth/disassoc floods per network, with confidence
    based on PMF, spread and reason codes
  - `malformed-frames`: floods of broken management frames
- Every alert says why it fired, how much evidence there was, and keeps
  severity separate from confidence
- Fixed memory. The whole detector is about 11 KB, with no allocation while
  processing frames.
- **Firmware** for ESP32 / S3 / C3 / C6: passive capture, channel hopping,
  text or JSON output over serial ([docs](docs/firmware.md))
- **Replay tool**: run any monitor-mode `.pcap` through the same detector on
  your laptop
- Builds and tests on any machine with CMake and a C++20 compiler. No board
  needed.

## Try it without a board

```sh
cmake -S . -B build && cmake --build build -j
python3 tools/make_demo_pcap.py demo.pcap
./build/tools/replay/inapparency-replay demo.pcap
```

```
[60.190] HIGH deauth-burst confidence=75 evidence=20/5000ms bssid=02:10:10:10:10:10 ch=6 | Unprotected deauth/disassoc burst on a network that requires PMF. The real access point would protect these, so they are likely forged.
[70.450] LOW malformed-frames confidence=30 evidence=10/10000ms ch=6 | Lots of malformed or invalid frames in a short time. Could be a fuzzing tool, a buggy device or heavy interference.
```

The demo is a synthetic minute of normal apartment traffic, then a forged
deauth flood and some broken frames. It also works with real captures: any
Wi-Fi adapter that supports monitor mode plus `tcpdump` or Wireshark, saved
as classic `.pcap`. Only capture networks you're allowed to.

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
core/              portable C++ core, no hardware or SDK code in here
modules/serial/    event and status formatting (text / JSON lines)
platform/espidf/   ESP-IDF radio adapter
platform/host/     pcap + radiotap reader for laptops
firmware/          ESP-IDF project tying it together
tools/             replay tool and demo capture generator
tests/             host tests and the synthetic frame builder
docs/              rules, firmware, hardware status, limitations
```

## Roadmap

1. **Foundation**: types, parser, tests, CI ✓
2. **Detection MVP**: rolling windows, deauth/disassoc bursts, malformed frames,
   structured events ✓
3. **First ESP32 adapter**: ESP-IDF, promiscuous capture, serial output ✓
   (compiles, waiting on a real board)
4. **Reliability**: dedup, rate limiting, bounded everything ← *next*
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
