# Supported hardware

| Chip | Builds | Tested on a board | Notes |
|---|---|---|---|
| ESP32 | ✓ | ✓ | baseline target |
| ESP32-S3 | ✓ | | |
| ESP32-C3 | ✓ | | RISC-V, least RAM |
| ESP32-C6 | ✓ | | Wi-Fi 6 radio, still 2.4 GHz only |
| ESP32-C5 | – | | dual-band, would cover 5 GHz |

ESP-IDF v5.4.1. CI builds all four on every push.

Running it on an S3, C3 or C6? Open a
[hardware report](https://github.com/nyrasdev/inapparency/issues/new?template=hardware_report.yml)
and the table gets updated.

## Build sizes

Measured from the v0.1 firmware with default settings:

| Chip | App binary | With OLED + SD | Static RAM used (base) |
|---|---|---|---|
| ESP32 | 534 KB | 634 KB | 74 KB of 177 KB DRAM |
| ESP32-S3 | 526 KB | 630 KB | 139 KB of 334 KB |
| ESP32-C3 | 542 KB | 654 KB | 140 KB of 314 KB |
| ESP32-C6 | 577 KB | 681 KB | 172 KB of 442 KB |

All fit the default 1 MB app partition with room to spare.

Most of that is the Wi-Fi driver. inapparency itself takes about 45 KB of
RAM: the capture queue (~17 KB), the five rules (~24 KB) and the detector,
correlator and event gate (~4 KB).
