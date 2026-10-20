# Supported hardware

"Compiles" and "works" are tracked separately. A board only counts as
supported once it has run on real hardware and the result is written down
here.

| Chip | Compiles | Flashed | Captures frames | Detection verified | Notes |
|---|---|---|---|---|---|
| ESP32 | ✓ | – | – | – | baseline target |
| ESP32-S3 | ✓ | – | – | – | |
| ESP32-C3 | ✓ | – | – | – | RISC-V, least RAM |
| ESP32-C6 | ✓ | – | – | – | Wi-Fi 6 radio, still 2.4 GHz only |
| ESP32-C5 | – | – | – | – | dual-band, would cover 5 GHz |

ESP-IDF v5.4.1. CI builds all four on every push.

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

## Still to check on real hardware

These are written from the ESP-IDF docs and need confirming on a board:

- `rx_ctrl.sig_len` includes the 4-byte FCS on every chip, and `payload`
  really holds that many bytes for management frames
- `rx_ctrl.channel` reports the channel we switched to
- Deauth and disassoc frames reach the promiscuous callback (receiving should
  be fine; it's sending raw deauths that ESP-IDF blocks)
- How many frames per second each chip handles before the queue drops some
- Free heap stays flat over a day of running
- The OLED shows the splash and status on both SSD1306 and SH1106 modules
- The SD card mounts, `inapp.log` rotates, and pulling power mid-write
  loses at most one line
