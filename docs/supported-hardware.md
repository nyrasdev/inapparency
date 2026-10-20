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

| Chip | App binary | Static RAM used |
|---|---|---|
| ESP32 | 525 KB | 57 KB of 177 KB DRAM |
| ESP32-S3 | 518 KB | 122 KB of 334 KB |
| ESP32-C3 | 533 KB | 123 KB of 314 KB |
| ESP32-C6 | 568 KB | 155 KB of 442 KB |

Most of that is the Wi-Fi driver. inapparency itself takes about 28 KB of
RAM: the capture queue (~17 KB) and the detector with its rules (~11 KB).

## Still to check on real hardware

These are written from the ESP-IDF docs and need confirming on a board:

- `rx_ctrl.sig_len` includes the 4-byte FCS on every chip, and `payload`
  really holds that many bytes for management frames
- `rx_ctrl.channel` reports the channel we switched to
- Deauth and disassoc frames reach the promiscuous callback (receiving should
  be fine; it's sending raw deauths that ESP-IDF blocks)
- How many frames per second each chip handles before the queue drops some
- Free heap stays flat over a day of running
