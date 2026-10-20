# Firmware

The firmware runs the same detection core as the host tests on an ESP32
board, headless. It only listens: the radio is in `WIFI_MODE_NULL` with
promiscuous mode on, so it never joins, scans or transmits anything.

## Build and flash

Needs [ESP-IDF v5.4](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32/get-started/).

```sh
cd firmware
idf.py set-target esp32        # or esp32s3, esp32c3, esp32c6
idf.py menuconfig              # optional, see below
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

No ESP-IDF installed? Every CI run uploads ready-made binaries for each chip
as artifacts. Flash them with `esptool.py` using the included `flash_args`.

## Settings

Under **inapparency** in `idf.py menuconfig`:

| Setting | Default | |
|---|---|---|
| Fixed channel | 0 (hop) | Watching your own network? Set its channel. |
| Channels to hop | `1,6,11` | Only used when not fixed |
| Time on each channel | 500 ms | |
| Status interval | 30 s | 0 turns status lines off |
| Output format | text | or JSON lines |

A fixed channel is the better choice whenever you know which network you
care about. While hopping, each channel is only heard part of the time, so
bursts get undercounted.

## What it prints

```
inapparency 0.1.0 | target esp32 rev 3 | 2 core(s) | esp-idf v5.4.1
passive mode: listening only, nothing is transmitted
rules: deauth-burst, malformed-frames
channel: hopping 1,6,11 every 500 ms
monitoring started
[30.000] status frames=2841 ok=2830 unsupported=0 truncated=11 ... dropped=0 queue_peak=3 ch=6 heap=187420 heap_min=186904
[61.204] HIGH deauth-burst confidence=75 evidence=20/5000ms bssid=... ch=6 | Unprotected deauth/disassoc burst on a network that requires PMF. ...
```

`dropped` above 0 means frames came in faster than detection could handle
them. Worth reporting with your board model.

## How it's put together

```
Wi-Fi driver task          capture callback copies the frame into a ring
        │                  (never waits, drops and counts when full)
        ▼
CaptureRing (32 × 512 B)
        │
        ▼
"detect" task              parse → learn networks → rules → serial lines
                           (the only task touching the detector, no locks)

main task                  channel hopper, moves the radio every N ms
```

Everything is allocated statically at boot. Nothing in the frame path uses
the heap.
