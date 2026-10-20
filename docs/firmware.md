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

## Flash a release without building

Every [release](https://github.com/nyrasdev/inapparency/releases) has one
complete image per chip. Flash it at offset 0:

```sh
pip install esptool
esptool.py --chip esp32 write_flash 0x0 inapparency-v0.1.0-esp32.bin
```

Or from the browser: open https://espressif.github.io/esptool-js/, connect,
and flash the `.bin` at `0x0`. The `-oled-sd` images have the display and SD
card switched on with the default pins from [modules.md](modules.md); the
others are serial only. Then open any serial monitor at 115200 baud.

## Settings

Under **inapparency** in `idf.py menuconfig`:

| Setting | Default | |
|---|---|---|
| Fixed channel | 0 (hop) | Watching your own network? Set its channel. |
| Channels to hop | `1,6,11` | Only used when not fixed |
| Time on each channel | 500 ms | |
| Status interval | 30 s | 0 turns status lines off |
| Output format | text | or JSON lines |
| OLED display | off | see [modules.md](modules.md) |
| Log alerts to a microSD card | off | see [modules.md](modules.md) |

A fixed channel is the better choice whenever you know which network you
care about. While hopping, each channel is only heard part of the time, so
bursts get undercounted.

## What it prints

```
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⢀⠐⡩⠄⠒⠋⠱⠳⡀⠈⣆⠀ ...
   (the logo, 30 lines of braille art)
  inapparency 0.1.0

target esp32 rev 3 | 2 core(s) | esp-idf v5.4.1 | boot #12
passive mode: listening only, nothing is transmitted
rules: deauth-burst, malformed-frames, ap-change, evil-twin, auth-flood + attack-chain
channel: hopping 1,6,11 every 500 ms (33% coverage each)
monitoring started
[30.000] status frames=2841 ok=2830 ... dropped=0 queue_peak=3 ch=6 heap=187420 heap_min=186904 stack_free=3120 suppressed=0
[61.204] HIGH deauth-burst confidence=70 evidence=7/5000ms bssid=... ch=6 coverage=33% | Unprotected deauth/disassoc burst on a network that requires PMF. ...
```

Worth reporting, with your board model:

- `dropped` above 0: frames came in faster than detection could handle them
- `heap_min` going down over hours: something is leaking
- `stack_free` under ~500: the detection task needs a bigger stack

## How it's put together

```
Wi-Fi driver task          capture callback copies the frame into a ring
        │                  (never waits, drops and counts when full)
        ▼
CaptureRing (32 × 512 B)
        │
        ▼
"detect" task              parse → learn networks → rules → correlator →
                           event gate → serial lines
                           (the only task touching the detector, no locks)

main task                  channel hopper, moves the radio every N ms

"display" task (optional)  redraws the OLED every 500 ms from a snapshot
"storage" task (optional)  writes queued alerts to the SD card
```

The detection task never waits on a module. It hands the display a copy of
its counters every 250 ms and the storage task a queue of alerts. When that
queue is full, the alert is still printed on serial and only the log copy
is dropped.

Everything is allocated statically at boot. Nothing in the frame path uses
the heap.
