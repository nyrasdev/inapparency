# Changelog

## 0.1.0

First release. Tested on an ESP32 and on synthetic traffic, and builds for
the ESP32, S3, C3 and C6. Hardware reports for the other chips are welcome.

### Detection
- `deauth-burst`: deauth/disassoc floods, much more confident when a network
  that requires PMF receives unprotected ones
- `evil-twin`: a copy of a network name with weaker security
- `ap-change`: a known access point changing its setup, or two transmitters
  sharing one BSSID
- `auth-flood`: join floods meant to fill an AP's client table
- `malformed-frames`: floods of broken management frames
- `attack-chain`: an impostor plus a deauth flood against the real AP
- Severity and confidence kept separate, every alert explains itself
- Deduplication and rate limiting, with held-back alerts counted
- Thresholds adjust to channel hopping

### Firmware
- ESP32, ESP32-S3, ESP32-C3 and ESP32-C6 (ESP-IDF 5.4)
- Passive capture, channel hopping or a fixed channel
- Text or JSON lines over serial, status line with drop and memory stats
- Optional SSD1306/SH1106 OLED display
- Optional microSD logging with rotation and a boot counter

### Tools
- `inapparency-replay`: run monitor-mode `.pcap` captures through the
  detector on a laptop
- `make_demo_pcap.py`: synthetic capture with a full evil twin attack
- `inapparency-display-preview`: draw the OLED screens without a display
