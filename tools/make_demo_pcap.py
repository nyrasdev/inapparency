#!/usr/bin/env python3
"""Writes a synthetic monitor-mode capture for trying out inapparency-replay.

Nothing here touches a radio. It builds 802.11 frames as bytes and saves
them as a radiotap .pcap:

  0-60 s   an ordinary apartment: three access points beaconing, phones
           probing, a client leaving now and then
  55 s     an open copy of the WPA3 network "home" starts beaconing (evil twin)
  60-63 s  a flood of forged, unprotected deauths against the real "home",
           to push its clients onto the copy (attack chain)
  70-71 s  a burst of malformed frames
  80-83 s  an authentication flood against the neighbor's access point

    python3 tools/make_demo_pcap.py demo.pcap
"""

import random
import struct
import sys

HOME = bytes.fromhex("021010101010")
NEIGHBOR = bytes.fromhex("022020202020")
CAFE = bytes.fromhex("023030303030")
CLIENT = bytes.fromhex("02aabbccddee")
TWIN = bytes.fromhex("02eeeeeeee01")
BROADCAST = b"\xff" * 6

DEAUTH, DISASSOC, BEACON, PROBE_REQ, AUTH = 12, 10, 8, 4, 11


def radiotap(channel_mhz, signal_dbm):
    # present: flags (1), channel (3), antenna signal (5)
    present = (1 << 1) | (1 << 3) | (1 << 5)
    body = struct.pack("<B", 0)  # flags: no FCS
    body += b"\x00"  # pad channel to 2 bytes
    body += struct.pack("<HH", channel_mhz, 0x00A0)
    body += struct.pack("<b", signal_dbm)
    return struct.pack("<BBHI", 0, 0, 8 + len(body), present) + body


def mgmt(subtype, receiver, transmitter, bssid, seq, body=b""):
    fc = struct.pack("<BB", subtype << 4, 0)
    header = fc + struct.pack("<H", 314) + receiver + transmitter + bssid
    header += struct.pack("<H", (seq & 0xFFF) << 4)
    return header + body


def element(eid, data):
    return struct.pack("<BB", eid, len(data)) + data


def rsn(akm, caps):
    return element(
        48,
        b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00\x00\x0f\xac\x04"
        + b"\x01\x00\x00\x0f\xac" + bytes([akm]) + struct.pack("<H", caps),
    )


def beacon(bssid, ssid, security, seq):
    # Capability: ESS, short slot, and the privacy bit only if protected.
    capability = 0x0401 if security == "open" else 0x0411
    body = b"\x00" * 8 + struct.pack("<HH", 100, capability)
    body += element(0, ssid.encode()) + element(3, b"\x06")
    if security == "wpa3":
        body += rsn(8, 0x00C0)
    elif security == "wpa2":
        body += rsn(2, 0x0000)
    return mgmt(BEACON, BROADCAST, bssid, bssid, seq, body)


def main(path):
    rng = random.Random(7)
    packets = []  # (time_us, frame)
    seq = 0

    for t_ms in range(0, 60_000, 100):
        seq += 1
        packets.append((t_ms * 1000, beacon(HOME, "home", "wpa3", seq)))
        packets.append(((t_ms + 30) * 1000, beacon(NEIGHBOR, "neighbor", "wpa2", seq)))
        packets.append(((t_ms + 60) * 1000, beacon(CAFE, "cafe-free-wifi", "open", seq)))
        if t_ms % 2000 == 0:
            phone = bytes([0x02] + [rng.randrange(256) for _ in range(5)])
            packets.append(((t_ms + 20) * 1000,
                            mgmt(PROBE_REQ, BROADCAST, phone, BROADCAST, seq, element(0, b""))))
        if t_ms % 15_000 == 0 and t_ms > 0:
            packets.append(((t_ms + 40) * 1000,
                            mgmt(DISASSOC, NEIGHBOR, CLIENT, NEIGHBOR, seq, struct.pack("<H", 8))))

    # Evil twin: same name as the WPA3 network, but open.
    for t_ms in range(55_000, 85_000, 100):
        packets.append(((t_ms + 50) * 1000, beacon(TWIN, "home", "open", t_ms // 100)))

    # Forged deauths: unprotected, broadcast, same reason, on a network that
    # requires PMF. A real WPA3 access point would never send these.
    for i in range(300):
        packets.append(((60_000 + i * 10) * 1000,
                        mgmt(DEAUTH, BROADCAST, HOME, HOME, i, struct.pack("<H", 7))))

    # Malformed: deauths cut off before their reason code.
    for i in range(15):
        packets.append(((70_000 + i * 50) * 1000, mgmt(DEAUTH, CLIENT, CAFE, CAFE, i, b"\x07")))

    # Auth flood against the neighbor from random spoofed addresses.
    for i in range(300):
        fake = bytes([0x02] + [rng.randrange(256) for _ in range(5)])
        body = struct.pack("<HHH", 0, 1, 0)  # open system, client's first frame
        packets.append(((80_000 + i * 10) * 1000, mgmt(AUTH, NEIGHBOR, fake, NEIGHBOR, i, body)))

    packets.sort(key=lambda p: p[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
        start = 1_760_000_000 * 1_000_000
        for t_us, frame in packets:
            data = radiotap(2437, rng.randint(-80, -40)) + frame
            ts = start + t_us
            f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(data), len(data)))
            f.write(data)
    print(f"wrote {len(packets)} frames to {path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: make_demo_pcap.py output.pcap")
    main(sys.argv[1])
