# Limitations

inapparency can only reason about frames it actually receives. This page is
here so nobody mistakes it for more than it is.

## Radio

- **2.4 GHz only** on the ESP32, S3, C3 and C6. Anything happening on 5 GHz is
  invisible to them. The ESP32-C5 is dual-band and may close this gap later.
- **One channel at a time.** While hopping, each channel is only watched a
  fraction of the time, so counts are samples, not totals. Detection
  thresholds have to account for how long each channel was actually watched.
- Distance, walls, antenna placement and interference all drop frames.
- Corrupted frames are usually filtered out by the radio before the software
  ever sees them.
- **Neighboring channels leak.** 2.4 GHz channels overlap, so a radio on
  channel 6 also hears some frames sent on 5 or 7. Frames are tagged with
  the channel the radio was on, not always the one they were sent on.
- **Coverage is an average.** Hopping coverage assumes equal time per
  channel. The real share can differ slightly, and bursts shorter than one
  hop cycle can be missed entirely.
- Signal strength (RSSI) varies a lot between boards and antennas, so it
  isn't used for detection yet.

## Frames

- Only management frames are parsed so far. Control, data and extension
  frames come back as `Unsupported`, never as suspicious.
- Protected management frames (PMF) have encrypted bodies, so their reason
  codes can't be read. That's expected, not an error.
- The FCS (checksum) is stripped but not verified.

## Firmware

- Not yet run on a real board. It compiles for four chips, but radio
  behavior is unverified. See [supported hardware](supported-hardware.md)
  for what still needs checking.
- Channel hopping undercounts: rules don't yet scale their thresholds by how
  long each channel was watched.

## Detection

- Thresholds are fixed numbers for now, not learned from your environment. A
  busy office and an empty house get the same defaults.
- Rules track a limited number of networks (16 for deauth bursts, 32 for
  learned PMF state). In very crowded places older ones get replaced.
- PMF status comes from beacons. Until a network's beacon is heard, its PMF
  status is unknown and alerts say so.

## Output

- The event gate rate-limits output. During a big flood some events are
  held back. They're counted in `suppressed=` on the status line, never
  silently lost.

## Conclusions

- No alerts doesn't mean nothing happened.
- Two access points with the same name aren't proof of an evil twin. Mesh
  systems and roaming do that all the time.
- Lots of deauths can come from normal roaming, band steering or a rebooting
  access point.
- Probe requests are normal. Phones send them constantly.
- A passive listener can't see devices that only listen.

Every rule has to document its own false positives before it gets merged.
