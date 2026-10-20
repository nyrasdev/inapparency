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

## Frames

- Only management frames are parsed so far. Control, data and extension
  frames come back as `Unsupported`, never as suspicious.
- Protected management frames (PMF) have encrypted bodies, so their reason
  codes can't be read. That's expected, not an error.
- The FCS (checksum) is stripped but not verified.

## Conclusions

- No alerts doesn't mean nothing happened.
- Two access points with the same name aren't proof of an evil twin. Mesh
  systems and roaming do that all the time.
- Lots of deauths can come from normal roaming, band steering or a rebooting
  access point.
- Probe requests are normal. Phones send them constantly.
- A passive listener can't see devices that only listen.

Every rule has to document its own false positives before it gets merged.
