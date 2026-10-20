# Detection rules

Every rule reports two separate numbers:

- **severity**: how bad it would be if the thing is real
- **confidence** (0-100): how strongly the evidence points that way

Confidence is capped at 95. A threshold being crossed is evidence, never
proof.

Rules see every frame, keep fixed-size state, and go quiet for a cooldown
after firing so one long attack doesn't turn into thousands of events.

## Event gate

Everything rules emit passes through an event gate before it's printed:

- **Duplicates**: the same rule for the same BSSID within 10 s is dropped.
- **Rate limit**: at most 5 back to back, then 20 per minute on average. This
  stops an attacker spoofing thousands of BSSIDs from flooding the output.

Nothing is dropped silently. Both counts go into `suppressed=` on the status
line. The replay tool has `--no-limit` to see everything.

## Channel coverage

While hopping, a channel is only heard part of the time (3 channels → about
33 % each). Rules that count frames scale their thresholds by that share, so
an attack that's only partly heard still gets caught. These events carry
`coverage=33%` and lose a few confidence points, because less was actually
seen.

---

## 1. `deauth-burst`

**Severity:** high

Lots of deauthentication or disassociation frames tied to one BSSID inside
the window.

| Setting | Default |
|---|---|
| `window_ms` | 5000 |
| `threshold` | 20 frames |
| `cooldown_ms` | 30000 |
| `min_threshold` | 5 frames (floor when scaled for coverage) |

**Confidence** starts at 35 when the threshold is crossed, then:

| Evidence | Change |
|---|---|
| Every extra threshold's worth of frames | +10 (max +20) |
| Sent to broadcast, or to 3+ different clients | +10 |
| Every frame used the same reason code | +5 |
| Network requires PMF, at least half the frames unprotected | **+25** |
| Network requires PMF, some frames unprotected | +10 |
| Network requires PMF, all frames protected | **−25** |
| Channel only partly watched (hopping) | −5 |

The PMF check is the strongest signal. When a network requires PMF (WPA3
does), the real access point protects its deauth frames. An unprotected one
almost certainly didn't come from it.

PMF knowledge is sticky: once a BSSID has advertised "PMF required", a later
beacon saying otherwise doesn't erase it, because beacons can be forged too.

**Known false positives**

- An access point rebooting or kicking everyone off
- Band steering and mesh systems moving clients around
- Lots of clients leaving at once (end of a class, people heading home)
- On networks without PMF, forged and real frames look identical, so the
  explanation says so

**Known gaps**

- Only tracks 16 networks at once. Older ones get replaced.
- While hopping, the threshold is scaled from an average. A short burst
  that lands entirely while the radio is on another channel is still
  missed.
- An attacker sending under 20 frames per 5 s stays below the default
  threshold.

---

## 2. `malformed-frames`

**Severity:** low

Lots of structurally broken management frames in the window. Counted across
the whole channel, not per address, since addresses in a broken frame can't
be trusted.

| Setting | Default |
|---|---|
| `window_ms` | 10000 |
| `threshold` | 10 frames |
| `cooldown_ms` | 60000 |

Counts as malformed:

- Header or required fixed fields cut off
- Protocol version other than 0
- An element with an impossible length (SSID over 32 bytes, DS element not 1 byte, broken RSN)
- An element running past the end, **only** when the platform says the
  capture was complete

Never counted:

- Frames cut short by the capture itself
- Control, data and unknown frames
- Protected frames whose body we can't read

**Confidence** is 30 at the threshold, up to 60 with volume.

**Known false positives**

- Heavy interference, if the radio passes through frames with bad checksums
- Buggy or very old devices
- Vendor extensions the parser doesn't understand yet

---

## Adding a rule

1. Implement `inapparency::Rule` in `core/include/inapparency/rules/` and
   `core/src/rules/`.
2. Give it a stable id that's never reused.
3. Keep its state fixed-size. Use `RollingCounter` and `MacTable`.
4. Write a config with `valid()`, and fall back to defaults when invalid.
5. Test the case that should fire *and* the ordinary traffic that shouldn't.
6. Document it here, including false positives.
