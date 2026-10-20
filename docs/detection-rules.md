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
  Critical events (attack chains) skip the rate limit.

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

## 3. `ap-change`

**Severity:** info / medium / high depending on what changed

Learns how each BSSID normally looks from its first few beacons (name,
channel, beacon interval, security) and reports when that changes.

| Setting | Default |
|---|---|
| `confirmations` | 3 matching beacons to set the baseline |
| `threshold` | 3 differing beacons |
| `window_ms` | 10000 |
| `settle_ms` | 2000 |
| `cooldown_ms` | 60000 |

| What it sees | Severity | Confidence |
|---|---|---|
| Old and new setup **alternating** on the same BSSID, new one weaker | high | 80 |
| Alternating, same security (other channel, name or timing) | medium | 50 |
| Old setup gone, replaced by a weaker one | high | 55 |
| Old setup gone, replaced by an equal or stronger one | info | 15 |

"Alternating" means two transmitters are using one BSSID: the real AP and
a spoofed copy. A clean switch-over is just as likely to be the owner
changing settings, so after reporting it once the new setup becomes the
baseline.

**Known false positives**

- Changing the router's settings (reported once, as info)
- Some APs briefly announce a channel switch before moving

**Known gaps**

- If an impostor is already beaconing when monitoring starts, the baseline
  may never form. `evil-twin` covers the more common case.
- Two setups that differ only in fields we don't compare yet (rates, vendor
  elements) aren't noticed.

---

## 4. `evil-twin`

**Severity:** high

The same network name served by several BSSIDs where one offers **weaker
security** than another. Matching names alone never fire (mesh systems and
extenders do that), only a security gap does.

| Setting | Default |
|---|---|
| `min_beacons` | 3 per BSSID |
| `newcomer_after_ms` | 30000 |
| `expire_ms` | 120000 (BSSIDs not heard this long are forgotten) |
| `cooldown_ms` | 300000 |

| Evidence | Confidence |
|---|---|
| Weaker BSSID appeared 30 s+ after the stronger one | 65 |
| Both were there from the start | 35 |
| The weaker one is open | +15 |
| The stronger one requires PMF, weaker one is WPA2 or less | +5 |
| They're on different channels | +5 |

The event's `bssid` is the suspected twin and `related` is the real AP.

**Not reported**

- An older weak BSSID next to a newer strong one (someone added a WPA3
  node to a WPA2 network)
- Hidden networks
- Names that only look alike (`home` vs `Home` vs `home-guest`)

**Known false positives**

- Venues that really do run an open and a protected network under one name
- Mixed-generation mesh setups where an old node can't do WPA3

**Known gaps**

- Twins that copy the security too (same password, WPA2 to WPA2) look like a
  mesh node. Catching those needs signal strength or timing, coming later.
- Only beacons count. A twin that only answers probe requests isn't seen yet.
- Tracks 16 names with 6 BSSIDs each. In very busy places extra BSSIDs with
  security already tracked are skipped.

---

## 5. `auth-flood`

**Severity:** medium

Lots of authentication and (re)association requests to one access point from
many different addresses. Used to fill an AP's client table so real devices
can't join.

| Setting | Default |
|---|---|
| `window_ms` | 5000 |
| `threshold` | 50 requests |
| `min_sources` | 10 different addresses |
| `min_threshold` | 15 (floor when hopping) |
| `cooldown_ms` | 30000 |

Only the client's side of the handshake counts. Confidence starts at 40,
then +up to 20 for volume, +10 when 24+ different sources were seen, +5 when
nearly all addresses are randomized (weak, phones randomize too), and −5
while hopping.

**Known false positives**

- A crowd joining at once (a class walking in, an event starting)
- Devices stuck in a reconnect loop with a broken AP

---

## Attack chains

Not a rule but a **correlator** that watches the events rules produce. It
adds a **critical** `attack-chain` event when an impostor (`evil-twin`, or
`ap-change` with two setups alternating) and a `deauth-burst` against the
**same real AP** happen within 2 minutes of each other, in either order.

That's how evil twin attacks are usually run: put up the fake network, then
kick everyone off the real one so they reconnect to the fake. Confidence is
the stronger half +10 (max 95). Chains skip the rate limit but are reported
at most once per AP every 5 minutes.

---

## Adding a rule

1. Implement `inapparency::Rule` in `core/include/inapparency/rules/` and
   `core/src/rules/`, then add it to `DefaultRules` in
   `core/include/inapparency/default_rules.hpp`.
2. Give it a stable id that's never reused.
3. Keep its state fixed-size. Use `RollingCounter` and `MacTable`.
4. Write a config with `valid()`, and fall back to defaults when invalid.
5. Test the case that should fire *and* the ordinary traffic that shouldn't.
6. Document it here, including false positives.
