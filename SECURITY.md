# Security

## Reporting a vulnerability

If you find a security problem in inapparency itself (for example a frame
that crashes the parser or makes it read out of bounds, or a way to make the
firmware stop monitoring), please **don't open a public issue**.

Report it privately through GitHub:
**Security → Report a vulnerability** on this repository, or email
**fer@nyras.dev**.

Include what you found, how to reproduce it (a `.pcap` or the bytes of the
frame helps a lot), and which version or commit you tested. You should get a
reply within a week. Once a fix is out, you'll be credited unless you'd
rather not be.

Supported versions: the latest release and `main`.

## What counts

- Crashes, hangs, memory errors or out-of-bounds reads on any input frame
- Ways to stop or silence detection remotely (other than jamming the radio)
- Ways to get the firmware to transmit anything
- Problems with how logs or the SD card are handled

Missed detections and false positives are **not** security issues. Open a
normal issue for those, they're very welcome.

## Responsible use

inapparency only listens, but what it records can still be personal: MAC
addresses and network names belong to real people. Only monitor networks you
own or have permission to watch, and treat logs from an SD card the way
you'd treat any other personal data. Check the laws where you are; some
places restrict capturing wireless traffic even passively.
