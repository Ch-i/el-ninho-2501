# El Niño — CTF Writeups

Capture-the-flag field notes. Hack The Box machines taken apart step by step,
from first packet to root shell.

**Live site:** GitHub Pages, deployed from `main` / root. Machine index at [`index.html`](index.html).

## Machines

| Machine | Platform | OS | Difficulty | Status |
|---------|----------|----|------------|--------|
| [Nexus](nexus/) | Hack The Box | Linux | Medium | owned (user + root) |
| [Cap](cap/) | Hack The Box | Linux | Easy | owned (user + root) |

## Structure

```
index.html         landing page (machine index)

cap/index.html     Cap writeup (self-contained, screenshots inlined)
cap/cap.md         Cap writeup, markdown
cap/cap-0.pcap     the credential-bearing capture (IDOR artifact)

nexus/index.html   Nexus writeup (self-contained, screenshots inlined)
nexus/nexus.md     Nexus writeup, markdown
```

All writeups describe work performed against authorized Hack The Box lab machines.
