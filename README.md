# El Niño — CTF Writeups

Capture-the-flag field notes. Hack The Box machines taken apart step by step,
from first packet to root shell.

**Live site:** enable GitHub Pages on this repo (Settings → Pages → deploy from `main` / root).

## Machines

| Machine | Platform | OS | Difficulty | Status |
|---------|----------|----|------------|--------|
| [Cap](cap/) | Hack The Box | Linux | Easy | owned (user + root) |

## Structure

```
index.html      landing page (machine index)
cap/index.html  Cap writeup (self-contained, screenshots inlined)
cap/cap.md      Cap writeup, markdown
cap/cap-0.pcap  the credential-bearing capture (IDOR artifact)
```

All writeups describe work performed against authorized Hack The Box lab machines.
