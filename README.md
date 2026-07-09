# El Niño — CTF Writeups

Capture-the-flag field notes. Hack The Box machines taken apart step by step,
from first packet to root shell.

**Live site:** GitHub Pages, deployed from `main` / root. Machine index at [`index.html`](index.html).

## Machines

| Machine | Platform | OS | Difficulty | Status |
|---------|----------|----|------------|--------|
| [MakeSense](makesense/) | Hack The Box | Linux | Medium | owned (user + root) |
| [Orion](orion/) | Hack The Box | Linux | Easy | owned (user + root) |
| [FireFlow](fireflow/) | Hack The Box | Linux | Medium | user owned |
| [Enigma](enigma/) | Hack The Box | Linux | Medium | owned (user + root) |
| [Connected](connected/) | Hack The Box | Linux | Easy | owned (user + root) |
| [Nexus](nexus/) | Hack The Box | Linux | Medium | owned (user + root) |
| [Cap](cap/) | Hack The Box | Linux | Easy | owned (user + root) |

## Structure

```
index.html              landing page (machine index)

makesense/index.html    MakeSense writeup (self-contained)
makesense/makesense.md  MakeSense writeup, markdown

orion/index.html        Orion writeup (self-contained, screenshots inlined)
orion/orion.md          Orion writeup, markdown

fireflow/index.html     FireFlow writeup (self-contained, screenshots inlined)
fireflow/fireflow.md    FireFlow writeup, markdown

enigma/index.html       Enigma writeup (self-contained, screenshots inlined)
enigma/enigma.md        Enigma writeup, markdown

connected/index.html    Connected writeup (self-contained)
connected/connected.md  Connected writeup, markdown

nexus/index.html        Nexus writeup (self-contained, screenshots inlined)
nexus/nexus.md          Nexus writeup, markdown

cap/index.html          Cap writeup (self-contained, screenshots inlined)
cap/cap.md              Cap writeup, markdown
cap/cap-0.pcap          the credential-bearing capture (IDOR artifact)
```

All writeups describe work performed against authorized Hack The Box lab machines.
