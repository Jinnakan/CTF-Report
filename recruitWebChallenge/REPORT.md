# Pentest Report — Recruit (10.48.173.43)

## 1. Summary

- **Target:** 10.48.173.43 ("Recruit" web app)
- **Category:** General/mixed (recon → foothold → privesc)
- **Status:** In progress
- **Outcome:** TBD

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | 10.48.173.43 |
| Hostname/title | Recruit |
| Date started | 2026-09-05 |

## 3. Methodology / Timeline

Chronological log of actions taken, in order.

### 2026-09-05 — Initial recon

- Ran `nmap -sC -sV -oN recon.txt 10.48.173.43`
- Two earlier scan attempts failed due to malformed target argument (`recon`, `10.48.173.43` files) — not usable as evidence, discarded.

**Open ports:**

| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 |
| 53/tcp | domain (DNS) | ISC BIND 9.16.1 (Ubuntu) |
| 80/tcp | http | Apache httpd 2.4.41 (Ubuntu), PHP-backed (`PHPSESSID` cookie) |

**Notable details:**
- HTTP page title: "Recruit"
- `PHPSESSID` cookie missing `httponly` flag (session cookie readable via JS — potential XSS-to-session-theft vector, needs confirmation)

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

### F1 — [Title]
- **Description:**
- **Evidence:**
  ```
  command / output here
  ```
- **Impact:**
- **How found:**

## 5. Exploitation Chain

_(Step-by-step path from initial access to flag, filled in once confirmed.)_

## 6. Flag & Proof

- **Flag:**
- **Proof:**

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

### A1 — Raw nmap output

```
# Nmap 7.99 scan initiated Sat Sep  5 13:30:25 2026 as: nmap -sC -sV -oN recon.txt 10.48.173.43
Nmap scan report for 10.48.173.43
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 5d:ab:20:f3:97:7a:e9:c2:da:cb:aa:62:87:5a:2d:c4 (RSA)
|   256 63:8d:a8:a8:6d:ca:d8:84:a3:19:26:6a:2a:e8:50:90 (ECDSA)
|_  256 0c:34:87:ef:b1:be:fa:0d:c8:0b:0e:a8:e0:e8:42:51 (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Recruit
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep  5 13:31:29 2026 -- 1 IP address (1 host up) scanned in 64.36 seconds
```
