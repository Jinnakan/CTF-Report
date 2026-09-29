# Pentest Report — THMWindowsJump

## 1. Summary

- **Target:** TBD
- **Objective:** Escalate from guest access through a misconfigured Windows workstation left behind after a round of layoffs, moving laterally across accounts: `guest` → `thmuser` → `notadmin` → `svcadmin` → `SYSTEM`.
- **Category:** Windows privilege escalation / lateral movement
- **Status:** In progress
- **Outcome:** TBD

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | TBD |
| Attack box IP | TBD |
| Challenge name | THMWindowsJump |
| Category | Windows privesc / lateral movement |
| Date started | 2026-09-29 |

Room description: a routine vulnerability scan flagged a Windows machine on the internal network — a standard workstation left behind after a round of layoffs that IT never cleaned up properly. The intended path is to move laterally from guest access all the way to SYSTEM: `guest` → `thmuser` → `notadmin` → `svcadmin` → `SYSTEM`.

## 3. Methodology / Timeline

Chronological log of actions taken, in order. Filled in as the engagement progresses.

## 4. Findings

_(One entry per vulnerability/technique. Filled in as discovered.)_

Severity methodology: CVSS v3.1 base score, computed with the official FIRST.org calculator. Bands: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.

### F1 — [Title]
- **Affected asset:**
- **Severity:**
- **Description:**
- **Evidence:**
  ```
  command / output here
  ```
- **Impact:**
- **How found:**
- **Recommendation:**

## 5. Exploitation Chain

_(Step-by-step path from guest access to SYSTEM, filled in once confirmed.)_

## 6. Flag & Proof

- **Flag:**
- **Proof:**

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
