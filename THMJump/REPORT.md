# Pentest Report — THMJump

## 1. Summary

- **Target:** TBD
- **Objective:** Escalate from anonymous access through a misconfigured internal automation pipeline, moving laterally across accounts: `recon_user` → `dev_user` → `monitor_user` → `ops_user` → `root`.
- **Category:** Linux privilege escalation / lateral movement
- **Status:** In progress
- **Outcome:** TBD

## 2. Scope & Environment

| Item | Value |
|---|---|
| Target IP | TBD |
| Challenge name | THMJump |
| Category | Linux privesc / lateral movement |
| Date started | 2026-09-26 |

Room description: a misconfigured internal automation pipeline on a Linux server processes recon scripts, development backups, monitoring jobs, and deployment tasks across multiple users. Each pipeline stage trusts the previous one too much, and abusing those trust boundaries is the intended path to move laterally: `recon_user` → `dev_user` → `monitor_user` → `ops_user` → `root`.

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

_(Step-by-step path from anonymous access to root, filled in once confirmed.)_

## 6. Flag & Proof

- **Flag:**
- **Proof:**

## 7. Remediation

_(Optional — fill in if the challenge expects defensive recommendations.)_

## 8. Appendix

_(Raw command output, scripts, screenshots referenced from findings.)_
