# BBM-MA-RE : Bangladesh Bank 2016 Heist Toolkit: Malware Analysis && Reverse Engineering 

A byte-level static analysis of the malware toolkit used in the February 2016 Bangladesh Bank / SWIFT heist (`evtdiag.exe`, `evtsys.exe`, `nroff_b.exe`, `gpca.dat`), built through manual Ghidra reverse engineering.

**54 pages · 31 findings not present in prior public reporting (BAE 2016, DOJ 2018, Oosthoek & Doerr 2021 ...), each grounded in a specific binary address.**

📄 **[Read the full report → REPORT.md](./BBM_MA_RE.pdf)**

## What's in the report

- The complete attack timeline and the hardcoded kill-switch (byte-proven, section 5.2)
- Function-by-function reverse engineering of `evtdiag.exe`, with before/after Ghidra decompilation views
- The `gpca.dat` config format and RC4 decryption
- Attribution evidence tying all three binaries to a shared source tree (section 9)
- A complete IOC table for detection/hunting (section 10)
- A summary table of all novel findings vs. prior public reporting (section 11)

## Scope and intent

This is a defensive/educational Malware analysis writeup of an already publicly known, six-year-old incident.

---
Analyst: Hazem Akkouh · Part of the SENTRY Project
