# BBM-MA-RE — Bangladesh Bank 2016 Heist Toolkit: Static Analysis

A byte-level static analysis of the malware toolkit used in the February 2016 Bangladesh Bank / SWIFT heist (`evtdiag.exe`, `evtsys.exe`, `nroff_b.exe`, `gpca.dat`), built through manual Ghidra reverse engineering.

**54 pages · 31 findings not present in prior public reporting (BAE 2016, DOJ 2018, Oosthoek & Doerr 2021), each grounded in a specific binary address.**

📄 **[Read the full report → REPORT.md](./REPORT.md)**

## What's in the report

- The complete attack timeline and the hardcoded kill-switch (byte-proven, section 5.2)
- Function-by-function reverse engineering of `evtdiag.exe`, with before/after Ghidra decompilation views
- The `gpca.dat` config format and RC4 decryption
- Attribution evidence tying all three binaries to a shared source tree (section 9)
- A complete IOC table for detection/hunting (section 10)
- A summary table of all novel findings vs. prior public reporting (section 11)

## Scope and intent

This is a defensive/educational static-analysis writeup of an already publicly known, six-year-old incident. No malware samples are included in this repository — only the analysis, disassembly excerpts, and hashes for identification purposes.

## Sample hashes

| File | SHA-256 |
|---|---|
| evtdiag.exe | `4659DADB...F71B631737631BC3FDED2FE2AF250CEBA98959A` |
| evtsys.exe | `AE086350...F7D251C7422C7BC5CE74730EE8BAB8E6283` |
| gpca.dat | `B07B37F0...D702B12485D7BC8A9EF1475B54BFF513A18E68FEF7` |

*(nroff_b.exe — SHA-1: `70bf1659...f60e4eeb`)*

---
Analyst: Hazem Akkouh · Part of the SENTRY Project
