<div align="center">

# 🚩 ctf-writeups

**A growing archive of CTF challenge write-ups — reverse engineering, pwn, web, forensics & more.**

![Reverse Engineering](https://img.shields.io/badge/Reverse%20Engineering-black?style=flat-square&logo=ghostery&logoColor=white)
![Pwn](https://img.shields.io/badge/Binary%20Exploitation-black?style=flat-square&logo=gnubash&logoColor=white)
![Web](https://img.shields.io/badge/Web%20Exploitation-black?style=flat-square&logo=todoist&logoColor=white)
![Forensics](https://img.shields.io/badge/Forensics-black?style=flat-square&logo=files&logoColor=white)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen?style=flat-square)

</div>

---

## 👋 About

Write-ups from CTF competitions I've played, documenting the analysis process, the vulnerability, and the exploitation path for each challenge — not just the flag. Maintained by **[@thaihq-ns](https://github.com/thaihq-ns)**, competing as **`c10v3`**.

Focus areas: reverse engineering, binary exploitation, web exploitation, digital forensics, OSINT, and cryptography.

---

## 📁 Repository Structure

Write-ups are organized by **competition** and **category**:

```
ctf-writeups/
├── NNS-CTF-2026/
│   ├── reverse/
│   └── pwn/
├── TAMUctf 2026/
│   └── reverse/
├── bdsec-2026/
│   └── Web/
├── picoCTF-2026/
│   └── pwn/offset-cycleV2/
├── v1t_2026/
│   └── forensic/
└── README.md
```

---

## 🗂️ Write-ups

| Competition | Category | Challenge | Key Technique |
|---|---|---|---|
| NNS CTF 2026 | Reverse | Flag Pointer Register | Windows x64 calling convention — wrong pointer in `RDX` before `WriteFile` |
| NNS CTF 2026 | Reverse | Open Secret | Direct `openat` syscall, XOR+LCG-encrypted runtime path |
| NNS CTF 2026 | Reverse | No Strings Attached | Runtime-built passphrase leaked via `ltrace`'ing `strcmp()` |
| NNS CTF 2026 | Pwn | Echo Chamber | Format string vulnerability (`printf(input)`) leaking the stack |
| picoCTF 2026 | Pwn | offset-cycleV2 | Buffer overflow → ret2win |
| TAMUctf 2026 | Reverse | — | — |
| bdsec 2026 | Web | — | — |
| v1t 2026 | Forensic | — | — |

*(Rows without a listed challenge are folders with write-ups pending index — check the folder directly.)*

---

## 🛠️ Tools & Skills

`x64dbg` · `IDA` · `Ghidra` · `strace` / `ltrace` · `pwntools` · `Wireshark` · `Nmap` · Wazuh / ELK for blue-team work

---

## 📌 Notes

- Each write-up covers: challenge description → analysis → vulnerability → exploitation → flag.
- Flags are included for completeness/reference — the value is in the *how*, not the flag itself.
- More write-ups added as challenges get solved.

---

<div align="center">

*Made with 🐛 and too much coffee.*

</div>
