# BYTEME CTF 2026 (CTF7) — Writeups

Writeups & solve notes for **BYTEME CTF 2026 (CTF7)**, the OWASP student-chapter "Soul Stone / Vormir"-themed CTF.

## 🏆 Result

| | |
|---|---|
| **Placement** | 🥈 **6th place** |
| **Score** | **12,650 pts** |
| **Solved** | **60 / 79 challenges** |

### Team

| Player | Solves |
|---|---|
| `ednk` | 39 |
| `ftps3rver` | 21 |

---

## 📖 Writeups in this repo

A detailed, reproducible writeup for **15 challenges** across every category is in **[`byteme-ctf7-writeup.md`](./byteme-ctf7-writeup.md)**. Each entry includes recon, the key insight, a copy-pasteable reproduction (payload / script / command), and an explicit note on how the flag was validated.

> **Flag format:** `OWASP{...}`

### Challenges covered

| # | Challenge | Category | Flag |
|---|---|---|---|
| 1 | Return to Win | pwn | `OWASP{g3ts_1s_4_s3cur1ty_n1ghtm4r3}` |
| 2 | Soul's Weakness | pwn | `OWASP{S0ul_St0ne_Buff3r_0v3rfl0w}` |
| 3 | Soul // Memory of Thanos | pwn | `OWASP{Th4n0s_S0ul_Mem0ry_UAF_Type_Confusion}` |
| 4 | Soul Vault: The Collector | pwn | `OWASP{S0ul_St0ne_C0ll3ct0r_UAF_Aw4k3n3d}` |
| 5 | SoulStone (Trial of Vormir) | rev | `OWASP{a_s0ul_f0r_a_s0ul_v0rm1r_cl1ff_7c8d9e2a}` |
| 6 | SoulVault | rev | `OWASP{s0ul_v4ult_byt3c0d3_vm_r3v3rs3d_7a8f9c2e}` |
| 7 | The Soul Forge | ai | `OWASP{ARCHIVIST_SOUL_STONE_FORGE}` |
| 8 | The Null Crown | ai | `OWASP{ARCHIVIST_OBSIDIAN_HEART_CROWN}` |
| 9 | Soul Ascension | mobile | `OWASP{s0ul_4sc3nd3d_th3_f1fth_guardian}` |
| 10 | Soul Fragment Race | web | `OWASP{byteme_soul_fragment_race}` |
| 11 | Red Skull's Trail | osint | `OWASP{PhantomSoul}` |
| 12 | The Vormir Ledger | osint | `OWASP{preikestolen_7734_sacrifice}` |
| 13 | The Keeper's Legacy | osint | `OWASP{Manikarnika_Ghat}` |
| 14 | The Soul Stone's Legacy | osint | `OWASP{Mady_Madnoliet_Los_Angeles}` |
| 15 | Stalker 0 | osint | `OWASP{ARNAV_KHADKE_124B1B144_TREASURER}` |

---

## 🧠 Highlights

- **pwn** — classic ret2win (with the x86-64 `movaps` stack-alignment gotcha), plus two heap challenges solved via use-after-free → callback hijack (one to a `soul_ascension` win func, one to `system("/bin/sh")` with a smallbin libc leak).
- **rev** — a crypto-gated binary cracked entirely from its **offline HMAC oracle** (no need to run it), and an **obfuscated Go bytecode VM** reversed with pure-Python `pyelftools` + `capstone` and inverted round-by-round.
- **ai** — two multi-guardian Gemini-Gem prompt-injection chains, one attack class per guardian; both avoid the planted decoy flags.
- **web** — the advertised "race condition" was a decoy; the real bug was a hidden endpoint reading the wrong JSON key.
- **mobile** — Android dex logic + a native `libguardian.so` TEA-in-CBC pipeline gated by an FNV-1a check.
- **osint** — reverse-image → artist identity → Behance; a seven-point **Big Dipper constellation overlay** on Varanasi geolocation; data hidden past a PNG `IEND`.

Full technique notes and a reproduction environment appendix are at the end of the writeup.

---

## 🗂️ Categories (team total: 60/79)

`pwn` · `rev` · `crypto` · `web` · `forensics` · `stego` · `osint` · `mobile` · `ai`

---

## ⚠️ Notes

- All flags here were either produced/accepted by the live challenge during the event, or are statically verifiable in the provided artifacts (see the validation column in the writeup).
- Writeups are for educational purposes. Exploits target the retired CTF infrastructure only.

---

*BYTEME CTF 2026 (CTF7) · Team placement 6th · 12,650 pts · 60/79 solved*
