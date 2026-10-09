<div align="center">

# REA · OpenBSD `nc`

**Static reverse-engineering of the Ubuntu `netcat-openbsd 1.234-1` binary with
[REA](https://github.com/morluto/rea) — "Reverse Engineer Anything" — and Ghidra 12.1.4.**
No execution, no guesswork: every claim below is backed by an artifact in [`files/`](files/).

[![REA](https://img.shields.io/badge/REA-v6.2.0-5c4ee5?style=flat-square)](https://github.com/morluto/rea)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.1.4-3fb950?style=flat-square)](https://ghidra-sre.org)
[![Target](https://img.shields.io/badge/target-netcat--openbsd_1.234--1-58a6ff?style=flat-square)](https://launchpad.net/ubuntu/+source/netcat-openbsd)
[![License](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/NullLabTests/OpenBSD_netcat_REA?style=flat-square&color=orange)](https://github.com/NullLabTests/OpenBSD_netcat_REA/stargazers)

<img src="assets/rea-pipeline.png" alt="REA analysis pipeline" width="860">

</div>

---

## Contents
[TL;DR](#tldr) · [At a glance](#target-at-a-glance) · [Method](#method-how-rea-was-used) ·
[Findings](#what-we-found) · [Evidence](#annotated-evidence) · [Function map](#function-map) ·
[Capabilities](#capabilities--imports) · [Strings](#notable-strings) · [Layout](#repo-layout) ·
[Reproduce](#reproduce) · [Limits](#confidence--limits) · [Security](#security-notes)

---

## TL;DR

> `nc` is the stock **Ubuntu/Debian `netcat-openbsd`, version `1.234-1`** — an
> unmodified-looking, stripped PIE with **all modern hardening enabled** and **no
> TLS**. The embedded Debian package note, the version banner, the full option
> table, and every imported symbol match the upstream package. **No evidence of
> custom, backdoored, or trojanized code was found.**

| | |
|---|---|
| **Identity** | `netcat-openbsd 1.234-1` (Ubuntu, amd64) — confirmed 4 ways |
| **Format** | ELF64 · x86-64 · LE · PIE (`ET_DYN`) · **stripped** |
| **SHA-256** | `de49cac83b4645476865e1faa39ac6c9e833baa1ea26fde02ec8045ec71a160d` |
| **Build ID** | `f8b823fa69cb2bcae5acf66b977262d7b7321755` |
| **Size** | 39,160 bytes |
| **Hardening** | Full RELRO · NX · stack canary · CET (IBT + SHSTK) |
| **Recovered** | `main` + 24 helpers, 166 internal procedures, 247 strings, full call graph, pseudocode |

---

## Target at a glance

| Property | Value | How it was proven |
|---|---|---|
| Package | `netcat-openbsd 1.234-1` amd64 | `.note.package` = `{"type":"deb","os":"ubuntu",…}` |
| Banner | `OpenBSD netcat (Debian patchlevel 1.234-1)` | `.rodata` @ `0x7a78`, xref'd by `-h` path |
| Linkage | `libbsd.so.0`, `libresolv.so.2`, `libc.so.6` | `DT_NEEDED` / `readelf -d` |
| Interpreter | `/lib64/ld-linux-x86-64.so.2` | `PT_INTERP` @ file `0x3a4` |
| TLS | **absent** | no `libtls`/`libssl`, no `SSL_*` imports |
| Symbols | stripped (dynsym only) | no `.symtab`, `nm` shows only imports |

---

## Method: how REA was used

REA wraps analysis engines and returns **evidence envelopes** — every answer
carries the provider, the raw result, and a confidence/limitations block. We ran
two providers against the same image and cross-checked with `readelf`, `objdump`,
`nm`, and `strings`.

**1 · Offline ELF layout — `pwntools-elf`, no execution**

```bash
REA_PWNTOOLS_PYTHON=./env/bin/python \
  rea inspect-binary-layout nc --json      # sections, segments, relocs, prot, hardening
```
Isolated env: `pwntools 4.15.0` · `pyelftools 0.33` · `unicorn 2.1.2`.

**2 · Deep analysis — Ghidra 12.1.4 headless**

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/opt/jdk-21              # Ghidra 12.1 rejects JDK 25

rea analyze  nc --provider ghidra --json                 # base 0x100000, auto-analysis
rea search   nc --kind procedures --provider ghidra --json   # 236 procedures
rea search   nc --kind strings    --provider ghidra --json   # 247 strings
rea decompile nc 0x102a90         --provider ghidra --json   # main
rea trace    nc "OpenBSD netcat (Debian patchlevel 1.234-1)" --provider ghidra --json
```

Upstream `netcat.c` (same patchlevel intent) was consulted **only** to name
functions — the binary is the source of truth. Findings are reproduced in
`results.txt`; raw outputs live in `files/`.

---

## What we found

<div align="center">

**Hardening profile**

<img src="assets/hardening.png" alt="Hardening mitigations" width="620">

**ELF mapping — file offset → virtual address**

<img src="assets/memory-map.png" alt="File offset to virtual address PT_LOAD mapping with .bss noted" width="900">

*The RW segment shifts `+0x1000` from file offset `0x8b98` to virtual `0x9b98`, and its
`.bss` tail (`memsz − filesz = 0x80608`) is not file-backed — a detail the raw ELF
tables hide.*

**Section sizes**

<img src="assets/sections.png" alt="ELF section sizes" width="760">

**Recovered call graph**

<img src="assets/call-graph.png" alt="Recovered function call graph" width="920">

</div>

### Highlights
- **One giant `main`.** `main` (0x102a90) is 10,086 bytes, split by GCC
  hot/cold partitioning and aggressive inlining; proxy, option parsing and
  dispatch are all inlined into it.
- **Proxy stack, recovered from strings + xrefs.** SOCKS4/4A/5 (`-X 4|4A|5`)
  with auth, plus HTTP `CONNECT` tunnelling with Basic auth and `200`/`407`
  handling — fully inlined, no separate functions.
- **Secrets handled carefully.** Proxy and TCP-MD5 passwords go through
  `readpassphrase`; buffers are wiped with `__explicit_bzero_chk`; HTTP auth is
  built with `__b64_ntop`.
- **Safe-string discipline.** The binary uses BSD `strlcpy`/`strlcat`/`strtonum`
  (via `libbsd`), not the unbounded `strcpy`/`sprintf` family.

---

## Annotated evidence

A representative decompile — `writep` at `0x106120`, which implements `-C`
(line-ending → CRLF) and `-q` (quit delay). Cleaned from Ghidra output
(`FUN_00106120`); `atomicio` is the local `EINTR`/`EAGAIN` retry helper at
`0x105340`. Full listing: [`files/decompiled_functions.c`](files/decompiled_functions.c).

```c
/* writep(fd, buf, *len, crlf_enabled) — returns bytes written */
size_t writep(int fd, char *buf, size_t *len, int crlf) {
    if (fd == -1) return -1;
    char *lf = crlf ? memchr(buf, '\n', *len) : NULL;   /* expand LF -> CRLF */
    if (lf) {
        if (!crlf || lf == buf || lf[-1] != '\r') {
            write(fd, buf, lf - buf);                     /* write up to LF */
            atomicio(write, fd, "\r\n", 2);               /* then CRLF  */
        }
    } else {
        write(fd, buf, *len);                             /* plain write */
    }
    ...
    if (delay) sleep(delay);                              /* -q seconds  */
}
```

Every address, string and call edge in this repo traces back to a JSON envelope
in `files/` (e.g. `rea-decompile-main.json`), so the analysis is auditable.

---

## Function map

`main` plus 24 helpers. Linked addresses (image base 0); Ghidra added `+0x100000`.

| File vaddr | Function | Role (evidence-based) |
|---:|---|---|
| `0x02a90` | **`main`** | Options, SOCKS4/4A/5 + HTTP CONNECT proxy, listen/connect dispatch |
| `0x05340` | `atomicio` | read/write retry on `EINTR`/`EAGAIN` with `poll` |
| `0x05440` | proxy reader | HTTP proxy response line (≤1024 B, until `LF`) |
| `0x054d0` | `usage` | short usage text |
| `0x05510` | `strtoport` | numeric port or `getservbyname` lookup |
| `0x055b0` | sockopt/connect | common socket options on connect paths |
| `0x059d0` | resolver | `getaddrinfo` → `sockaddr_storage` |
| `0x05b40` | `fillbuf` | buffered read, `EAGAIN`/`EINTR` aware |
| `0x05bb0` | UNIX addr | builds UNIX sockaddr (abstract `@` paths) |
| `0x05c60` | `remote_connect` | timeout `connect`, verbose `getnameinfo`, min-TTL |
| `0x06120` | `writep` | write with `-C` CRLF translation + `-q` delay |
| `0x06300` | `readwrite` | main `poll` loop, 16 KB buffers |
| `0x06b00` | `report_sock` | `"%s on %s %s"` verbose reporting |
| `0x06c20` | `unix_bind` | UNIX socket create/bind (abstract-aware) |
| `0x00895` | `set_common_sockopts` | TTL/ToS/IPv6 hop limit, TCP buffer sizes |

<sub>Callers/callees, per-function xrefs and split-fragment flags:
[`files/function_inventory.md`](files/function_inventory.md) ·
[`.tsv`](files/function_inventory.tsv).</sub>

---

## Capabilities & imports

**Modes** — TCP connect; TCP listen (`-l`); UDP (`-u`); UNIX domain (`-U`); DCCP
(`-Z`); zero-I/O scan (`-z`); keep-listening (`-k`); detach (`-d`).

| Import group | Notables |
|---|---|
| Sockets | `socket`, `connect`, `bind`, `listen`, `accept4`, `sendmsg`, `recvfrom`, `shutdown`, `setsockopt`, `getsockopt`, `getsockname`, `select`, `poll`, `fcntl` |
| Name resolution | `getaddrinfo`, `freeaddrinfo`, `gai_strerror`, `getnameinfo`, `getservbyname`, `getservbyport` |
| Safe strings | `strlcpy`, `strlcat`, `strtonum`, `strdup`, `strcasecmp`, `__isoc23_strtol` |
| Secrets | `readpassphrase`, `__explicit_bzero_chk`, `__b64_ntop` |
| Runtime / misc | `alarm`, `signal`, `mkdtemp`, `unlink`, `rmdir`, `isatty`, `arc4random_uniform` |

**Socket options** — TTL / hop-limit (`-M`), min-TTL (`-m`), TOS/DSCP keywords
(`-T`: `critical` `inetcontrol` `lowcost` `lowdelay` `reliability` `throughput`),
TCP send/recv buffers (`-I`/`-O`), `SO_REUSEADDR`/`SO_REUSEPORT`, broadcast
(`-b`), TCP MD5SIG (`-S`, password via `readpassphrase`), source address (`-s`).

**Data path** — `readwrite` `select`/`poll` loop over stdin/stdout and the
network fd; `-C` CRLF translation; telnet negotiation (`-t`); fd passing (`-F`)
via `sendmsg`.

---

## Notable strings

<sub>Addresses are file vaddrs (Ghidra linked addresses are these `+0x100000`).</sub>

| Address | String (abridged) | Meaning |
|---:|---|---|
| `0x7a78` | `OpenBSD netcat (Debian patchlevel 1.234-1)` | version banner (`-h`) |
| `0x77e0` | `usage: nc [-46CDdFhklNnrStUuvZz] …` | full option table |
| `0x7699` | `CONNECT [%s]:%d HTTP/1.0\r\n` | HTTP proxy tunnelling (IPv6) |
| `0x7733` | `HTTP/1.0 407 ` | proxy auth required |
| `0x71f0` | `General SOCKS server failure` | SOCKS5 status → message map |
| `0x7a08` | `SOCKS server cannot connect to identd on the client` | SOCKS4/4A path |
| `0x702b` | `port number %s: %s` | `strtoport` error |

<sub>All 247 extracted strings: [`files/rea-search-strings.json`](files/rea-search-strings.json)
and [`files/strings.txt`](files/strings.txt).</sub>

---

## Repo layout

```
.
├── README.md                 # this file
├── LICENSE                   # MIT (analysis + docs)
├── NOTICE                    # upstream BSD attribution
├── results.txt               # full written report
├── assets/                   # README figures (regenerate with tools/make_assets.py)
├── tools/make_assets.py      # builds every figure from files/
└── files/                    # all evidence
    ├── README.md             # artifact index
    ├── layout_summary.md     # ELF layout + hardening
    ├── function_inventory.md / .tsv
    ├── decompiled_functions.c    # 25 functions, 3,499 lines
    ├── rea-*.json            # 30 canonical REA evidence envelopes
    └── *.txt                 # raw readelf / objdump / nm / strings
```

<sub>46 files, ~600 KB of evidence.</sub>

## Reproduce

```bash
npm i -g rea-agents                     # or: npx rea-agents@latest ...
# REA needs Ghidra 12.1.x + JDK 21 (see files/README.md for the exact env)
rea analyze  nc --provider ghidra --json
rea search   nc --kind procedures --provider ghidra --json
python3 tools/make_assets.py            # rebuild the figures
```

## Confidence & limits

| Aspect | Confidence | Basis |
|---|---|---|
| Identity / provenance | **High** | package note + banner + option table + imports |
| Hardening / linkage | **High** | static ELF facts |
| Function roles | **Medium** | Ghidra auto-names; roles inferred from string xrefs + call graph |

- No runtime / dynamic analysis — the target was **never executed**.
- GCC hot/cold splitting and inlining blur some function boundaries (flagged in
  the inventory).
- All addresses are **linked** addresses (base 0); the runtime load base differs.
- `inspect_binary_layout` could not emulate the PLT (Unicorn needed 1 GB), so
  PLT/GOT facts come from the static disassembly instead.

## Security notes

- **Attack surface** is the classic netcat one: raw socket I/O, name resolution,
  proxy negotiation, UNIX sockets, `-F` fd passing. Hardened build (RELRO + NX +
  canary + CET) and safe-string APIs reduce the usual memory-safety class.
- **Credentials**: proxy/TCP-MD5 passwords use `readpassphrase` and are wiped
  after use (`__explicit_bzero_chk`); HTTP Basic auth is encoded via `__b64_ntop`.
- **No TLS** — do not treat `nc` as a confidential transport. This matches the
  distro package, which builds out upstream's libtls paths.

---

<div align="center">

**Analysis:** [REA v6.2.0](https://github.com/morluto/rea) · Ghidra 12.1.4 ·
**Target:** `netcat-openbsd 1.234-1` (Ubuntu) ·
**License:** MIT — see [`LICENSE`](LICENSE) & [`NOTICE`](NOTICE)

</div>
