# Binary layout and hardening summary - `nc`

Produced with REA (Reverse Engineer Anything) v6.2.0.

## Identity

| Field | Value |
|---|---|
| SHA-256 | `de49cac83b4645476865e1faa39ac6c9e833baa1ea26fde02ec8045ec71a160d` |
| Size | 39,160 bytes |
| Format | ELF64, little-endian, x86-64 |
| Type | `ET_DYN` (Position-Independent Executable) |
| Entry point | file vaddr `0x5240` -> Ghidra addr `0x105240` |
| Build ID | `f8b823fa69cb2bcae5acf66b977262d7b7321755` |
| Package | `deb: netcat-openbsd 1.234-1 (amd64, ubuntu)` |
| Banner | `OpenBSD netcat (Debian patchlevel 1.234-1)` |
| Symbols | stripped (no `.symtab`); 74 dynamic symbols remain |

REA's offline ELF profile (`provider: pwntools-elf`,
`pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2`) decoded the layout without
executing the target. Deep analysis used the Ghidra 12.1.4 provider.

## Hardening (static inferences)

| Mitigation | Value |
|---|---|
| PIE | yes (`ET_DYN`, `FLAGS_1: NOW PIE`) |
| NX (non-exec stack) | yes (`PT_GNU_STACK` is RW, not RWX) |
| Executable stack | no |
| Stack canary | yes (`__stack_chk_fail` imported) |
| RELRO | Full (`PT_GNU_RELRO` covers `.got`, `BIND_NOW`) |
| CET | `IBT`, `SHSTK` (note `.note.gnu.property`) |

These are static heuristic indicators, not runtime measurements.

## Linkage

- Interpreter: `/lib64/ld-linux-x86-64.so.2`
- `NEEDED`: `libbsd.so.0`, `libresolv.so.2`, `libc.so.6`
- No bundled TLS: the binary does **not** link `libtls`/libssl, so the
  upstream TLS code paths are compiled out (matches Debian/Ubuntu
  `netcat-openbsd`).
- 70 external functions imported across `GLIBC_2.2.5` .. `GLIBC_2.38`,
  `LIBBSD_0.2`.

Notable imports that reveal capability: `socket`, `connect`, `bind`, `listen`,
`accept4`, `select`, `poll`, `getsockopt`/`setsockopt`, `getaddrinfo`/
`getnameinfo`/`getservbyname`/`getservbyport`, `recvfrom`/`sendmsg`,
`fcntl`, `poll`, `readpassphrase`, `arc4random_uniform`, `strtonum`,
`strlcpy`/`strlcat`, `__b64_ntop` (SOCKS/HTTP proxy auth encoding),
`readpassphrase` (proxy password / TCP MD5SIG password prompt).

## Sections / segments

`.text` = `0x44c7` bytes (`0x2840`..`0x6d07`), `.rodata` = `0x1440` bytes,
`.plt` + `.plt.sec` + `.plt.got` for the 70 imports, Full-RELRO GOT.
14 program headers, 30 section headers.

## Reliability notes

- `inspect_binary_layout` reported `Could not populate PLT: Cannot allocate 1GB
  memory to run Unicorn Engine` - a benign environment limitation. PLT/GOT
  mapping is recovered from the static disassembly instead.
- Ghidra analysis used the default auto-analyzer; `FUN_*` names are assigned by
  REA/Ghidra, and the role column in `function_inventory.md` is inferred from
  string references and the call graph (see methodology in `results.txt`).
