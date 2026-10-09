# files/ index

Reverse-engineering artifacts for `/home/illy/REA/nc`, produced with
**REA (Reverse Engineer Anything) v6.2.0**.

## Reports

| File | Description |
|---|---|
| `layout_summary.md` | Human-readable binary layout + hardening summary |
| `function_inventory.md` | Function table (address, role, callers/callees, evidence strings) |
| `function_inventory.tsv` | Same table, tab-separated |
| `decompiled_functions.c` | Ghidra pseudocode for `main` + all helpers (combined) |

## REA Evidence (JSON, canonical envelopes)

| File | REA operation / provider |
|---|---|
| `rea-inspect-binary-layout.json` | `inspect_binary_layout` (pwntools-elf provider, offline) |
| `rea-analyze.json` | `analyze` overview (Ghidra 12.1.4) |
| `rea-search-procedures.json` | `search --kind procedures` (236 procedures) |
| `rea-search-strings.json` | `search --kind strings` (247 strings) |
| `rea-trace-version.json` | `trace` for the version banner |
| `rea-decompile-main.json` | `decompile 0x102a90` (main) |
| `rea-decompile-0x*.json` | `decompile` for each helper function |
| `rea_snapshot.json` | REA analysis snapshot (reusable cache) |

## Raw tool outputs (cross-checks)

| File | Tool |
|---|---|
| `readelf_all.txt` | `readelf -a` |
| `readelf_dynsyms.txt` | `readelf --dyn-syms -W` |
| `nm_dynsym.txt` | `nm -D` |
| `objdump_dynsym.txt` | `objdump -T` |
| `objdump_disasm_intel.txt` | `objdump -d -M intel` |
| `objdump_disasm_att.txt` | `objdump -d` (AT&T) |
| `strings.txt` | `strings -a -n 4` |

## Reproducibility

| File | Description |
|---|---|
| `build_inventory.py` | Regenerates `function_inventory.*` from the JSON artifacts |
| `function_addresses.txt` | Address list fed to the decompile batch |
| `reference/upstream_openbsd_netcat.c` | Upstream OpenBSD `netcat.c` used only for symbol correlation |
| `reference/upstream_openbsd_atomicio.c` | Upstream OpenBSD `atomicio.c` (reference) |

> The `reference/` sources are **not** part of the target binary. They were used
> as a naming cross-check and are clearly marked as historical reference.
