# nc function inventory (Ghidra via REA)

Image base 0x100000. Addresses below are Ghidra analysis addresses (file vaddr + 0x100000).

| Ghidra addr | file vaddr | role (inferred) | kind | calls | called by |
|---|---|---|---|---|---|
| 0x00102020 | 0x02020 | PLT0 / dynamic resolver stub (calls through GOT[1]) | plt-stub | 0x102020 | 0x102020 |
| 0x00102840 | 0x02840 | cold error-path fragment: 'proxy read'/'proxy read too long' | main cold | 0x102840 | 0x102840 |
| 0x00102866 | 0x02866 | cold fragment: port/service parse errors | strtoport cold | 0x102866 | 0x102866 |
| 0x00102895 | 0x02895 | set_common_sockopts: TTL/ToS/min-TTL/IPv6 hop + TCP buffer sizes | helper | 0x102895, 0x1055b0 | 0x102895, 0x1055b0 |
| 0x0010293b | 0x0293b | remote_connect hot path (connect + 'timed out') | remote_connect | 0x10293b, 0x1055b0 | 0x10293b |
| 0x00102a32 | 0x02a32 | cold write-error fragment ('write failed (%zu/2)') | writep cold | 0x102a32, 0x105340, 0x105b40, 0x106120 | 0x102a32, 0x106120 |
| 0x00102a48 | 0x02a48 | cold read/write error fragment ('Write Error!','polling error') | main cold | 0x102a48, 0x105340, 0x105b40, 0x106120 | 0x102a48 |
| 0x00102a6e | 0x02a6e | cold getnameinfo wrapper | helper cold | 0x102a6e | 0x102a6e |
| 0x00102a90 | 0x02a90 | main() - option parsing, proxy setup (SOCKS4/4A/5 + HTTP CONNECT), listen/connect dispatch | main | 0x102a90, 0x105340, 0x105440, 0x1054d0, 0x105510, 0x1055b0, 0x1059d0, 0x105bb0, 0x105c60, 0x106300, 0x106b00, 0x106c20 | 0x102a90 |
| 0x00105240 | 0x05240 | _start / entry (passes main to __libc_start_main) | entry | - | - |
| 0x00105270 | 0x05270 | compiler-generated empty trampoline | trampoline | 0x105270 | 0x105270 |
| 0x001052a0 | 0x052a0 | compiler-generated empty trampoline | trampoline | 0x1052a0 | 0x1052a0 |
| 0x00105330 | 0x05330 | exit(0) thunk | thunk | 0x105330 | 0x105330 |
| 0x00105340 | 0x05340 | atomicio() - retry read/write on EINTR/EAGAIN with poll | atomicio | 0x105340 | 0x102a90, 0x106300, 0x102a48, 0x102a32, 0x105340, 0x106120, 0x105440 |
| 0x00105440 | 0x05440 | proxy response line reader (read until LF, 1024 cap) | proxy helper | 0x105340, 0x105440 | 0x102a90, 0x105440 |
| 0x001054d0 | 0x054d0 | usage() - prints short usage and exits | usage | 0x1054d0 | 0x102a90, 0x1054d0 |
| 0x00105510 | 0x05510 | strtoport() - numeric port or getservbyname lookup | strtoport | 0x105510 | 0x102a90, 0x105510 |
| 0x001055b0 | 0x055b0 | socket-option/connect helper used by connect + listen paths | helper | 0x102895, 0x1055b0 | 0x102a90, 0x10293b, 0x102895, 0x1055b0, 0x105c60 |
| 0x001059d0 | 0x059d0 | getaddrinfo -> sockaddr_storage resolver helper | resolver | 0x1059d0 | 0x102a90, 0x1059d0 |
| 0x00105b40 | 0x05b40 | fillbuf() - read into buffer, EAGAIN/EINTR aware | fillbuf | 0x105b40 | 0x106300, 0x102a48, 0x102a32, 0x105b40 |
| 0x00105bb0 | 0x05bb0 | UNIX sockaddr builder (handles abstract '@' paths) | unix addr | 0x105bb0 | 0x102a90, 0x105bb0, 0x106c20 |
| 0x00105c60 | 0x05c60 | remote_connect() - connect w/ timeout, verbose getnameinfo, minttl check | remote_connect | 0x1055b0, 0x105c60 | 0x102a90, 0x105c60 |
| 0x00106120 | 0x06120 | writep() - write with -C CRLF translation and -q delay | writep | 0x102a32, 0x105340, 0x106120 | 0x106300, 0x102a48, 0x102a32, 0x106120 |
| 0x00106300 | 0x06300 | readwrite() - main poll loops over stdin/stdout/net (16KB buffers) | readwrite | 0x105340, 0x105b40, 0x106120, 0x106300 | 0x102a90, 0x106300 |
| 0x00106b00 | 0x06b00 | report_sock() - '%s on %s %s' verbose reporting | report_sock | 0x106b00 | 0x102a90, 0x106b00, 0x106c20 |
| 0x00106c20 | 0x06c20 | unix_bind() - build UNIX addr, socket/bind (abstract-aware) | unix_bind | 0x105bb0, 0x106b00, 0x106c20 | 0x102a90, 0x106c20 |
| 0x00106d08 | 0x06d08 | _fini / DT_FINI | fini | - | - |

## Evidence strings referenced per function

