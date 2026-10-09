#!/usr/bin/env python3
"""Build function inventory for nc (netcat-openbsd 1.234-1) from REA + Ghidra artifacts."""
import json,glob,os,re,bisect

BASE=0x100000
GH=lambda a:a+BASE

roles={
 0x102020:("PLT0 / dynamic resolver stub (calls through GOT[1])","plt-stub"),
 0x102840:("cold error-path fragment: 'proxy read'/'proxy read too long'","main cold"),
 0x102866:("cold fragment: port/service parse errors","strtoport cold"),
 0x102895:("set_common_sockopts: TTL/ToS/min-TTL/IPv6 hop + TCP buffer sizes","helper"),
 0x10293b:("remote_connect hot path (connect + 'timed out')","remote_connect"),
 0x102a32:("cold write-error fragment ('write failed (%zu/2)')","writep cold"),
 0x102a48:("cold read/write error fragment ('Write Error!','polling error')","main cold"),
 0x102a6e:("cold getnameinfo wrapper","helper cold"),
 0x102a90:("main() - option parsing, proxy setup (SOCKS4/4A/5 + HTTP CONNECT), listen/connect dispatch","main"),
 0x105240:("_start / entry (passes main to __libc_start_main)","entry"),
 0x105270:("compiler-generated empty trampoline","trampoline"),
 0x1052a0:("compiler-generated empty trampoline","trampoline"),
 0x105330:("exit(0) thunk","thunk"),
 0x105340:("atomicio() - retry read/write on EINTR/EAGAIN with poll","atomicio"),
 0x105440:("proxy response line reader (read until LF, 1024 cap)","proxy helper"),
 0x1054d0:("usage() - prints short usage and exits","usage"),
 0x105510:("strtoport() - numeric port or getservbyname lookup","strtoport"),
 0x1055b0:("socket-option/connect helper used by connect + listen paths","helper"),
 0x1059d0:("getaddrinfo -> sockaddr_storage resolver helper","resolver"),
 0x105b40:("fillbuf() - read into buffer, EAGAIN/EINTR aware","fillbuf"),
 0x105bb0:("UNIX sockaddr builder (handles abstract '@' paths)","unix addr"),
 0x105c60:("remote_connect() - connect w/ timeout, verbose getnameinfo, minttl check","remote_connect"),
 0x106120:("writep() - write with -C CRLF translation and -q delay","writep"),
 0x106300:("readwrite() - main poll loops over stdin/stdout/net (16KB buffers)","readwrite"),
 0x106b00:("report_sock() - '%s on %s %s' verbose reporting","report_sock"),
 0x106c20:("unix_bind() - build UNIX addr, socket/bind (abstract-aware)","unix_bind"),
 0x106d08:("_fini / DT_FINI","fini"),
}

# load decompiles for call graph
def code_of(path):
    try: return json.load(open(path))['normalized_result']
    except Exception: return ""
addr_map={0x102a90:'files/rea-decompile-main.json'}
for f in glob.glob('files/rea-decompile-0x*.json'):
    a=int(re.search(r'0x[0-9a-f]+',os.path.basename(f)).group(0),16)
    addr_map[a]=f
callees={}
for a,f in addr_map.items():
    c=code_of(f)
    callees[a]=sorted({int(x,16) for x in re.findall(r'FUN_([0-9a-f]{6,})\(',c) if int(x,16)>=0x100000})
callers={a:[] for a in addr_map}
for a,cs in callees.items():
    for c in cs: callers.setdefault(c,[]).append(a)

# string refs per function
strs={}
for x in json.load(open('files/rea-search-strings.json'))['normalized_result']:
    m=re.search(r'0x([0-9a-fA-F]+)$',x['address'])
    if m:
        v=int(m.group(1),16)
        strs[v-BASE if v>=BASE else v]=x['value']
starts=sorted(strs)
def lookup(a):
    i=bisect.bisect_right(starts,a)-1
    if i>=0 and a-starts[i]<200: return strs[starts[i]]
    return None
# function bounds for attribution
bounds=sorted(roles)
def fn_of(a):
    i=bisect.bisect_right(bounds,a)-1
    return bounds[i] if i>=0 else None
srefs={}
for line in open('files/objdump_disasm_intel.txt'):
    m=re.match(r'\s*([0-9a-f]+):\s',line)
    if not m: continue
    a=int(m.group(1),16)
    m2=re.search(r'#\s*([0-9a-f]+)',line)
    if not m2: continue
    t=int(m2.group(1),16)
    if 0x7000<=t<0x8500:
        s=lookup(t)
        if s: srefs.setdefault(fn_of(a),set()).add(s)

rows=[]
for a in bounds:
    role,kind=roles[a]
    cs=callees.get(a,[])
    cl=callers.get(a,[])
    refs=sorted(srefs.get(a,[]))
    tag=""
    if kind=="main": tag="10086 B (non-contiguous, 15 ranges)"
    elif len(refs)>=0: tag=""
    rows.append((a,role,kind,cs,cl,refs))

with open('files/function_inventory.md','w') as w:
    w.write("# nc function inventory (Ghidra via REA)\n\n")
    w.write(f"Image base 0x{BASE:x}. Addresses below are Ghidra analysis addresses (file vaddr + 0x{BASE:x}).\n\n")
    w.write("| Ghidra addr | file vaddr | role (inferred) | kind | calls | called by |\n")
    w.write("|---|---|---|---|---|---|\n")
    for a,role,kind,cs,cl,refs in rows:
        w.write(f"| 0x{a:08x} | 0x{a-BASE:05x} | {role} | {kind} | "
                f"{', '.join('0x%x'%c for c in cs) or '-'} | {', '.join('0x%x'%c for c in cl) or '-'} |\n")
    w.write("\n## Evidence strings referenced per function\n\n")
    for a,role,kind,cs,cl,refs in rows:
        if refs:
            w.write(f"### 0x{a:08x} - {role}\n\n")
            for s in refs: w.write(f"- `{s}`\n")
            w.write("\n")
with open('files/function_inventory.tsv','w') as w:
    w.write("ghidra_addr\tfile_vaddr\tkind\trole\tcalls\tcalled_by\tevidence_strings\n")
    for a,role,kind,cs,cl,refs in rows:
        w.write("\t".join([f"0x{a:08x}",f"0x{a-BASE:x}",kind,role,
            ";".join('0x%x'%c for c in cs) or "-",";".join('0x%x'%c for c in cl) or "-",
            " | ".join(refs)]) +"\n")
print("wrote files/function_inventory.md and .tsv with", len(rows), "entries")
