#!/usr/bin/env python3
"""Generic 4-Gate workset acquisition & widening pipeline for ATField samples.

Phases per sample:
  prepare  : edger8r + compile Enclave_t.c, sample.c, assemble enclave_4gate.o /
             enclave_prod.o, link&sign ProfileElf (empty0, 4gate) stubs.
  capture  : run host_4gate (ipi_mask=7, cold TLB at each gate) for each capture
             round; collect P_S3 sets; plus one alt_rsp=1 run for Gate-B rsp.
  widen    : P_dyn -> effect map via PT_LOAD flags; closures:
               (a) STT_OBJECT span closure
               (b) dlmalloc physical chunk walk (heap span closure + fnptr scan)
               (c) stack closure (.stack_sizes max depth below Gate-B rsp page;
                   upward to VMA top within observed write window)
               (d) static call-reachability closure pruned at noreturn sinks,
                   seeded from P_dyn code pages + fnptr targets + endbr64 sites
  emit     : generate pretouch_<tag>.s, link+sign 4gate + prod variants.
  verify   : host_kat on FinalElf; host_4gate ipi_mask=3 on 4gate variant
             (expect empty S3) for capture rounds AND hidden-patch rounds.

Sample-agnostic: all per-sample knobs live in SAMPLES below.
"""
import os, re, struct, subprocess, sys, json, glob

BASE      = "/home/meandssh/ATField/product/build/workset-haji1"
REPO      = "/home/meandssh/ATField/product"
ACQ       = f"{BASE}/acquire"
CLANG_BIN = "/nix/store/iss8m6q9gn36ml28g76c2038xl2v5pzc-clang-wrapper-22.1.8/bin"
LLVM_BIN  = "/nix/store/m6vp8j0vpzlgk6ljxk3s3p3j5h3482h1-llvm-22.1.8/bin"
LLD_BIN   = "/nix/store/fv53kz6bwf3bkpj4qini6cfq5njl4xvn-lld-22.1.8/bin"
SGX_SDK   = "/nix/store/5fkrv05k57fqrjx54f5abzhvh0kr9j0l-sgx-sdk-2.29.100.1"
SGX_PSW   = "/nix/store/idzqgxj50m3zd5h39yh5gij3iddzii3a-sgx-psw-2.29.100.1"
SGX_SSL   = "/home/meandssh/.omp/wt/sgxssl-build/hw/src/Linux/package"
CLANG_RES = "/nix/store/iss8m6q9gn36ml28g76c2038xl2v5pzc-clang-wrapper-22.1.8/resource-root"
FP_PT_O   = "/home/meandssh/ATField/product/real/build/fp-pt.o"
GATE_PAGE = 0x049000            # dedicated gate helper page (0x3000 in 16KiB pretouch)
PRETOUCH_SIZE = 0x4000          # fixed 16 KiB reservation -> zero RVA drift
def control_pages(dumps_dir):
    """Pages in the 0x3000-byte rw-s TCS VMA (and any same-size rw-s twin VMA)
    are SGX control structures: they carry no workload state and must never be
    pretouch targets (nor counted in P_dyn)."""
    out = set()
    meta_p = f"{dumps_dir}/meta.txt"
    if not os.path.exists(meta_p):
        return out
    for mm in re.finditer(r"VMA 0x([0-9a-f]+) 0x([0-9a-f]+) (\S+)",
                          open(meta_p).read()):
        lo, hi, pr = int(mm.group(1), 16), int(mm.group(2), 16), mm.group(3)
        if hi - lo == 0x3000 and pr == "rw-s":
            out.update(range(lo, hi, 0x1000))
    return out

env = os.environ.copy()
env["PATH"] = f"{CLANG_BIN}:{LLVM_BIN}:{LLD_BIN}:" + env.get("PATH", "")

def run(cmd, cwd=BASE, logf=None):
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env, text=True, capture_output=True)
    if logf:
        logf.write(f"$ {' '.join(str(c) for c in cmd)}\n{r.stdout}{r.stderr}\n")
    if r.returncode != 0:
        raise RuntimeError(f"FAILED: {' '.join(str(c) for c in cmd)}\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
    return r.stdout

# ---------------------------------------------------------------- sample cfgs
def sample_cfg(name):
    sdir = f"{REPO}/bench/sample/{name}"
    common_inc = [f"-I{REPO}/bench/common", f"-I{sdir}"]
    edl_search = ["--search-path", f"{SGX_SDK}/include",
                  "--search-path", f"{REPO}/bench/common",
                  "--search-path", sdir]
    cfg = {
        "name": name,
        "sdir": sdir,
        "edl": f"{sdir}/Enclave.edl",
        "lds": f"{sdir}/Enclave.lds",
        "config_aex0": None,  # patched below
        "config_aex1": f"{sdir}/Enclave.config.xml",
        "sample_inc": common_inc,
        "edl_search": edl_search,
        "trusted_libs": [],
        "capture_rounds": [0, 1],
        "hidden_rounds": [],  # [{"round":2,"patch_file":path}]
        "stack_min_size": None,
        "extra_host_cflags": [],
    }
    if name == "openssl-aes-256-gcm":
        cfg["sample_inc"].append(f"-I{SGX_SSL}/include")
        cfg["edl_search"] += ["--search-path", f"{SGX_SSL}/include"]
        cfg["trusted_libs"] = [
            "-Wl,--whole-archive", f"{SGX_SSL}/lib64/libsgx_tsgxssl.a", "-Wl,--no-whole-archive",
            f"{SGX_SSL}/lib64/libsgx_tsgxssl_crypto.a"]
        cfg["hidden_rounds"] = [{"round": 0, "patch": {"payload_size": 17},
                                 "note": "len=17 exercises len%16!=0 tail path"}]
    elif name == "wolfssl-pbkdf2-sha256":
        wolf_root = f"{BASE}/libs/wolfssl-ac01707f552c611fbd135cc723b2682b3e7f80f2"
        cfg["sample_inc"].append(f"-I{wolf_root}")
        cfg["compile_defs"] = ["-DWOLFSSL_USER_SETTINGS"]
        cfg["trusted_libs"] = [f"{BASE}/libs/libwolfssl-sgx.a"]
    elif name == "yescrypt-kdf-rw":
        yes_root = f"{BASE}/libs/yescrypt-sgx-1.1.0"
        cfg["sample_inc"].append(f"-I{yes_root}")
        cfg["trusted_libs"] = [f"{BASE}/libs/libyescrypt-sgx.a"]
    elif name in ("secret-network", "oasis-keymanager", "mobilecoin-consensus", "intel-qe3"):
        sdir = f"{BASE}/real_adapters/{name}"
        cfg["sdir"] = sdir
        cfg["edl"] = f"{sdir}/Enclave.edl"
        cfg["lds"] = f"{sdir}/Enclave.lds"
        cfg["config_aex1"] = f"{sdir}/Enclave.config.xml"
        cfg["sample_inc"] = [f"-I{REPO}/bench/common", f"-I{sdir}"]
        cfg["edl_search"] = ["--search-path", f"{SGX_SDK}/include",
                             "--search-path", f"{REPO}/bench/common",
                             "--search-path", sdir]
        cfg["capture_rounds"] = [0]
        if name == "intel-qe3":
            cfg["trusted_libs"] = [f"{REPO}/real/build/intel-qe3.o"]
        else:
            rname = name.replace("-", "_")
            cfg["trusted_libs"] = [f"{REPO}/real/target/x86_64-unknown-linux-gnu/release/libreal_{rname}.a"]
    else:
        raise SystemExit(f"unknown sample {name}")
    return cfg

C_FLAGS = ["-m64", "-O3", "-fstack-size-section",
           f"-I{SGX_SDK}/include", f"-I{SGX_SDK}/include/tlibc",
           "-nostdinc", "-ffreestanding", "-fvisibility=hidden", "-fpie",
           "-fno-strict-aliasing", "-fwrapv", "-fno-delete-null-pointer-checks",
           "-fzero-call-used-regs=used-gpr", "-fstack-protector-strong",
           "-ftrivial-auto-var-init=pattern", "-ffunction-sections", "-fdata-sections"]

GATE_HELPER_TAIL = """
.org 0x3000, 0xcc
.globl __gate_A_entry
.hidden __gate_A_entry
__gate_A_entry:
    mfence
    lfence
    movabsq $0x700000000000, %r10
    cmpl $1, 4(%r10)
    jne __after_gate_A
    movl $10, (%r10)
1:
    incl 24(%r10)
    movl (%r10), %eax
    cmpl $20, %eax
    je 2f
    pause
    jmp 1b
2:
    mfence
    lfence
    jmp __after_gate_A

.p2align 4, 0xcc
.globl __gate_B_entry
.hidden __gate_B_entry
__gate_B_entry:
    mfence
    lfence
    movabsq $0x700000000000, %r10
    cmpl $1, 4(%r10)
    jne __atfield_pretouch_2
    movl $30, (%r10)
1:
    incl 24(%r10)
    movl (%r10), %eax
    cmpl $40, %eax
    je 2f
    pause
    jmp 1b
2:
    mfence
    lfence
    cmpq $1, 8(%r10)
    jne 3f
    movq %rsp, 16(%r10)
    leaq 0xff0(%r10), %rsp
3:
    jmp __atfield_pretouch_2

.p2align 4, 0xcc
.globl __atfield_after_marker_2
.hidden __atfield_after_marker_2
__atfield_after_marker_2:
    mfence
    lfence
    movabsq $0x700000000000, %r10
    cmpq $1, 8(%r10)
    jne 3f
    movq 16(%r10), %rsp
3:
    cmpl $1, 4(%r10)
    jne __after_gate_C
    movl $50, (%r10)
1:
    incl 24(%r10)
    movl (%r10), %eax
    cmpl $60, %eax
    je 2f
    pause
    jmp 1b
2:
    mfence
    lfence
    jmp __after_gate_C

.p2align 4, 0xcc
.globl __gate_D_entry
.hidden __gate_D_entry
__gate_D_entry:
    mfence
    lfence
    movabsq $0x700000000000, %r10
    cmpl $1, 4(%r10)
    jne __after_gate_D
    movl $70, (%r10)
1:
    incl 24(%r10)
    movl (%r10), %eax
    cmpl $80, %eax
    je 2f
    pause
    jmp 1b
2:
    mfence
    lfence
    jmp __after_gate_D

.org 0x4000, 0xcc
"""

# ---------------------------------------------------------------- elf parsing
def parse_elf(path):
    """Return dict: pt_loads, sections {name:(addr,off,size,flags)}, syms."""
    b = open(path, "rb").read()
    assert b[:4] == b"\x7fELF" and b[4] == 2
    e_phoff = struct.unpack_from("<Q", b, 32)[0]
    e_phentsize = struct.unpack_from("<H", b, 54)[0]
    e_phnum = struct.unpack_from("<H", b, 56)[0]
    e_shoff = struct.unpack_from("<Q", b, 40)[0]
    e_shentsize = struct.unpack_from("<H", b, 58)[0]
    e_shnum = struct.unpack_from("<H", b, 60)[0]
    e_shstrndx = struct.unpack_from("<H", b, 62)[0]
    pt_loads = []
    for i in range(e_phnum):
        p = struct.unpack_from("<IIQQQQQQ", b, e_phoff + i * e_phentsize)
        if p[0] == 1:
            pt_loads.append({"vaddr": p[3], "memsz": p[6], "off": p[2], "filesz": p[5], "flags": p[1]})
    shdrs = []
    for i in range(e_shnum):
        shdrs.append(struct.unpack_from("<IIQQQQIIQQ", b, e_shoff + i * e_shentsize))
    shstr_off = shdrs[e_shstrndx][4]
    def sname(o):
        return b[shstr_off + o: b.index(b"\x00", shstr_off + o)].decode()
    sections = {}
    for sh in shdrs:
        name, typ, flags, addr, off, size = sh[0], sh[1], sh[2], sh[3], sh[4], sh[5]
        sections[sname(name)] = {"addr": addr, "off": off, "size": size,
                                 "flags": flags, "type": typ, "link": sh[6]}
    syms = []
    if ".symtab" in sections:
        st = sections[".symtab"]
        strt = shdrs[st["link"]]
        for o in range(st["off"], st["off"] + st["size"], 24):
            nm, info, other, shndx, val, sz = struct.unpack_from("<IBBHQQ", b, o)
            name_off = strt[4] + nm
            name_b = b[name_off: b.index(b"\x00", name_off)].decode(errors="replace")
            syms.append({"name": name_b, "type": info & 0xf, "bind": info >> 4,
                         "shndx": shndx, "value": val, "size": sz})
    return {"bytes": b, "pt_loads": pt_loads, "sections": sections,
            "syms": syms, "nsec": e_shnum}

def parse_stack_sizes(elf):
    """{.stack_sizes}: sequence of {u64 func_addr; u8 frame_bytes}."""
    out = {}
    if ".stack_sizes" not in elf["sections"]:
        return out
    s = elf["sections"][".stack_sizes"]
    b = elf["bytes"]
    for o in range(s["off"], s["off"] + s["size"], 9):
        addr = struct.unpack_from("<Q", b, o)[0]
        out[addr] = b[o + 8]
    return out

def parse_disasm(so_path, elf, llvm_objdump):
    """Returns (call_edges:[(src_rva,dst_rva)], indcall_rvas:set, func_by_name)."""
    txt = run([llvm_objdump, "-d", "--no-show-raw-insn", so_path])
    edges, ind = [], set()
    cur = None
    for m in re.finditer(r"^\s*([0-9a-f]+):\s+(callq?|jmpq?|je|jne|ja|jae|jb|jbe|jl|jle|jg|jge|js|jns|jp|jnp|jo|jno|loop[a-z]*)\s+\*?[^\n]*$",
                         txt, re.M):
        insn_rva = int(m.group(1), 16)
        rest = m.group(0)
        if re.search(r"callq?\s+\*", rest):
            ind.add(insn_rva)
        elif "call" in rest:
            tm = re.search(r"(0x[0-9a-f]+)\s*<([^>]+)>", rest)
            if tm:
                edges.append((insn_rva, int(tm.group(1), 16)))
    return edges, ind

def endbr64_sites(elf):
    """RVAs of every f3 0f 1e fa in file-mapped X PT_LOAD ranges."""
    sites = set()
    b = elf["bytes"]
    for l in elf["pt_loads"]:
        if not (l["flags"] & 1):
            continue
        lo, hi = l["off"], l["off"] + l["filesz"]
        i = b.find(b"\xf3\x0f\x1e\xfa", lo)
        while i != -1 and i + 3 < hi:
            sites.add(l["vaddr"] + (i - l["off"]))
            i = b.find(b"\xf3\x0f\x1e\xfa", i + 1)
    return sites

def vma_of(vma_list, rva):
    for lo, hi, perm in vma_list:
        if lo <= rva < hi:
            return (lo, hi, perm)
    return None

# ---------------------------------------------------------------- build phase
def prepare(cfg, logf):
    wd = f"{ACQ}/{cfg['name']}"
    os.makedirs(f"{wd}/src", exist_ok=True)
    os.makedirs(f"{wd}/bin", exist_ok=True)
    os.makedirs(f"{wd}/signed", exist_ok=True)
    os.makedirs(f"{wd}/dumps", exist_ok=True)
    os.makedirs(f"{wd}/logs", exist_ok=True)
    # edger8r
    run([f"{SGX_SDK}/bin/x64/sgx_edger8r", "--trusted", cfg["edl"],
         "--trusted-dir", f"{wd}/src", *cfg["edl_search"]], logf=logf)
    run([f"{SGX_SDK}/bin/x64/sgx_edger8r", "--untrusted", cfg["edl"],
         "--untrusted-dir", f"{wd}/src", *cfg["edl_search"]], logf=logf)
    # aex0 config copy
    # compile objects
    defs = cfg.get("compile_defs", [])
    run([f"{CLANG_BIN}/clang", *C_FLAGS, *defs, *cfg["sample_inc"],
         "-c", f"{wd}/src/Enclave_t.c", "-o", f"{wd}/src/Enclave_t.o"], logf=logf)
    run([f"{CLANG_BIN}/clang", *C_FLAGS, *defs, *cfg["sample_inc"],
         "-c", f"{cfg['sdir']}/sample.c", "-o", f"{wd}/src/sample.o"], logf=logf)
    # enclave_prod: compile to .s, rewrite `callq __atfield_marker_2` ->
    # `jmp __atfield_pretouch_2` + `__atfield_after_marker_2:` label, then assemble
    run([f"{CLANG_BIN}/clang", *C_FLAGS, *defs, *cfg["sample_inc"], f"-I{BASE}/src",
         "-S", f"{BASE}/src/enclave_prod.c", "-o", f"{wd}/src/enclave_prod_raw.s"], logf=logf)
    raw_s = open(f"{wd}/src/enclave_prod_raw.s").read().splitlines()
    out_s, n_marker = [], 0
    for l in raw_s:
        ls = l.strip()
        if ls.startswith("callq") and "__atfield_marker_2" in ls:
            out_s += ["\tjmp\t__atfield_pretouch_2",
                      "\t.globl\t__atfield_after_marker_2",
                      "\t.hidden\t__atfield_after_marker_2",
                      "__atfield_after_marker_2:"]
            n_marker += 1
        else:
            out_s.append(l)
    assert n_marker == 1, f"expected exactly 1 callq __atfield_marker_2, got {n_marker}"
    open(f"{wd}/src/enclave_prod.s", "w").write("\n".join(out_s) + "\n")
    run([f"{CLANG_BIN}/clang", "-c", f"{wd}/src/enclave_prod.s", "-o", f"{wd}/src/enclave_prod.o"], logf=logf)
    run([f"{CLANG_BIN}/clang", "-c", f"{BASE}/src/enclave_4gate.s", "-o", f"{wd}/src/enclave_4gate.o"], logf=logf)
    # host binaries
    run([f"{CLANG_BIN}/clang", "-O2", "-DLIBSGXSTEP_SILENT=1",
         f"-I{SGX_SDK}/include", "-I/home/meandssh/ATField/TLBlurSgx-TLBlur/sgx-step",
         f"-I{wd}/src", f"{BASE}/src/host_4gate.c", f"{wd}/src/Enclave_u.c", FP_PT_O,
         f"-L{SGX_PSW}/lib", f"-L{SGX_SDK}/lib64", f"-L{SGX_SSL}/lib64",
         "-lsgx_urts", "-lsgx_usgxssl", "-lpthread", "-ldl",
         f"-Wl,-rpath,{SGX_PSW}/lib", "-o", f"{wd}/bin/host_4gate"], logf=logf)
    run([f"{CLANG_BIN}/clang", "-O2", f"-I{SGX_SDK}/include", f"-I{wd}/src",
         f"{BASE}/src/host_scan.c", f"{wd}/src/Enclave_u.c",
         f"-L{SGX_PSW}/lib", f"-L{SGX_SDK}/lib64", f"-L{SGX_SSL}/lib64",
         "-lsgx_urts", "-lsgx_usgxssl", "-lpthread", "-ldl",
         f"-Wl,-rpath,{SGX_PSW}/lib", "-o", f"{wd}/bin/host_scan"], logf=logf)
    run([f"{CLANG_BIN}/clang", "-O2", f"-I{SGX_SDK}/include", f"-I{wd}/src",
         f"{BASE}/src/host_kat.c", f"{wd}/src/Enclave_u.c", f"{cfg['sdir']}/answer.c",
         f"-L{SGX_PSW}/lib", f"-L{SGX_SDK}/lib64", f"-L{SGX_SSL}/lib64",
         "-lsgx_urts", "-lsgx_usgxssl", "-lpthread", "-ldl",
         f"-Wl,-rpath,{SGX_PSW}/lib", "-o", f"{wd}/bin/host_kat"], logf=logf)
    # hidden-round patch files (resolve symbol -> rva once stub.so exists)
    return wd

def link_variant(cfg, wd, tag, page_eff_map, is_4gate, elf, sign_cfg, logf, emit_relocs=False):
    b = elf["bytes"]
    def valid_mapped_first_byte(page_rva):
        for l in elf["pt_loads"]:
            lo = max(page_rva, l["vaddr"]); hi = min(page_rva + 0x1000, l["vaddr"] + l["memsz"])
            if lo < hi: return lo
        return page_rva
    def lowest_c3(page_rva):
        for l in elf["pt_loads"]:
            lo = max(page_rva, l["vaddr"]); hi = min(page_rva + 0x1000, l["vaddr"] + l["filesz"])
            if lo < hi:
                for rva in range(lo, hi):
                    if b[l["off"] + (rva - l["vaddr"])] == 0xC3: return rva
        raise RuntimeError(f"no 0xC3 on page 0x{page_rva:06x}")
    lines = ['.section .atfield_pretouch, "ax", @progbits', '.p2align 12',
             '.globl __atfield_pretouch_2', '.hidden __atfield_pretouch_2',
             '__atfield_pretouch_2:']
    for page_rva in sorted(page_eff_map):
        eff = page_eff_map[page_rva]
        if "X" in eff and "W" in eff:
            raise RuntimeError(f"X+W conflict on page 0x{page_rva:06x}")
        if "X" in eff:
            lines.append(f"    call __ImageBase + 0x{lowest_c3(page_rva):x}")
        if "W" in eff:
            d = valid_mapped_first_byte(page_rva)
            lines.append(f"    lock orb $0, (__ImageBase + 0x{d:x})(%rip)")
        elif "R" in eff:
            d = valid_mapped_first_byte(page_rva)
            lines.append(f"    movb (__ImageBase + 0x{d:x})(%rip), %al")
    lines.append("    lfence")
    lines.append("    jmp __atfield_after_marker_2")
    lines.append(GATE_HELPER_TAIL if is_4gate else ".org 0x4000, 0xcc")
    s_path = f"{wd}/src/pretouch_{tag}.s"
    open(s_path, "w").write("\n".join(lines) + "\n")
    o_path = f"{wd}/src/pretouch_{tag}.o"
    run([f"{CLANG_BIN}/clang", "-c", s_path, "-o", o_path], logf=logf)
    so_path = f"{wd}/bin/{tag}.so"
    base_link = [f"{CLANG_BIN}/clang", f"-fuse-ld={LLD_BIN}/ld.lld",
                 "-Wl,-soname,enclave.so", "-Wl,-z,relro,-z,now,-z,noexecstack",
                 "-Wl,--fatal-warnings", "-Wl,--as-needed", "-Wl,--no-undefined",
                 "-Wl,--no-undefined-version", "-nostdlib", "-nodefaultlibs", "-nostartfiles",
                 "-Wl,-Bstatic", "-Wl,-Bsymbolic", "-Wl,-pie,-eenclave_entry",
                 "-Wl,--export-dynamic", "-Wl,--defsym,__ImageBase=0", "-Wl,--gc-sections",
                 *(["-Wl,--emit-relocs"] if emit_relocs else []),
                 f"-Wl,--script={BASE}/src/baseline/SgxDiscardEmbeddedBitcode.lds",
                 f"-Wl,--script={BASE}/src/pretouch.lds",
                 f"-Wl,--version-script={cfg['lds']}"]
    encl_o = f"{wd}/src/enclave_4gate.o" if is_4gate else f"{wd}/src/enclave_prod.o"
    run([*base_link, f"{wd}/src/Enclave_t.o", encl_o, f"{wd}/src/sample.o", o_path,
         "-Wl,--whole-archive", f"{SGX_SDK}/lib64/libsgx_trts.a", "-Wl,--no-whole-archive",
         "-Wl,--start-group", *cfg["trusted_libs"],
         f"{SGX_SDK}/lib64/libsgx_tstdc.a", f"{SGX_SDK}/lib64/libsgx_tcxx.a",
         f"{SGX_SDK}/lib64/libsgx_tcrypto.a", f"{SGX_SDK}/lib64/libsgx_tservice.a",
         "-Wl,--end-group", "-o", so_path], logf=logf)
    signed = f"{wd}/signed/{tag}.signed.so"
    run([f"{SGX_SDK}/bin/x64/sgx_sign", "sign", "-key", f"{BASE}/src/test_key.pem",
         "-enclave", so_path, "-out", signed, "-config", sign_cfg], logf=logf)
    verify_pretouch_elf(so_path, page_eff_map, elf, logf)
    return so_path, signed

def verify_pretouch_elf(so_path, page_eff_map, profile_elf, logf=None):
    """Post-link byte, displacement, target RVA, trailing lfence+jmp, and exact length L verifier."""
    fe = parse_elf(so_path)
    b = fe["bytes"]
    p_bytes = profile_elf["bytes"]
    sym_map = {s["name"]: s["value"] for s in fe["syms"] if s["name"]}
    if "__atfield_pretouch_2" not in sym_map or "__atfield_after_marker_2" not in sym_map:
        raise RuntimeError(f"missing boundary symbols in {so_path}")
    block_start = sym_map["__atfield_pretouch_2"]
    after_marker = sym_map["__atfield_after_marker_2"]
    sec = fe["sections"].get(".atfield_pretouch")
    if not sec:
        raise RuntimeError(f"missing .atfield_pretouch section in {so_path}")

    def rva_to_off(rva):
        for l in fe["pt_loads"]:
            if l["vaddr"] <= rva < l["vaddr"] + l["filesz"]:
                return l["off"] + (rva - l["vaddr"])
        raise RuntimeError(f"RVA 0x{rva:x} not in file-backed PT_LOAD of {so_path}")

    def valid_mapped_first_byte(page_rva):
        for l in profile_elf["pt_loads"]:
            lo = max(page_rva, l["vaddr"]); hi = min(page_rva + 0x1000, l["vaddr"] + l["memsz"])
            if lo < hi: return lo
        return page_rva

    def lowest_c3(page_rva):
        for l in profile_elf["pt_loads"]:
            lo = max(page_rva, l["vaddr"]); hi = min(page_rva + 0x1000, l["vaddr"] + l["filesz"])
            if lo < hi:
                for rva in range(lo, hi):
                    if p_bytes[l["off"] + (rva - l["vaddr"])] == 0xC3: return rva
        raise RuntimeError(f"no 0xC3 on page 0x{page_rva:06x}")

    cur_rva = block_start
    n_call = n_read = n_lock_or = 0
    sample_records = []

    for page_rva in sorted(page_eff_map):
        eff = page_eff_map[page_rva]
        if "X" in eff and "W" in eff:
            raise RuntimeError(f"X+W conflict on page 0x{page_rva:06x}")
        if "X" in eff:
            off = rva_to_off(cur_rva)
            opcode = b[off]
            rel32 = struct.unpack_from("<i", b, off + 1)[0]
            target = cur_rva + 5 + rel32
            exp_c3 = lowest_c3(page_rva)
            t_off = rva_to_off(target)
            if opcode != 0xE8 or target != exp_c3 or (target & ~0xFFF) != page_rva or b[t_off] != 0xC3:
                raise RuntimeError(f"CALL verify failed at 0x{cur_rva:x}: op=0x{opcode:02x} target=0x{target:x} exp=0x{exp_c3:x}")
            n_call += 1
            cur_rva += 5
        if "W" in eff:
            off = rva_to_off(cur_rva)
            hdr = b[off:off+3]
            disp32 = struct.unpack_from("<i", b, off + 3)[0]
            imm8 = b[off + 7]
            target = cur_rva + 8 + disp32
            exp_d = valid_mapped_first_byte(page_rva)
            if hdr != b"\xf0\x80\x0d" or imm8 != 0x00 or target != exp_d or (target & ~0xFFF) != page_rva:
                raise RuntimeError(f"LOCK OR verify failed at 0x{cur_rva:x}: bytes={b[off:off+8].hex()} target=0x{target:x} exp=0x{exp_d:x}")
            if len(sample_records) < 3 or page_rva >= 0x319000:
                sample_records.append(f"0x{cur_rva:06x}: {b[off:off+8].hex(' ')} -> disp32={disp32:+d} (0x{disp32 & 0xffffffff:08x}), next_rip=0x{cur_rva+8:06x}, target=0x{target:06x} (exp=0x{exp_d:06x})")
            n_lock_or += 1
            cur_rva += 8
        elif "R" in eff:
            off = rva_to_off(cur_rva)
            hdr = b[off:off+2]
            disp32 = struct.unpack_from("<i", b, off + 2)[0]
            target = cur_rva + 6 + disp32
            exp_d = valid_mapped_first_byte(page_rva)
            if hdr != b"\x8a\x05" or target != exp_d or (target & ~0xFFF) != page_rva:
                raise RuntimeError(f"MOVB verify failed at 0x{cur_rva:x}: bytes={b[off:off+6].hex()} target=0x{target:x} exp=0x{exp_d:x}")
            n_read += 1
            cur_rva += 6

    # Verify trailing lfence (0F AE E8, 3 bytes)
    lf_off = rva_to_off(cur_rva)
    lf_bytes = b[lf_off:lf_off+3]
    if lf_bytes != b"\x0f\xae\xe8":
        raise RuntimeError(f"LFENCE verify failed at 0x{cur_rva:x}: got {lf_bytes.hex()}")
    lf_rva = cur_rva
    cur_rva += 3

    # Verify trailing jmp rel32 (E9 <rel32>, 5 bytes) to __atfield_after_marker_2
    jmp_off = rva_to_off(cur_rva)
    jmp_op = b[jmp_off]
    jmp_rel32 = struct.unpack_from("<i", b, jmp_off + 1)[0]
    jmp_target = cur_rva + 5 + jmp_rel32
    if jmp_op != 0xE9 or jmp_target != after_marker:
        raise RuntimeError(f"JMP verify failed at 0x{cur_rva:x}: op=0x{jmp_op:02x} target=0x{jmp_target:x} exp=0x{after_marker:x}")
    jmp_rva = cur_rva
    cur_rva += 5

    actual_L = cur_rva - block_start
    expected_L = 5 * n_call + 6 * n_read + 8 * n_lock_or + 3 + 5
    if actual_L != expected_L:
        raise RuntimeError(f"Length L mismatch: actual={actual_L} expected={expected_L}")

    msg = (f"[verify_pretouch_elf] {os.path.basename(so_path)}: PASS | "
           f"block=[0x{block_start:06x}..0x{cur_rva:06x}) L={actual_L}B "
           f"(call={n_call}*5B + movb={n_read}*6B + lock_orb={n_lock_or}*8B + lfence=3B@0x{lf_rva:06x} + jmp=5B@0x{jmp_rva:06x}->0x{jmp_target:06x})")
    print(msg, flush=True)
    for rec in sample_records[:5]:
        print(f"  [lock_orb sample] {rec}", flush=True)
    if logf:
        logf.write(msg + "\n")


# ---------------------------------------------------------------- phases
def run_host4(wd, signed, round_arg, ipi_mask, alt_rsp=0, patch=None):
    args = ["sudo", "env", "ATFIELD_ENCL_CPU=45", "ATFIELD_WATCH_CPU=1", "setarch", "x86_64", "-R", f"{wd}/bin/host_4gate", signed, str(round_arg), str(ipi_mask),
            str(alt_rsp), "-", patch or "-"]
    r = subprocess.run(args, text=True, capture_output=True)
    out = r.stdout
    stages, rsp = {}, None
    for l in out.splitlines():
        if l.startswith("  S"):
            k, v = l.strip().split(":", 1)
            stages[k.split("(")[0]] = v.strip().split()
        m = re.search(r"gateB_rsp_rva=0x([0-9a-f]+)", l)
        if m: rsp = int(m.group(1), 16)
    st = re.search(r"st=(0x[0-9a-f]+) ret=(-?\d+)", out)
    return {"stages": stages, "rsp": rsp, "st": st.group(1) if st else None,
            "ret": st.group(2) if st else None, "raw": out, "rc": r.returncode,
            "stderr": r.stderr}

def capture(cfg, wd, logf, elf=None):
    """Capture P_S3 per capture_round on the empty0 4gate profile ELF."""
    profile = f"{wd}/signed/profile4gate.signed.so"
    per_round = {}
    rsp = None
    for rd in cfg["capture_rounds"]:
        res = run_host4(wd, profile, rd, 7, 0)
        per_round[rd] = res
        logf.write(res["raw"] + "\n")
        assert res["st"] == "0x0", f"capture round {rd} failed: {res['raw']}"
    # alt-rsp run to grab Gate-B rsp (pretouch runs on aux stack)
    res = run_host4(wd, profile, cfg["capture_rounds"][0], 7, 1)
    rsp = res["rsp"]
    logf.write(res["raw"] + "\n")
    p_s3 = {}
    p_s1 = {}
    ctl = control_pages(f"{wd}/dumps")
    if elf and ".atfield_pretouch" in elf["sections"]:
        pt_s = elf["sections"][".atfield_pretouch"]
        ctl.update(range(pt_s["addr"], pt_s["addr"] + pt_s["size"], 0x1000))
    if ctl:
        logf.write(f"[capture] control (TCS/SSA) pages excluded: "
                   f"{[hex(p) for p in sorted(ctl)]}\n")
    for rd, res in per_round.items():
        for item in res["stages"].get("S3", []):
            rva, eff = item.split("(")
            rva_i = int(rva, 16)
            if rva_i in ctl or rva_i == GATE_PAGE:
                continue
            e = eff.rstrip(")")
            p_s3[rva_i] = "D" if (p_s3.get(rva_i) == "D" or e == "D") else "A"
        for item in res["stages"].get("S1", []):
            rva_i = int(item.split("(")[0], 16)
            if rva_i not in ctl and rva_i != GATE_PAGE:
                p_s1[rva_i] = item.split("(")[1].rstrip(")")
    return p_s3, p_s1, rsp, per_round

def page_perm_map(elf):
    """rva-> p_flags set from PT_LOADs covering the page."""
    m = {}
    for l in elf["pt_loads"]:
        lo = l["vaddr"] & ~0xFFF
        hi = (l["vaddr"] + l["memsz"] + 0xFFF) & ~0xFFF
        for p in range(lo, hi, 0x1000):
            m.setdefault(p, 0)
            m[p] |= l["flags"]
    return m

def widen(cfg, wd, elf, p_dyn, p_s1, rsp_rva, dumps_dir, logf):
    p_dyn = set(p_dyn)
    """Return {page_rva: effect} and report lines."""
    report = []
    syms = elf["syms"]
    nsec = elf.get("nsec", 0xffff)
    real = lambda s: 0 < s["shndx"] < nsec
    funcs = {s["value"]: s for s in syms if s["type"] == 2 and real(s) and s["value"]}
    func_entries = sorted(funcs)
    func_entry_set = set(func_entries)
    objects = [s for s in syms if s["type"] == 1 and real(s) and 0 < s["size"] < 0x1000000]
    targets = set(p_dyn) - control_pages(dumps_dir) - {GATE_PAGE}
    perm = page_perm_map(elf)
    def add_t(p):
        # pages inside mapped PT_LOAD extents, or already-observed dynamic pages
        if (p in perm or p in p_dyn or vma_perm_of(p)) and p not in targets:
            targets.add(p)
            return True
        return False

    # --- VMA map from host_scan dump dir listing
    vmas = []
    meta = open(f"{dumps_dir}/meta.txt").read() if os.path.exists(f"{dumps_dir}/meta.txt") else ""
    vma_perm = {}
    for mm in re.finditer(r"VMA 0x([0-9a-f]+) 0x([0-9a-f]+) (\S+)", meta):
        vma_perm[(int(mm.group(1), 16), int(mm.group(2), 16))] = mm.group(3)
    for f in glob.glob(f"{dumps_dir}/rva_*.bin"):
        m = re.match(r"rva_([0-9a-f]+)_([0-9a-f]+)\.bin", os.path.basename(f))
        if m:
            lo, hi = int(m.group(1), 16), int(m.group(2), 16)
            vmas.append((lo, hi, f))
    def vma_perm_of(rva):
        for (lo, hi), pr in vma_perm.items():
            if lo <= rva < hi:
                return pr
        return None
    # RW VMA list from maps is unavailable here; rely on PT_LOAD flag for data effect.
    stack_vma = None
    rsp_page = rsp_rva & ~0xFFF if rsp_rva else None
    # identify stack VMA: the mapped rw VMA that contains rsp (dump files exist only
    # for VMAs with readable first page; stack pages may exist partially)

    # (a) STT_OBJECT span closure
    obj_added = set()
    for s in objects:
        lo, hi = s["value"], s["value"] + max(s["size"], 1)
        if any(p in targets for p in range(lo & ~0xFFF, (hi + 0xFFF) & ~0xFFF, 0x1000)):
            for p in range(lo & ~0xFFF, (hi + 0xFFF) & ~0xFFF, 0x1000):
                if add_t(p): obj_added.add(p)
    report.append(f"[objects] +{len(obj_added)} pages: {sorted(hex(p) for p in obj_added)}")
    import resource as _r
    report.append(f"[dbg] rss={_r.getrusage(_r.RUSAGE_SELF).ru_maxrss//1024}MB targets={len(targets)}")

    # (b) heap closure via dlmalloc physical chain (from host_scan dumps)
    heap_added, fnptr_pages = set(), {}
    # probe mstate over all dumped regions
    mstate_base = None
    heap_lo = heap_hi = None
    mb = re.search(r"BASE 0x([0-9a-f]+)", meta)
    encl_base = int(mb.group(1), 16) if mb else None
    mstate_base = None; heap_lo = heap_hi = None
    def chain_ok(heap_rva, top_rva):
        if heap_rva > top_rva:
            return False
        dump = None
        for l3, h3, f3 in vmas:
            if l3 <= heap_rva < h3:
                dump = (l3, h3, f3)
                break
        if heap_rva == top_rva:
            return True  # empty heap: no chain to validate
        if not dump:
            return False
        dl = open(dump[2], "rb").read()
        cur, hops = heap_rva, 0
        while cur < top_rva and hops < 4096:
            o = cur - dump[0]
            if o + 16 > len(dl):
                return False
            sz = struct.unpack_from("<Q", dl, o + 8)[0] & ~7
            if sz < 16 or sz > 0x1000000:
                return False
            cur += sz; hops += 1
        return cur == top_rva
    def mstate_at(m_rva):
        for l3, h3, f3 in vmas:
            if l3 <= m_rva < h3:
                d = open(f3, "rb").read()
                o = m_rva - l3
                if o + 0x30 > len(d):
                    return None
                least = struct.unpack_from("<Q", d, o + 0x18)[0]
                top = struct.unpack_from("<Q", d, o + 0x28)[0]
                if encl_base and encl_base < least <= top < encl_base + 0x4000000:
                    lr, tr = least - encl_base, top - encl_base
                    if chain_ok(lr, tr):
                        return (lr, tr)
                break  # m_rva lies in exactly one VMA
        return None
    if encl_base is not None:
        # fast path: dlmalloc's mstate is the `_gm_` (or `gm_`) symbol
        for nm in ("_gm_", "gm_", "_gm"):
            sym = next((x for x in syms if x["name"] == nm and x["value"]), None)
            if sym:
                got = mstate_at(sym["value"])
                if got:
                    mstate_base, (heap_lo, heap_hi) = sym["value"], got
                    break
        # slow fallback: scan dumped regions for a valid mstate candidate
        if mstate_base is None:
            for lo, hi, f in sorted(vmas):
                if mstate_base is not None:
                    break
                data = open(f, "rb").read()
                for off in range(0, len(data) - 0x30, 8):
                    least = struct.unpack_from("<Q", data, off + 0x18)[0]
                    top = struct.unpack_from("<Q", data, off + 0x28)[0]
                    if not (encl_base < least <= top < encl_base + 0x4000000):
                        continue
                    lr, tr = least - encl_base, top - encl_base
                    if chain_ok(lr, tr):
                        mstate_base, heap_lo, heap_hi = lo + off, lr, tr
                        break
    live_chunks = []
    if encl_base is not None and heap_lo is not None:
        dl = None
        for l3, h3, f3 in vmas:
            if l3 <= heap_lo < h3:
                dl = (l3, h3, f3)
        data = open(dl[2], "rb").read()
        cur = heap_lo; chain_exact = False
        while cur < heap_hi:
            o = cur - dl[0]
            head = struct.unpack_from("<Q", data, o + 8)[0]
            sz = head & ~7
            cinuse = (head >> 1) & 1
            if sz < 16: break
            if sz > 0x1000000 or len(live_chunks) > 65536:
                break
            if cinuse:
                live_chunks.append((cur + 16, cur + sz))
                span_lo, span_hi = cur & ~0xFFF, (cur + sz + 0xFFF) & ~0xFFF
                if span_hi - span_lo > 0x1000000:
                    break
                if any(p in targets for p in range(span_lo, span_hi, 0x1000)):
                    for q in range(span_lo, span_hi, 0x1000):
                        if add_t(q): heap_added.add(q)
            cur += sz
        chain_exact = (cur == heap_hi)
        if not chain_exact:
            report.append(f"[heap] WARNING: live walk stopped at 0x{cur:x} != "
                          f"top 0x{heap_hi:x}; discarding {len(live_chunks)} chunks")
            live_chunks = []
        report.append(f"[heap] _gm_ found at rva 0x{mstate_base:x}, "
                      f"{len(live_chunks)} live chunks in [0x{heap_lo:x},0x{heap_hi:x}), "
                      f"+{len(heap_added)} span pages: {sorted(hex(p) for p in heap_added)}")
    else:
        report.append("[heap] WARNING: mstate chain not found in dumps")

    report.append(f"[dbg] rss={_r.getrusage(_r.RUSAGE_SELF).ru_maxrss//1024}MB after-heap targets={len(targets)}")
    # (d-pre) function-pointer scan: every 8-byte word in every dumped RW/R
    # region whose value lands on a STT_FUNC entry or an endbr64 site.
    eb64 = endbr64_sites(elf)
    seen_fnptr = set()
    scan_spans = list(live_chunks)
    # object spans that intersect targets
    for s_ in objects:
        lo, hi = s_["value"], s_["value"] + max(s_["size"], 1)
        if any(pp in targets for pp in range(lo & ~0xFFF, (hi + 0xFFF) & ~0xFFF, 0x1000)):
            scan_spans.append((lo, hi))
    for slo, shi in scan_spans:
        data = None; base_rva = None
        for lo, hi, f in vmas:
            if lo <= slo < shi <= hi:
                data = open(f, "rb").read(); base_rva = lo; break
        if data is None:
            continue
        for off in range(slo - base_rva, min(shi - base_rva, len(data) - 8), 8):
            v = struct.unpack_from("<Q", data, off)[0]
            if encl_base is None or not (encl_base <= v < encl_base + 0x400000):
                continue
            rva = v - encl_base
            if rva in func_entry_set or rva in eb64:
                pg = rva & ~0xFFF
                if pg in perm and perm[pg] & 1:
                    key = (base_rva + off, rva)
                    if key not in seen_fnptr:
                        seen_fnptr.add(key)
                        fname = funcs.get(rva, {}).get("name", "?")
                        fnptr_pages[rva] = fname
    for rva, nm in sorted(fnptr_pages.items()):
        pg = rva & ~0xFFF
        add_t(pg)
        report.append(f"[fnptr] -> 0x{rva:x} <{nm}> (page 0x{pg:x})")

    report.append(f"[dbg] rss={_r.getrusage(_r.RUSAGE_SELF).ru_maxrss//1024}MB after-fnptr targets={len(targets)}")
    # (d) static reachability: direct-call edges from within target pages,
    # pruned at noreturn sinks; iterate to fixpoint.
    relocs_so = f"{wd}/bin/profile4gate_relocs.so"
    disasm_src = relocs_so if os.path.exists(relocs_so) else f"{wd}/bin/profile4gate.so"
    edges, _ind = parse_disasm(disasm_src, elf, f"{LLVM_BIN}/llvm-objdump")
    PRUNE = {"abort", "__stack_chk_fail", "field_exit", "exit"}
    def func_at(rva):
        # largest STT_FUNC entry <= rva
        lo, hi2 = 0, len(func_entries)
        while lo < hi2:
            mid = (lo + hi2) // 2
            if func_entries[mid] <= rva: lo = mid + 1
            else: hi2 = mid
        return func_entries[lo - 1] if lo else None
    callees = {}
    for src, dst in edges:
        f = func_at(src)
        if f is not None:
            callees.setdefault(src, []).append(dst)
    changed = True
    reach_added = set()
    it = 0
    while changed and it < 20:
        changed = False; it += 1
        for src, dst in edges:
            if (src & ~0xFFF) not in targets:
                continue
            f = func_at(dst)
            name = funcs.get(f, {}).get("name", "") if f else ""
            if name in PRUNE:
                continue
            pg = dst & ~0xFFF
            if pg in perm and perm[pg] & 1:
                if add_t(pg):
                    reach_added.add(pg); changed = True
    report.append(f"[reach] +{len(reach_added)} code pages via direct-call closure "
                  f"({it} fixpoint rounds): {sorted(hex(p) for p in reach_added)}")

    report.append(f"[dbg] rss={_r.getrusage(_r.RUSAGE_SELF).ru_maxrss//1024}MB after-reach targets={len(targets)}")
    # (c) stack closure
    stack_added = set()
    if rsp_page is not None:
        ss = parse_stack_sizes(elf)
        # functions on target code pages may lack .stack_sizes -> worst case page each
        UNKNOWN_FRAME = 4096
        depth = 0
        # crude path bound: sum frame sizes of unique funcs on reachable code pages
        seen_f = set()
        for src, dst in edges:
            f = func_at(src)
            if f and (src & ~0xFFF) in targets and f not in seen_f:
                seen_f.add(f)
                depth += ss.get(f, UNKNOWN_FRAME)
        depth = min(depth, 0x40000)  # cap at StackMaxSize
        lo_bound = (rsp_page - ((depth + 0xFFF) & ~0xFFF)) & ~0xFFF
        # stay inside the stack VMA (dumped region containing rsp page's vma)
        for lo, hi, f in vmas:
            if lo <= rsp_page < hi:
                lo_bound = max(lo_bound, lo)
        for p in range(lo_bound, rsp_page + 0x2000, 0x1000):
            if add_t(p): stack_added.add(p)
        report.append(f"[stack] rsp@GateB page=0x{rsp_page:x}, depth bound={depth}B, "
                      f"window [0x{lo_bound:x}..0x{rsp_page + 0x1000:x}), "
                      f"+{len(stack_added)} pages: {sorted(hex(p) for p in stack_added)}")

    # effect assignment
    dropped = sorted(p for p in targets if p not in perm and not vma_perm_of(p))
    if dropped:
        report.append(f"[drop] {len(dropped)} unmapped pages dropped: {[hex(p) for p in dropped]}")
    # Runtime VMA permissions are authoritative: PT_LOAD W flag lies for
    # RELRO pages (r--s at runtime) and misses committed heap/stack pages.
    eff_map = {}
    for p in sorted(targets):
        if p in dropped:
            continue
        vp = vma_perm_of(p)
        if vp is not None:
            if "w" in vp:
                eff_map[p] = "W"
            elif "x" in vp:
                eff_map[p] = "XR"
            else:
                eff_map[p] = "R"
            continue
        fl = perm.get(p)
        if fl is None:
            eff_map[p] = "W"
            continue
        x = bool(fl & 1); w = bool(fl & 2); r = bool(fl & 4)
        if w:
            eff_map[p] = "W"
        elif x:
            eff_map[p] = "XR"
        else:
            eff_map[p] = "R"
    for _l in report:
        print(_l, flush=True)
    return eff_map, report


def main():
    sample = sys.argv[1] if len(sys.argv) > 1 else "openssl-aes-256-gcm"
    phases = " ".join(sys.argv[2:]).replace(" ", ",").split(",") if len(sys.argv) > 2 else \
        "prepare,emit-stub,capture,widen,emit,verify".split(",")
    cfg = sample_cfg(sample)
    wd = f"{ACQ}/{sample}"
    for d in ("src", "bin", "signed", "dumps", "logs"):
        os.makedirs(f"{wd}/{d}", exist_ok=True)
    cfg["config_aex0"] = f"{wd}/src/cfg_aex0.xml"
    if not os.path.exists(cfg["config_aex0"]):
        xml = open(cfg["config_aex1"]).read()
        xml = re.sub(r"<EnableAEXNotify>\s*\d\s*</EnableAEXNotify>",
                     "<EnableAEXNotify>0</EnableAEXNotify>", xml)
        if "<EnableAEXNotify>" not in xml:
            xml = xml.replace("</EnclaveConfiguration>",
                              "  <EnableAEXNotify>0</EnableAEXNotify>\n</EnclaveConfiguration>")
        open(cfg["config_aex0"], "w").write(xml)
    logf = open(f"{wd}/logs/acquire.log", "a")

    if "prepare" in phases:
        prepare(cfg, logf)
    stub = f"{wd}/bin/profile4gate.so"

    if "emit-stub" in phases or not os.path.exists(stub):
        lines = ['.section .atfield_pretouch, "ax", @progbits', '.p2align 12',
                 '.globl __atfield_pretouch_2', '.hidden __atfield_pretouch_2',
                 '__atfield_pretouch_2:', '    jmp __atfield_after_marker_2',
                 GATE_HELPER_TAIL]
        s_path = f"{wd}/src/pretouch_profile4gate.s"
        open(s_path, "w").write("\n".join(lines) + "\n")
        o_path = f"{wd}/src/pretouch_profile4gate.o"
        run([f"{CLANG_BIN}/clang", "-c", s_path, "-o", o_path], logf=logf)
        base_link = [f"{CLANG_BIN}/clang", f"-fuse-ld={LLD_BIN}/ld.lld",
                     "-Wl,-soname,enclave.so", "-Wl,-z,relro,-z,now,-z,noexecstack",
                     "-Wl,--fatal-warnings", "-Wl,--as-needed", "-Wl,--no-undefined",
                     "-Wl,--no-undefined-version", "-nostdlib", "-nodefaultlibs", "-nostartfiles",
                     "-Wl,-Bstatic", "-Wl,-Bsymbolic", "-Wl,-pie,-eenclave_entry",
                     "-Wl,--export-dynamic", "-Wl,--defsym,__ImageBase=0", "-Wl,--gc-sections",
                     f"-Wl,--script={BASE}/src/baseline/SgxDiscardEmbeddedBitcode.lds",
                     f"-Wl,--script={BASE}/src/pretouch.lds",
                     f"-Wl,--version-script={cfg['lds']}"]
        run([*base_link, f"{wd}/src/Enclave_t.o", f"{wd}/src/enclave_4gate.o",
             f"{wd}/src/sample.o", o_path,
             "-Wl,--whole-archive", f"{SGX_SDK}/lib64/libsgx_trts.a", "-Wl,--no-whole-archive",
             "-Wl,--start-group", *cfg["trusted_libs"],
             f"{SGX_SDK}/lib64/libsgx_tstdc.a", f"{SGX_SDK}/lib64/libsgx_tcxx.a",
             f"{SGX_SDK}/lib64/libsgx_tcrypto.a", f"{SGX_SDK}/lib64/libsgx_tservice.a",
             "-Wl,--end-group", "-o", stub], logf=logf)
        run([*base_link, "-Wl,--emit-relocs", f"{wd}/src/Enclave_t.o",
             f"{wd}/src/enclave_4gate.o", f"{wd}/src/sample.o", o_path,
             "-Wl,--whole-archive", f"{SGX_SDK}/lib64/libsgx_trts.a", "-Wl,--no-whole-archive",
             "-Wl,--start-group", *cfg["trusted_libs"],
             f"{SGX_SDK}/lib64/libsgx_tstdc.a", f"{SGX_SDK}/lib64/libsgx_tcxx.a",
             f"{SGX_SDK}/lib64/libsgx_tcrypto.a", f"{SGX_SDK}/lib64/libsgx_tservice.a",
             "-Wl,--end-group", "-o", f"{wd}/bin/profile4gate_relocs.so"], logf=logf)
        run([f"{SGX_SDK}/bin/x64/sgx_sign", "sign", "-key", f"{BASE}/src/test_key.pem",
             "-enclave", stub, "-out", f"{wd}/signed/profile4gate.signed.so",
             "-config", cfg["config_aex0"]], logf=logf)

    elf = parse_elf(stub)

    if "capture" in phases:
        p_s3, p_s1, rsp, per_round = capture(cfg, wd, logf, elf)
        json.dump({"p_s3": {hex(k): v for k, v in p_s3.items()},
                   "p_s1": {hex(k): v for k, v in p_s1.items()},
                   "gateB_rsp": hex(rsp) if rsp else None},
                  open(f"{wd}/capture.json", "w"), indent=1)
        rs = subprocess.run(["sudo", f"{wd}/bin/host_scan",
                             f"{wd}/signed/profile4gate.signed.so",
                             f"{wd}/dumps", str(cfg["capture_rounds"][0]), "-"],
                            text=True, capture_output=True)
        open(f"{wd}/dumps/meta.txt", "w").write(rs.stdout)
        logf.write("[host_scan]\n" + rs.stdout + rs.stderr + "\n")

    if "widen" in phases:
        cap = json.load(open(f"{wd}/capture.json"))
        p_dyn = {int(k, 16): v for k, v in cap["p_s3"].items()}
        p_s1 = {int(k, 16): v for k, v in cap["p_s1"].items()}
        rsp = int(cap["gateB_rsp"], 16) if cap.get("gateB_rsp") else None
        eff_map, report = widen(cfg, wd, elf, set(p_dyn), p_s1, rsp,
                                f"{wd}/dumps", logf)
        json.dump({hex(k): v for k, v in eff_map.items()},
                  open(f"{wd}/workset.json", "w"), indent=1)
        for l in report:
            logf.write(l + "\n")
        print(f"[widen] {len(eff_map)} target pages for {sample}")

    if "emit" in phases:
        ws = {int(k, 16): v for k, v in json.load(open(f"{wd}/workset.json")).items()}
        link_variant(cfg, wd, "auto4gate", ws, True, elf, cfg["config_aex0"], logf)
        link_variant(cfg, wd, "FinalElf_auto_aex1", ws, False, elf, cfg["config_aex1"], logf)

    if "verify" in phases:
        r = subprocess.run([f"{wd}/bin/host_kat", f"{wd}/signed/FinalElf_auto_aex1.signed.so"],
                           text=True, capture_output=True)
        print(r.stdout.strip()); logf.write(r.stdout + r.stderr + "\n")
        assert "KAT_OK=1" in r.stdout, "KAT failed on FinalElf"
        ok = True
        def check_round(tag, res):
            """Fail closed: require clean host exit, clean enclave return,
            all four stage records parsed, and empty S3."""
            good = (res["rc"] == 0 and res["st"] == "0x0" and res["ret"] == "0"
                    and all(k in res["stages"] for k in ("S0", "S1", "S2", "S3"))
                    and not res["stages"].get("S3"))
            print(f"[verify] {tag}: rc={res['rc']} st={res['st']} ret={res['ret']} "
                  f"S3(GateD)={res['stages'].get('S3')} -> {'OK' if good else 'FAIL'}")
            logf.write(res["raw"] + "\n")
            return good
        for rd in cfg["capture_rounds"]:
            res = run_host4(wd, f"{wd}/signed/auto4gate.signed.so", rd, 3, 0)
            ok = check_round(f"round={rd}", res) and ok
        for h in cfg["hidden_rounds"]:
            patch_path = f"{wd}/src/patch_{h['round']}.txt"
            with open(patch_path, "w") as pf:
                for sym, val in h["patch"].items():
                    rva = next(s_["value"] for s_ in elf["syms"] if s_["name"] == sym)
                    pf.write(f"{rva:x} {val.to_bytes(8,'little').hex()}\n")
            res = run_host4(wd, f"{wd}/signed/auto4gate.signed.so", h["round"], 3, 0,
                            patch=patch_path)
            ok = check_round(f"hidden {h['note']}", res) and ok
        print(f"[verify] {'PASS' if ok else 'FAIL'} for {sample}")
        logf.write(f"VERIFY {'PASS' if ok else 'FAIL'}\n")
        if not ok:
            sys.exit(2)
    logf.close()


if __name__ == "__main__":
    main()
