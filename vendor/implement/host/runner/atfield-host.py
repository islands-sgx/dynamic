#!/usr/bin/env python3
"""ATField host setup, read-only audit, and exclusive-core runner."""
import argparse
import fcntl
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

CPU = pathlib.Path("/sys/devices/system/cpu")
SMT = CPU / "smt"
NOHZ_FULL = CPU / "nohz_full"
ISOLATED = CPU / "isolated"
DEFAULT_CONF = pathlib.Path("/etc/atfield/cores.conf")
LOCKDIR = pathlib.Path("/run/lock/atfield")
WORKQ = pathlib.Path("/sys/devices/virtual/workqueue/cpumask")
IRQ_ROOT = pathlib.Path("/proc/irq")
SYS_IRQ_ROOT = pathlib.Path("/sys/kernel/irq")
PID1_STATUS = pathlib.Path("/proc/1/status")
PID1_AFFINITY_MARKER = "restore-pid1-affinity"
NMI_WATCHDOG = pathlib.Path("/proc/sys/kernel/nmi_watchdog")
VMSTAT = pathlib.Path("/proc/sys/vm/stat_interval")
PERSISTENT_VMSTAT_INTERVAL = "120"
PERSISTENT_NUMA_BALANCING = "0"
ISOLCPUS_FLAGS = {"domain", "nohz", "managed_irq", "io_queue"}


class HostError(RuntimeError):
    pass


def read(path):
    try:
        return pathlib.Path(path).read_text().strip()
    except OSError as e:
        raise HostError(f"cannot read {path}: {e}") from e


def write(path, value):
    try:
        pathlib.Path(path).write_text(str(value) + "\n")
    except OSError as e:
        raise HostError(f"cannot write {path}: {e}") from e


def parse_cpulist(value):
    result = set()
    try:
        for part in value.split(","):
            if not part:
                continue
            ends = part.split("-")
            if len(ends) == 1:
                a = b = int(ends[0])
            elif len(ends) == 2:
                a, b = map(int, ends)
            else:
                raise ValueError()
            if a < 0 or b < a:
                raise ValueError()
            result.update(range(a, b + 1))
    except ValueError as e:
        raise HostError(f"invalid Linux CPU list: {value!r}") from e
    return result


def parse_isolcpus_cpus(value):
    tokens = [part for part in value.split(",") if part and part not in ISOLCPUS_FLAGS]
    if not tokens:
        raise HostError(f"isolcpus lacks a CPU list: {value!r}")
    return parse_cpulist(",".join(tokens))


def fmt_cpulist(cpus):
    xs = sorted(cpus)
    groups = []
    for n in xs:
        if groups and n == groups[-1][-1] + 1:
            groups[-1].append(n)
        else:
            groups.append([n])
    return ",".join(str(g[0]) if len(g) == 1 else f"{g[0]}-{g[-1]}" for g in groups)


def cpumask(cpus):
    if not cpus:
        raise HostError("cannot encode an empty CPU mask")
    words = [0] * (max(cpus) // 32 + 1)
    for n in cpus:
        words[n // 32] |= 1 << (n % 32)
    return ",".join(f"{w:08x}" for w in reversed(words))


def parse_cpumask(value):
    """Decode Linux cpumask hex groups (highest 32-bit group first)."""
    groups = value.strip().lower().split(",")
    if not groups or any(not g or len(g) > 8 for g in groups):
        raise HostError(f"invalid Linux hex CPU mask: {value!r}")
    result = set()
    try:
        for group_no, word in enumerate(reversed(groups)):
            bits = int(word, 16)
            for bit in range(32):
                if bits & (1 << bit):
                    result.add(group_no * 32 + bit)
    except ValueError as e:
        raise HostError(f"invalid Linux hex CPU mask: {value!r}") from e
    return result


def require_root():
    if os.geteuid() != 0:
        raise HostError("run this command as root (for example: sudo atfield-host ...)")


def parse_conf(path, secure=False):
    vals = {}
    try:
        conf_path = pathlib.Path(path)
        st = conf_path.stat()
        if secure and (st.st_uid != 0 or (st.st_mode & 0o022) or not conf_path.is_file()):
            raise HostError(f"configuration must be a root-owned regular file not writable by group/others: {path}")
        lines = conf_path.read_text().splitlines()
    except OSError as e:
        raise HostError(f"cannot read configuration {path}: {e}") from e
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise HostError(f"malformed config line: {line}")
        k, v = line.split("=", 1)
        if k in vals:
            raise HostError(f"duplicate config key: {k}")
        vals[k.strip()] = v.strip()
    required = ("initial_online", "surviving_online", "atfield_cores", "system_cores")
    if set(vals) != set(required):
        raise HostError(f"{path} must contain exactly: {', '.join(required)}")
    out = {k: parse_cpulist(vals[k]) for k in required}
    if len(out["atfield_cores"]) != 4:
        raise HostError("atfield_cores must contain exactly four logical CPUs")
    if out["atfield_cores"] & out["system_cores"]:
        raise HostError("atfield_cores and system_cores overlap")
    if not out["system_cores"] or 0 not in out["system_cores"]:
        raise HostError("system_cores must be nonempty and contain CPU 0")
    if out["atfield_cores"] | out["system_cores"] != out["initial_online"]:
        raise HostError("atfield_cores + system_cores must cover initial_online exactly")
    if not out["atfield_cores"] <= out["surviving_online"]:
        raise HostError("atfield_cores must be a subset of surviving_online")
    return out


def online():
    return parse_cpulist(read(CPU / "online"))


def smt_state():
    p = SMT / "control"
    if not p.exists():
        return "unsupported"
    v = read(p)
    if v not in ("on", "off"):
        raise HostError(f"unexpected SMT control value {v!r}")
    return v


def core_key(cpu):
    base = CPU / f"cpu{cpu}/topology"
    try:
        return (read(base / "physical_package_id"), read(base / "core_id"))
    except HostError as e:
        raise HostError(f"cannot identify physical core for CPU {cpu}: {e}") from e


def check_topology(conf):
    now = online()
    state = smt_state()
    if now not in (conf["initial_online"], conf["surviving_online"]):
        raise HostError(f"online CPUs {fmt_cpulist(now)} match neither configured set")
    if state == "off" and now != conf["surviving_online"]:
        raise HostError("SMT is off but online CPUs differ from surviving_online")
    if state == "on" and now != conf["initial_online"]:
        raise HostError("SMT is on but online CPUs differ from initial_online")
    physical = [core_key(c) for c in sorted(conf["atfield_cores"])]
    if len(set(physical)) != 4:
        raise HostError("atfield_cores do not identify four distinct physical cores")
    return now, state


def parse_cmdline():
    result = {}
    for word in read("/proc/cmdline").split():
        if "=" in word:
            k, v = word.split("=", 1)
            result[k] = v
        else:
            result[word] = ""
    return result


def effective_irq_cpus(path):
    try:
        return parse_cpulist(pathlib.Path(path).read_text().strip())
    except (OSError, HostError):
        return set()


def irq_residual_label(irq_dir, overlap):
    irq = irq_dir.name
    cpus = fmt_cpulist(overlap)
    sys_irq_dir = SYS_IRQ_ROOT / irq
    action_path = sys_irq_dir / "actions"
    chip_path = sys_irq_dir / "chip_name"
    try:
        action = action_path.read_text().strip()
    except OSError:
        action = "unknown action"
    try:
        chip = chip_path.read_text().strip()
    except OSError:
        chip = "unknown chip"
    return f"IRQ {irq} on CPU(s) {cpus} (fixed/managed residual; chip={chip}, action={action})"


def irq_affinity_is_fixed(irq_dir):
    requested = irq_dir / "smp_affinity_list"
    try:
        return not (requested.stat().st_mode & 0o200)
    except OSError:
        return True


def irq_snapshot(conf, irq_root=IRQ_ROOT):
    blocked, residual = [], []
    total = 0
    unreadable = 0
    for d in pathlib.Path(irq_root).iterdir():
        if not d.name.isdecimal():
            continue
        p = d / "effective_affinity_list"
        if not p.exists():
            continue
        total += 1
        try:
            eff = parse_cpulist(p.read_text().strip())
        except (OSError, HostError):
            unreadable += 1
            continue
        overlap = eff & conf["atfield_cores"]
        if not overlap:
            continue
        if irq_affinity_is_fixed(d):
            residual.append(irq_residual_label(d, overlap))
        else:
            blocked.append((int(d.name), fmt_cpulist(overlap), str(d / "smp_affinity_list")))
    return total, unreadable, blocked, residual

def validate_runtime(conf, strict):
    failures, notes = [], []
    try:
        now, state = check_topology(conf)
        if state != "off" or now != conf["surviving_online"]:
            failures.append("persistent host setup requires SMT off with surviving_online CPUs")
    except HostError as e:
        failures.append(str(e))
    cmd = parse_cmdline()
    for key in ("nohz_full", "isolcpus", "irqaffinity"):
        if key not in cmd:
            failures.append(f"kernel command line is missing {key}")
    if cmd.get("nohz_full") and parse_cpulist(cmd["nohz_full"]) != conf["atfield_cores"]:
        failures.append("nohz_full does not match atfield_cores")
    if cmd.get("nohz_full"):
        notes.append("Linux 7.0 nohz_full also offloads RCU callbacks; a separate rcu_nocbs= parameter is not required")
    if cmd.get("isolcpus"):
        try:
            if parse_isolcpus_cpus(cmd["isolcpus"]) != conf["atfield_cores"]:
                failures.append("isolcpus does not match atfield_cores")
        except HostError as e:
            failures.append(str(e))
    for key in ("irqaffinity",):
        if cmd.get(key) and parse_cpulist(cmd[key]) != conf["system_cores"]:
            failures.append(f"{key} does not match system_cores")
    isolated_path = ISOLATED
    if not isolated_path.exists():
        message = "kernel /sys/devices/system/cpu/isolated readback is unavailable"
        (failures if strict else notes).append(message)
    else:
        isolated_raw = read(isolated_path)
        if not isolated_raw:
            message = "kernel /sys/devices/system/cpu/isolated is empty; effective isolcpus mask is unavailable"
            (failures if strict else notes).append(message)
        elif parse_cpulist(isolated_raw) != conf["atfield_cores"]:
            failures.append(f"kernel isolated CPU readback {isolated_raw} does not match atfield_cores")
    try:
        full = parse_cpulist(read(NOHZ_FULL))
        if not conf["atfield_cores"] <= full:
            failures.append("kernel nohz_full readback omits an atfield CPU")
    except HostError:
        failures.append("kernel nohz_full readback is unavailable")
    try:
        pid1 = pathlib.Path(PID1_STATUS).read_text()
    except OSError as e:
        pid1 = ""
        message = f"PID 1 CPU affinity readback is unavailable: {e}"
        (failures if strict else notes).append(message)
    allowed = next((line.split(":", 1)[1].strip() for line in pid1.splitlines()
                    if line.startswith("Cpus_allowed_list:")), "")
    if not allowed and pid1:
        message = "PID 1 CPU affinity readback is missing Cpus_allowed_list"
        (failures if strict else notes).append(message)
    elif allowed:
        pid1_cpus = parse_cpulist(allowed)
        if pid1_cpus & conf["atfield_cores"]:
            failures.append(f"PID 1 CPU affinity includes atfield_cores: {allowed}")
        if not pid1_cpus or not pid1_cpus <= conf["system_cores"]:
            failures.append(f"PID 1 CPU affinity is not a nonempty subset of system_cores: {allowed}")
    for label, path, expected in (
        ("vm.stat_interval", VMSTAT, PERSISTENT_VMSTAT_INTERVAL),
        ("kernel.numa_balancing", NUMA_BALANCING, PERSISTENT_NUMA_BALANCING),
    ):
        if not path.exists():
            (failures if strict else notes).append(f"{label} runtime readback is unavailable")
        else:
            try:
                actual = read(path)
                if actual != expected:
                    failures.append(f"{label} is {actual}; expected persistent setting {expected}")
            except HostError as e:
                failures.append(str(e))
    if WORKQ.exists():
        try:
            wq = parse_cpumask(read(WORKQ))
            overlap = wq & conf["atfield_cores"]
            if overlap:
                failures.append(f"unbound workqueue cpumask includes {fmt_cpulist(overlap)}")
            if (wq & conf["initial_online"]) != conf["system_cores"]:
                failures.append("unbound workqueue cpumask does not cover exactly system_cores")
        except HostError as e:
            failures.append(str(e))
    else:
        message = "global unbound workqueue cpumask readback is unavailable"
        (failures if strict else notes).append(message)
    total, unreadable, bad, residual = irq_snapshot(conf)
    if unreadable:
        message = f"{unreadable}/{total} IRQ effective masks were unreadable or unavailable"
        (failures if strict else notes).append(message)
    if residual:
        notes.append(f"{len(residual)} fixed/managed IRQ(s) remain on atfield_cores as residual events; "
                     f"active-phase AEX must still trigger fail-stop. Example: {residual[0]}")
    if bad:
        failures.append(f"{len(bad)} apparently migratable IRQ(s) still route to atfield_cores; first: IRQ {bad[0][0]} on CPU {bad[0][1]}")
    watchdog = NMI_WATCHDOG
    if watchdog.exists():
        val = read(watchdog)
        notes.append(f"nmi_watchdog={val} (low-noise setting; not an SGX readiness guarantee)")
    else:
        notes.append("nmi_watchdog value unavailable")
    notes.append("CPU frequency/governor/turbo are timing metadata only; not part of SGX readiness.")
    service = subprocess.run(["systemctl", "is-active", "irqbalance"], capture_output=True, text=True)
    if service.returncode == 0 and service.stdout.strip() == "active":
        failures.append("irqbalance is active")
    elif service.returncode not in (0, 3, 4):
        notes.append("could not read irqbalance service state")
    if "nmi_watchdog=0" not in read("/proc/cmdline"):
        notes.append("kernel command line lacks nmi_watchdog=0 (low-noise setting)")
    for n in notes:
        print(f"NOTE: {n}")
    for e in failures:
        print(f"FAIL: {e}")
    if not failures:
        print(f"PASS: host readback checks; atfield={fmt_cpulist(conf['atfield_cores'])}, system={fmt_cpulist(conf['system_cores'])}")
    return not failures


def cpumask_write(path, cpus):
    mask = cpumask(cpus)
    write(path, mask)
    actual = read(path).replace(" ", "")
    if actual.lower() != mask.lower():
        raise HostError(f"{path} readback {actual} does not match {mask}")


def migrate_irqs(conf, irq_root=IRQ_ROOT):
    moved, ignored, residual, failed = 0, 0, [], []
    dest = conf["system_cores"]
    for d in pathlib.Path(irq_root).iterdir():
        if not d.name.isdecimal():
            continue
        effective = d / "effective_affinity_list"
        requested = d / "smp_affinity_list"
        if not effective.exists():
            continue
        try:
            eff_before = parse_cpulist(effective.read_text().strip())
        except (OSError, HostError):
            ignored += 1
            continue
        overlap = eff_before & conf["atfield_cores"]
        if not overlap:
            continue
        if irq_affinity_is_fixed(d):
            residual.append(irq_residual_label(d, overlap))
            continue
        try:
            requested.write_text(fmt_cpulist(dest) + "\n")
        except PermissionError as e:
            if e.errno == 1:  # EPERM: kernel/irqchip refuses this affinity change.
                residual.append(irq_residual_label(d, overlap))
                continue
            failed.append(f"IRQ {d.name}: {e}")
            continue
        except OSError as e:
            failed.append(f"IRQ {d.name}: {e}")
            continue
        try:
            req_after = parse_cpulist(requested.read_text().strip())
            eff_after = parse_cpulist(effective.read_text().strip())
        except (OSError, HostError) as e:
            failed.append(f"IRQ {d.name}: readback failed: {e}")
            continue
        if req_after != dest or eff_after & conf["atfield_cores"]:
            failed.append(f"IRQ {d.name}: readback requested={fmt_cpulist(req_after)} effective={fmt_cpulist(eff_after)}")
            continue
        moved += 1
    print(f"IRQ migration: moved={moved}, ignored-unreadable={ignored}, fixed/managed residual={len(residual)}, failed={len(failed)}")
    for item in residual:
        print(f"NOTE: {item}")
    if residual:
        print("NOTE: residual IRQs can still cause AEX; active-phase AEX must trigger fail-stop.")
    for e in failed:
        print(f"FAIL: {e}")
    if failed:
        raise HostError("some apparently migratable IRQs could not be migrated; completed moves remain in place")


def migrate_irqs_action(args):
    """Migrate eligible IRQs without changing SMT or other host settings."""
    require_root()
    conf = parse_conf(args.config, secure=True)
    ensure_root_lockdir()
    alloc_fd = open_lock(LOCKDIR / "allocator.lock")
    locked = False
    try:
        if not lock_nonblock(alloc_fd):
            raise HostError("another setup or atfield-run currently holds allocator.lock")
        locked = True
        if acquire_busy_info(conf):
            raise HostError("an ATField core lease is active; IRQ migration is refused")
        current, state = check_topology(conf)
        persistent = LOCKDIR / "persistent-smt-off"
        if state == "off" and current == conf["surviving_online"]:
            if not persistent.exists() or session_state(persistent) != "active":
                raise HostError("SMT-off state lacks an active persistent setup marker")
        elif state == "on" and current == conf["initial_online"]:
            if (LOCKDIR / "restore-smt-on").exists():
                raise HostError("legacy SMT recovery marker exists; inspect it before IRQ migration")
        else:
            raise HostError("migrate-irqs requires a configured stable SMT-on or persistent SMT-off state")
        migrate_irqs(conf)
    finally:
        if locked:
            fcntl.flock(alloc_fd, fcntl.LOCK_UN)
        os.close(alloc_fd)


def atomic_write(path, text):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".cores.conf.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass



def session_state(marker):
    stages = [line.split("=", 1)[1] for line in read(marker).splitlines()
              if line.startswith("stage=")]
    if len(stages) != 1:
        raise HostError(f"session marker has invalid stage record: {marker}")
    return stages[0]


def set_session_state(marker, expected, new):
    marker = pathlib.Path(marker)
    text = read(marker)
    state = session_state(marker)
    if state != expected:
        raise HostError(f"session marker stage={state}; expected {expected}")
    updated = text.replace(f"stage={expected}", f"stage={new}", 1)
    atomic_write(marker, updated)
    os.chmod(marker, 0o600)



def select_plan(initial, surviving):
    if len(surviving) < 5:
        raise HostError("SMT-off online set must retain at least five CPUs")
    selected = set(sorted(surviving)[-4:])
    if len({core_key(c) for c in selected}) != 4:
        raise HostError("highest four surviving CPUs are not four physical cores")
    system = initial - selected
    if 0 not in system:
        raise HostError("CPU 0 would be assigned to atfield_cores")
    return dict(initial_online=initial, surviving_online=surviving,
                atfield_cores=selected, system_cores=system)


def projected_survivors(initial):
    # Linux SMT-off keeps one thread per core; use the lowest online sibling
    # as a read-only preview, then verify the actual set during --apply.
    groups = {}
    for cpu in initial:
        groups.setdefault(core_key(cpu), []).append(cpu)
    return {min(xs) for xs in groups.values()}


def setup(args):
    if not args.apply:
        initial = online()
        present = parse_cpulist(read(CPU / "present"))
        if smt_state() != "on":
            raise HostError("setup --plan requires SMT on to project the initial topology")
        if initial != present:
            raise HostError("setup --plan requires all present CPUs online")
        plan = select_plan(initial, projected_survivors(initial))
        _print_setup_guidance(plan)
        print("PLAN ONLY: read-only; no file, SMT, IRQ, workqueue, boot or systemd setting was changed.")
        return 0

    require_root()
    ensure_root_lockdir()
    admin_fd = open_lock(LOCKDIR / "allocator.lock")
    try:
        if not lock_nonblock(admin_fd):
            raise HostError("another setup or atfield-run currently holds allocator.lock")
        stale = [name for name in ("restore-smt-on", PID1_AFFINITY_MARKER, "persistent-smt-off") if (LOCKDIR / name).exists()]
        if stale:
            raise HostError("legacy recovery marker exists; archive/inspect it before setup: " + ", ".join(stale))
        initial = online()
        present = parse_cpulist(read(CPU / "present"))
        if smt_state() != "on" or initial != present:
            raise HostError("setup --apply requires SMT on and all present CPUs online")
        plan = select_plan(initial, projected_survivors(initial))
        if acquire_busy_info(plan):
            raise HostError("an ATField core lease is active; setup apply is refused")
        actual_boot_args(plan)
        baseline, original_pid1 = setup_pid1_baseline(plan)
        original_vmstat = read(VMSTAT)
        original_numa = read(NUMA_BALANCING)
        conf_text = "".join(f"{k}={fmt_cpulist(plan[k])}\n" for k in
                            ("initial_online", "surviving_online", "atfield_cores", "system_cores"))
        atomic_write(args.config, conf_text)
        state_marker = LOCKDIR / "persistent-smt-off"
        marker_text = ("stage=pending\noriginal_smt=on\n"
                       + f"pid1_affinity={fmt_cpulist(baseline)}\npid1_original={fmt_cpulist(original_pid1)}\n"
                       + f"vm_stat_interval={original_vmstat}\nnuma_balancing={original_numa}\n")
        atomic_write(state_marker, marker_text)
        os.chmod(state_marker, 0o600)
        write(SMT / "control", "off")
        wait_smt("off", plan["surviving_online"])
        apply_persistent_runtime(plan, baseline)
        apply_persistent_sysctls()
        migrate_wide_kthreads(plan)
        if not validate_runtime(plan, strict=True):
            raise HostError("persistent host setup readback failed; SMT remains off and setup marker is retained")
        set_session_state(state_marker, "pending", "active")
        _print_setup_guidance(plan)
        print(f"Published {args.config}; persistent SMT-off setup is active and retained between runs.")
        return 0
    finally:
        try:
            fcntl.flock(admin_fd, fcntl.LOCK_UN)
        finally:
            os.close(admin_fd)


def actual_boot_args(plan):
    cmd = parse_cmdline()
    expected = {
        "nohz_full": plan["atfield_cores"],
        "isolcpus": plan["atfield_cores"],
        "irqaffinity": plan["system_cores"],
    }
    for key, cpus in expected.items():
        if key not in cmd:
            raise HostError(f"kernel command line is missing {key}; install boot parameters and reboot before setup --apply")
        actual = parse_isolcpus_cpus(cmd[key]) if key == "isolcpus" else parse_cpulist(cmd[key])
        if actual != cpus:
            raise HostError(f"kernel command line {key} does not match planned CPU set")


def _print_setup_guidance(plan):
    for k in ("initial_online", "surviving_online", "atfield_cores", "system_cores"):
        print(f"  {k}={fmt_cpulist(plan[k])}")
    print(f"Boot parameters: nohz_full={fmt_cpulist(plan['atfield_cores'])} isolcpus=domain,managed_irq,{fmt_cpulist(plan['atfield_cores'])} irqaffinity={fmt_cpulist(plan['system_cores'])} nmi_watchdog=0")
    print("Linux 7.0 nohz_full also offloads RCU callbacks; rcu_nocbs is not required separately.")
    print(f"Configure systemd Manager CPUAffinity and global unbound workqueues for system_cores={fmt_cpulist(plan['system_cores'])}; setup applies and reads back PID 1/workqueue masks.")
    print("irqbalance must be inactive. CPU frequency, turbo and nmi_watchdog are noise controls, not SGX readiness conditions.")


def ensure_root_lockdir():
    require_root()
    try:
        LOCKDIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as e:
        raise HostError(f"cannot create {LOCKDIR}: {e}") from e
    st = LOCKDIR.lstat()
    if not pathlib.Path(LOCKDIR).is_dir() or st.st_uid != 0 or (st.st_mode & 0o077):
        raise HostError(f"{LOCKDIR} must be a root-owned directory with mode 0700")


def open_lock(path):
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        st = os.fstat(fd)
        if not pathlib.Path(path).is_file() or st.st_uid != 0 or (st.st_mode & 0o077):
            os.close(fd)
            raise HostError(f"lock file must be root-owned, regular and mode 0600: {path}")
        return fd
    except OSError as e:
        raise HostError(f"cannot open lock file {path}: {e}") from e


def lock_nonblock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def all_core_fds(conf):
    return [(c, open_lock(LOCKDIR / f"core-{c}.lock")) for c in sorted(conf["atfield_cores"])]


def acquire_busy_info(conf):
    others = False
    for c, fd in all_core_fds(conf):
        if not lock_nonblock(fd):
            others = True
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return others


def wait_smt_state(expected_state, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if smt_state() == expected_state:
                return
        except HostError:
            pass
        time.sleep(.1)
    raise HostError(f"SMT control did not reach state={expected_state}")


def wait_smt(expected_state, expected_cpus, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if smt_state() == expected_state and online() == expected_cpus:
                return
        except HostError:
            pass
        time.sleep(.1)
    raise HostError(f"SMT transition did not reach state={expected_state}, online={fmt_cpulist(expected_cpus)}")


PF_KTHREAD = 0x00200000
NUMA_BALANCING = pathlib.Path("/proc/sys/kernel/numa_balancing")


def kthread_migration_target(allowed, target, atfield_cores):
    """Remove ATField CPUs while retaining the thread's existing allowed system CPUs."""
    if len(allowed) <= 1 or not (allowed & atfield_cores):
        return None
    destination = allowed & target
    return destination or None


def migrate_wide_kthreads(conf):
    target = conf["system_cores"] & online()
    if not target:
        raise HostError("no online system_cores available for movable kernel threads")
    migrated = 0
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            stat_text = (entry / "stat").read_text()
            rparen = stat_text.rfind(")")
            if rparen == -1:
                continue
            fields = stat_text[rparen + 2:].split()
            flags = int(fields[6])
            if not (flags & PF_KTHREAD):
                continue
            allowed = set(os.sched_getaffinity(pid))
            destination = kthread_migration_target(allowed, target, conf["atfield_cores"])
            if destination is None:
                continue
            os.sched_setaffinity(pid, destination)
            actual = set(os.sched_getaffinity(pid))
            if actual & conf["atfield_cores"]:
                raise HostError(f"kthread PID {pid} affinity readback still overlaps atfield_cores: {fmt_cpulist(actual)}")
            if actual - allowed:
                raise HostError(f"kthread PID {pid} affinity readback widened beyond its original mask: {fmt_cpulist(actual)}")
            migrated += 1
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue


def pid1_allowed_cpus():
    try:
        return set(os.sched_getaffinity(1))
    except OSError as e:
        raise HostError(f"cannot read PID 1 CPU affinity: {e}") from e


def setup_pid1_baseline(conf):
    original = pid1_allowed_cpus()
    baseline = original & conf["system_cores"]
    required = conf["system_cores"] & conf["surviving_online"]
    if not required <= baseline:
        raise HostError("PID 1 baseline affinity does not include all surviving system CPUs")
    return baseline, original


def apply_persistent_runtime(conf, baseline):
    target = baseline & conf["system_cores"] & online()
    required = conf["system_cores"] & online()
    if not target or not required <= target:
        raise HostError("saved PID 1 affinity cannot cover the surviving system CPUs without widening")
    try:
        os.sched_setaffinity(1, target)
        actual = set(os.sched_getaffinity(1))
    except OSError as e:
        raise HostError(f"cannot set PID 1 system-core affinity: {e}") from e
    if actual != target:
        raise HostError(f"PID 1 affinity readback {fmt_cpulist(actual)} != target {fmt_cpulist(target)}")
    cpumask_write(WORKQ, conf["system_cores"])
    migrate_irqs(conf)






def apply_persistent_sysctls():
    for name, path, target in (
        ("vm.stat_interval", VMSTAT, PERSISTENT_VMSTAT_INTERVAL),
        ("kernel.numa_balancing", NUMA_BALANCING, PERSISTENT_NUMA_BALANCING),
    ):
        if not path.exists():
            raise HostError(f"required persistent sysctl {name} is unavailable")
        if read(path) != target:
            write(path, target)
        actual = read(path)
        if actual != target:
            raise HostError(f"{name} readback {actual!r} != required {target!r}")


def restore_persistent_sysctls(data):
    settings = (
        ("vm.stat_interval", VMSTAT, "vm_stat_interval"),
        ("kernel.numa_balancing", NUMA_BALANCING, "numa_balancing"),
    )
    for name, path, key in settings:
        value = data.get(key)
        if value is None or not value.isdecimal():
            raise HostError(f"session marker lacks a valid saved {name} value")
        write(path, value)
        actual = read(path)
        if actual != value:
            raise HostError(f"{name} restore readback {actual!r} != saved {value!r}")



def restore_host(args):
    require_root()
    conf = parse_conf(args.config, secure=True)
    ensure_root_lockdir()
    alloc_fd = open_lock(LOCKDIR / "allocator.lock")
    try:
        if not lock_nonblock(alloc_fd):
            raise HostError("another setup or atfield-run currently holds allocator.lock")
        if acquire_busy_info(conf):
            raise HostError("an ATField core lease is active; restore is refused")
        marker = LOCKDIR / "persistent-smt-off"
        if not marker.exists():
            raise HostError("persistent setup marker is missing; refusing an untracked SMT transition")
        data = {}
        for line in read(marker).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value
        stage = data.get("stage")
        if stage == "active":
            if smt_state() != "off" or online() != conf["surviving_online"]:
                raise HostError("host is not in the configured SMT-off state; restore refused")
            original = parse_cpulist(data.get("pid1_original", ""))
            set_session_state(marker, "active", "restoring")
            write(SMT / "control", "on")
            wait_smt("on", conf["initial_online"])
        elif stage == "restoring":
            original = parse_cpulist(data.get("pid1_original", ""))
            if smt_state() == "off" and online() == conf["surviving_online"]:
                write(SMT / "control", "on")
                wait_smt("on", conf["initial_online"])
            elif smt_state() != "on" or online() != conf["initial_online"]:
                raise HostError("restore marker and SMT/online state disagree; inspect host manually")
        else:
            raise HostError("setup marker is pending or unknown; inspect recovery state manually")
        if original:
            os.sched_setaffinity(1, original)
            actual = set(os.sched_getaffinity(1))
            if actual != original:
                raise HostError(f"PID 1 affinity restore readback {fmt_cpulist(actual)} != saved {fmt_cpulist(original)}")
        restore_persistent_sysctls(data)
        marker.unlink()
        print("SMT restored to on by explicit request; session marker removed. IRQ and workqueue masks remain on system_cores.")
        return 0
    finally:
        fcntl.flock(alloc_fd, fcntl.LOCK_UN)
        os.close(alloc_fd)


def runner(args):
    require_root()
    if not args.command:
        raise HostError("usage: atfield-run [--config PATH] -- COMMAND [ARG ...]")
    conf = parse_conf(args.config, secure=True)
    ensure_root_lockdir()
    alloc_fd = open_lock(LOCKDIR / "allocator.lock")
    own_fd = None
    core = None
    try:
        fcntl.flock(alloc_fd, fcntl.LOCK_EX)
        state_marker = LOCKDIR / "persistent-smt-off"
        if not state_marker.exists() or session_state(state_marker) != "active":
            raise HostError("persistent setup is absent or incomplete; run atfield-host setup --apply first")
        now, state = check_topology(conf)
        if state != "off" or now != conf["surviving_online"]:
            raise HostError("host is not in the configured persistent SMT-off state")
        if not validate_runtime(conf, strict=True):
            raise HostError("host readback checks failed; refusing to start workload")
        for c, fd in all_core_fds(conf):
            if lock_nonblock(fd):
                own_fd, core = fd, c
                break
            os.close(fd)
        if own_fd is None:
            raise HostError("busy: all four ATField physical cores are leased")
        os.set_inheritable(own_fd, True)
    except Exception:
        if own_fd is not None:
            os.close(own_fd)
        raise
    finally:
        try:
            fcntl.flock(alloc_fd, fcntl.LOCK_UN)
        finally:
            os.close(alloc_fd)
    print(f"LEASE acquired: CPU {core}; persistent SMT-off state verified; child pinned to one logical CPU.", flush=True)
    return run_child_with_cleanup(args.command, core, own_fd, conf)


def cleanup_lease(conf, own_fd):
    try:
        os.close(own_fd)
    except OSError as e:
        print(f"FATAL cleanup: cannot release core lease: {e}", file=sys.stderr)
        return HostError(f"cannot release core lease: {e}")
    print("LEASE released; persistent host setup remains active.", flush=True)
    return None



def run_child_with_cleanup(command, core, own_fd, conf):
    proc_box = [None]
    requested_signal = [None]

    def forward(signum, _frame):
        requested_signal[0] = signum
        proc = proc_box[0]
        if proc is not None:
            try:
                os.killpg(proc.pid, signum)
            except ProcessLookupError:
                pass

    old_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[sig] = signal.signal(sig, forward)
    code = None
    launch_error = None
    try:
        proc_box[0] = subprocess.Popen(
            command, pass_fds=(own_fd,), start_new_session=True,
            preexec_fn=lambda: os.sched_setaffinity(0, {core}))
        if requested_signal[0] is not None:
            forward(requested_signal[0], None)
        code = proc_box[0].wait()
    except BaseException as e:
        launch_error = e
        proc = proc_box[0]
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
    finally:
        try:
            for sig, handler in old_handlers.items():
                signal.signal(sig, handler)
        finally:
            cleanup_error = cleanup_lease(conf, own_fd)
    if cleanup_error:
        return 125
    if launch_error is not None:
        if isinstance(launch_error, Exception):
            raise HostError(f"command start/wait failed: {launch_error}") from launch_error
        raise launch_error
    if requested_signal[0] is not None:
        return 128 + requested_signal[0]
    return code


def main():
    invoked = pathlib.Path(sys.argv[0]).name
    p = argparse.ArgumentParser(prog=invoked)
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("setup", help="probe physical cores and prepare host configuration")
    mode = s.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    s.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONF)
    c = sub.add_parser("check", help="read-only host configuration audit")
    c.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONF)
    m = sub.add_parser("migrate-irqs", help="migrate eligible IRQs away from atfield_cores without changing SMT")
    m.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONF)
    z = sub.add_parser("restore", help="explicitly stop the persistent isolation session and restore SMT")
    z.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONF)
    r = sub.add_parser("run", help="run a command under an exclusive physical-core lease")
    r.add_argument("--config", type=pathlib.Path, default=DEFAULT_CONF)
    r.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args()
    if args.action == "setup":
        return setup(args)
    if args.action == "check":
        conf = parse_conf(args.config)
        ok = validate_runtime(conf, strict=True)
        return 0 if ok else 1
    if args.action == "migrate-irqs":
        migrate_irqs_action(args)
        return 0
    if args.action == "restore":
        return restore_host(args)
    if args.action == "run":
        if args.command and args.command[0] == "--":
            args.command = args.command[1:]
        return runner(args)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HostError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
