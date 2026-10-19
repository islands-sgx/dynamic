# Host runner

The host protection is an explicit persistent session. Python 3 standard library only.

    ./atfield-host setup --plan
    sudo ./atfield-host setup --apply
    sudo ./atfield-check [--config /etc/atfield/cores.conf]
    sudo ./atfield-migrate-irqs [--config /etc/atfield/cores.conf]
    sudo ./atfield-run -- COMMAND [ARG ...]
    sudo ./atfield-host restore

setup --plan is read-only. setup --apply requires the intended boot arguments and SMT enabled. It snapshots the topology and PID 1 affinity, turns SMT off once, then keeps it off. It pins PID 1 to the existing system-CPU subset, sets and reads back the global unbound-workqueue mask, migrates eligible IRQs, sets vm.stat_interval=120 and kernel.numa_balancing=0, and saves the previous PID 1/sysctl values in a protected session marker. A failed apply leaves SMT in its observed state and retains the marker for inspection. Boot arguments still require an administrator-managed configuration and reboot; setup does not edit GRUB or systemd files.

For Linux 7.0, nohz_full also offloads RCU callbacks, so a separate rcu_nocbs parameter is not required. Required boot arguments are nohz_full, isolcpus=domain,managed_irq,..., and irqaffinity. nmi_watchdog=0, CPU frequency, governor, and turbo are noise or timing controls rather than SGX readiness conditions. Configure systemd Manager CPUAffinity and global unbound workqueues for system_cores; setup applies PID 1 affinity and reads both back. Kernel boot-argument changes require a reboot. A systemd configuration change is separate from the kernel command line.

atfield-check is read-only and expects the persistent SMT-off state. It verifies command-line masks, kernel isolated/nohz readbacks, PID 1 affinity, workqueue mask, irqbalance state, and effective IRQ affinity. Fixed or managed IRQs that remain on atfield_cores are reported as residual events; an active-phase AEX must still trigger fail-stop. The checker does not require separate command-line entries for rcu_nocbs, workqueue.unbound_cpumask, or systemd.cpu_affinity.

atfield-run requires an active persistent setup. Each invocation checks current readbacks while holding the allocator lock, leases one physical core, pins the child before exec, and releases only that core lease when the child exits. It never changes SMT, IRQ, PID 1, workqueue, or host sysctls. Concurrent children can lease separate cores. INT, TERM, and HUP are forwarded to the child process group.

restore is an explicit stop operation. It refuses while any core lease is active, turns SMT back on, restores the PID 1 affinity and sysctl values recorded by setup, then removes the session marker after readback succeeds. IRQ and workqueue masks remain on system CPUs. A pending marker needs manual inspection. If a previous restore was interrupted, the explicit restore command can resume from restoring state when the observed SMT/online state is known. Ordinary runs do not attempt recovery or hotplug. A successful restore removes the session marker, so setup can start a new session.

migrate-irqs moves eligible IRQs away from atfield_cores and verifies requested and effective masks without changing SMT. It takes the allocator lock and refuses active core leases. Use it after devices recreate MSI-X vectors. Fixed or managed IRQs remain residual events.
