import contextlib
import importlib.util
import io
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).parents[1] / "atfield-host.py"
SPEC = importlib.util.spec_from_file_location("atfield_host", MODULE_PATH)
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


class RuntimeCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.conf = {
            "initial_online": set(range(10)),
            "surviving_online": set(range(5)),
            "atfield_cores": {1, 2, 3, 4},
            "system_cores": {0, 5, 6, 7, 8, 9},
        }
        self.isolated = self.root / "isolated"
        self.nohz = self.root / "nohz_full"
        self.workq = self.root / "workqueue-cpumask"
        self.pid1 = self.root / "pid1-status"
        self.watchdog = self.root / "nmi-watchdog"
        self.vmstat = self.root / "vm-stat-interval"
        self.numa = self.root / "numa-balancing"
        self.isolated.write_text("1-4\n")
        self.nohz.write_text("1-4\n")
        self.workq.write_text(host.cpumask(self.conf["system_cores"]) + "\n")
        self.pid1.write_text("Name:\tsystemd\nCpus_allowed_list:\t0,5-9\n")
        self.watchdog.write_text("0\n")
        self.vmstat.write_text("120\n")
        self.numa.write_text("0\n")

    def tearDown(self):
        self.temp.cleanup()

    def check(self, cmd=None, irq_snapshot=None):
        cmd = cmd or {
            "nohz_full": "1-4",
            "isolcpus": "domain,managed_irq,1-4",
            "irqaffinity": "0,5-9",
        }
        with (
            mock.patch.object(host, "check_topology", return_value=(set(range(5)), "off")),
            mock.patch.object(host, "parse_cmdline", return_value=cmd),
            mock.patch.object(host, "ISOLATED", self.isolated),
            mock.patch.object(host, "NOHZ_FULL", self.nohz),
            mock.patch.object(host, "WORKQ", self.workq),
            mock.patch.object(host, "PID1_STATUS", self.pid1),
            mock.patch.object(host, "NMI_WATCHDOG", self.watchdog),
            mock.patch.object(host, "VMSTAT", self.vmstat),
            mock.patch.object(host, "NUMA_BALANCING", self.numa),
            mock.patch.object(host, "irq_snapshot", return_value=irq_snapshot or (100, 0, [], [])),
            mock.patch.object(host.subprocess, "run", return_value=SimpleNamespace(returncode=3, stdout="inactive")),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = host.validate_runtime(self.conf, strict=True)
        return result, output.getvalue()

    def test_linux_70_optional_tuning_is_checked_by_runtime_readback(self):
        result, output = self.check()
        self.assertTrue(result, output)
        self.assertIn("nohz_full also offloads RCU callbacks", output)
        self.assertNotIn("missing rcu_nocbs", output)
        self.assertNotIn("missing workqueue.unbound_cpumask", output)
        self.assertNotIn("missing systemd.cpu_affinity", output)

    def test_runtime_mask_and_affinity_mismatches_still_fail(self):
        self.workq.write_text(host.cpumask({0, 1, 5, 6, 7, 8, 9}) + "\n")
        self.pid1.write_text("Name:\tsystemd\nCpus_allowed_list:\t0-9\n")
        self.numa.write_text("1\n")
        result, output = self.check(irq_snapshot=(100, 0, [(583, "1", "/irq/583/smp_affinity_list")], []))
        self.assertFalse(result)
        self.assertIn("unbound workqueue cpumask includes 1", output)
        self.assertIn("PID 1 CPU affinity", output)
        self.assertIn("kernel.numa_balancing is 1", output)
        self.assertIn("apparently migratable IRQ", output)

    def test_missing_required_boot_argument_fails(self):
        result, output = self.check(cmd={"nohz_full": "1-4", "irqaffinity": "0,5-9"})
        self.assertFalse(result)
        self.assertIn("kernel command line is missing isolcpus", output)


class KthreadAffinityTests(unittest.TestCase):
    def test_narrow_system_only_mask_is_untouched(self):
        target = {0, 5, 6, 7, 8, 9}
        atfield = {1, 2, 3, 4}
        self.assertIsNone(host.kthread_migration_target({5, 6}, target, atfield))

    def test_migration_removes_atfield_cpus_without_widening(self):
        target = {0, 5, 6, 7, 8, 9}
        atfield = {1, 2, 3, 4}
        self.assertEqual(host.kthread_migration_target({1, 2, 5, 6}, target, atfield), {5, 6})
        self.assertEqual(host.kthread_migration_target(set(range(10)), target, atfield), target)
        self.assertIsNone(host.kthread_migration_target({1, 2, 3, 4}, target, atfield))


class IrqMigrationTests(unittest.TestCase):
    def test_migrate_irqs_uses_offline_fixture_and_verifies_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            irq_root = pathlib.Path(tmp)
            irq_dir = irq_root / "7"
            irq_dir.mkdir()
            requested = irq_dir / "smp_affinity_list"
            effective = irq_dir / "effective_affinity_list"
            requested.write_text("1\n")
            effective.write_text("1\n")
            original_read_text = pathlib.Path.read_text
            effective_reads = 0

            def effective_tracks_requested(path, *args, **kwargs):
                nonlocal effective_reads
                if path == effective:
                    effective_reads += 1
                    if effective_reads > 1:
                        return original_read_text(requested, *args, **kwargs)
                return original_read_text(path, *args, **kwargs)

            conf = {"atfield_cores": {1}, "system_cores": {0, 2, 3}}
            with (
                mock.patch.object(pathlib.Path, "read_text", effective_tracks_requested),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                host.migrate_irqs(conf, irq_root=irq_root)
            self.assertEqual(requested.read_text().strip(), "0,2-3")
            self.assertIn("moved=1", output.getvalue())

    def test_migrate_irqs_cli_is_live_only_and_guards_active_leases(self):
        conf = {
            "initial_online": {0, 1, 2, 3, 4, 5},
            "surviving_online": {0, 1, 2},
            "atfield_cores": {1, 2},
            "system_cores": {0, 3, 4, 5},
        }
        args = SimpleNamespace(config=pathlib.Path("/unused/config"))
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(host, "require_root"),
                mock.patch.object(host, "parse_conf", return_value=conf),
                mock.patch.object(host, "ensure_root_lockdir"),
                mock.patch.object(host, "open_lock", return_value=17),
                mock.patch.object(host, "lock_nonblock", return_value=True),
                mock.patch.object(host, "acquire_busy_info", return_value=False),
                mock.patch.object(host, "check_topology", return_value=({0, 1, 2, 3, 4, 5}, "on")),
                mock.patch.object(host, "LOCKDIR", pathlib.Path(tmp)),
                mock.patch.object(host, "migrate_irqs") as migrate,
                mock.patch.object(host, "write") as write,
                mock.patch.object(host.fcntl, "flock"),
                mock.patch.object(host.os, "close"),
            ):
                host.migrate_irqs_action(args)
                migrate.assert_called_once_with(conf)
                write.assert_not_called()

        with (
            mock.patch.object(host, "require_root"),
            mock.patch.object(host, "parse_conf", return_value=conf),
            mock.patch.object(host, "ensure_root_lockdir"),
            mock.patch.object(host, "open_lock", return_value=18),
            mock.patch.object(host, "lock_nonblock", return_value=True),
            mock.patch.object(host, "acquire_busy_info", return_value=True),
            mock.patch.object(host, "migrate_irqs") as migrate,
            mock.patch.object(host.fcntl, "flock"),
            mock.patch.object(host.os, "close"),
        ):
            with self.assertRaisesRegex(host.HostError, "lease is active"):
                host.migrate_irqs_action(args)
            migrate.assert_not_called()



class PersistentSysctlTests(unittest.TestCase):
    def test_setup_and_explicit_restore_apply_readback_and_original_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            vmstat = root / "vmstat"
            numa = root / "numa"
            vmstat.write_text("1\n")
            numa.write_text("1\n")
            with (
                mock.patch.object(host, "VMSTAT", vmstat),
                mock.patch.object(host, "NUMA_BALANCING", numa),
            ):
                host.apply_persistent_sysctls()
                self.assertEqual(vmstat.read_text().strip(), "120")
                self.assertEqual(numa.read_text().strip(), "0")
                host.restore_persistent_sysctls({"vm_stat_interval": "1", "numa_balancing": "1"})
                self.assertEqual(vmstat.read_text().strip(), "1")
                self.assertEqual(numa.read_text().strip(), "1")


class SessionMarkerTests(unittest.TestCase):
    def test_setup_restore_setup_session_marker_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = pathlib.Path(tmp) / "persistent-smt-off"
            marker.write_text("stage=pending\n")
            host.set_session_state(marker, "pending", "active")
            host.set_session_state(marker, "active", "restoring")
            marker.unlink()  # restore removes it only after SMT and PID 1 readbacks succeed
            self.assertFalse(marker.exists())
            marker.write_text("stage=pending\n")
            host.set_session_state(marker, "pending", "active")
            self.assertEqual(host.session_state(marker), "active")

    def test_interrupted_restore_stage_is_not_accepted_as_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = pathlib.Path(tmp) / "persistent-smt-off"
            marker.write_text("stage=restoring\n")
            self.assertEqual(host.session_state(marker), "restoring")
            with self.assertRaisesRegex(host.HostError, "expected active"):
                host.set_session_state(marker, "active", "restoring")


    def test_explicit_restore_refuses_while_any_core_lease_is_active(self):
        conf = {
            "initial_online": {0, 1, 2, 3, 4, 5},
            "surviving_online": {0, 1, 2},
            "atfield_cores": {1, 2},
            "system_cores": {0, 3, 4, 5},
        }
        args = SimpleNamespace(config=pathlib.Path("/unused/config"))
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(host, "require_root"),
                mock.patch.object(host, "parse_conf", return_value=conf),
                mock.patch.object(host, "ensure_root_lockdir"),
                mock.patch.object(host, "open_lock", return_value=91),
                mock.patch.object(host, "lock_nonblock", return_value=True),
                mock.patch.object(host, "acquire_busy_info", return_value=True),
                mock.patch.object(host, "LOCKDIR", pathlib.Path(tmp)),
                mock.patch.object(host.fcntl, "flock"),
                mock.patch.object(host.os, "close"),
                mock.patch.object(host, "write") as write,
            ):
                with self.assertRaisesRegex(host.HostError, "core lease is active"):
                    host.restore_host(args)
                write.assert_not_called()


class PersistentRunnerTests(unittest.TestCase):
    def test_run_verifies_persistent_state_and_never_changes_smt_or_host_masks(self):
        conf = {
            "initial_online": {0, 1, 2, 3, 4, 5},
            "surviving_online": {0, 1, 2},
            "atfield_cores": {1, 2},
            "system_cores": {0, 3, 4, 5},
        }
        args = SimpleNamespace(config=pathlib.Path("/unused/config"), command=["true"])
        with tempfile.TemporaryDirectory() as tmp:
            lockdir = pathlib.Path(tmp)
            (lockdir / "persistent-smt-off").write_text("stage=active\n")
            with (
                mock.patch.object(host, "require_root"),
                mock.patch.object(host, "parse_conf", return_value=conf),
                mock.patch.object(host, "ensure_root_lockdir"),
                mock.patch.object(host, "LOCKDIR", lockdir),
                mock.patch.object(host, "open_lock", return_value=91),
                mock.patch.object(host, "check_topology", return_value=(conf["surviving_online"], "off")),
                mock.patch.object(host, "validate_runtime", return_value=True),
                mock.patch.object(host, "all_core_fds", return_value=[(1, 92)]),
                mock.patch.object(host, "lock_nonblock", return_value=True),
                mock.patch.object(host.os, "set_inheritable"),
                mock.patch.object(host.os, "close"),
                mock.patch.object(host.fcntl, "flock"),
                mock.patch.object(host, "write") as write,
                mock.patch.object(host, "apply_persistent_runtime") as apply_runtime,
                mock.patch.object(host, "migrate_irqs") as migrate,
                mock.patch.object(host, "run_child_with_cleanup", return_value=0) as child,
            ):
                self.assertEqual(host.runner(args), 0)
                write.assert_not_called()
                apply_runtime.assert_not_called()
                migrate.assert_not_called()
                child.assert_called_once()


if __name__ == "__main__":
    unittest.main()
