"""The local container test runner under ``tools/`` (blueprint 10, status line rule)."""

import io
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

from .conftest import ROOT, TOOLS

sys.path.insert(0, str(TOOLS))
import container_test


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_status_line_is_due_at_the_fixed_interval() -> None:
    clock = FakeClock()
    beat = container_test.Heartbeat(15.0, clock)
    assert not beat.due()
    clock.now = 114.9
    assert not beat.due()
    clock.now = 115.0
    assert beat.due()
    assert beat.status("img") == "progress: ct img stage=start elapsed=15s lines=0"
    assert not beat.due()
    clock.now = 130.0
    assert beat.due()


def test_stage_markers_update_the_status() -> None:
    clock = FakeClock()
    beat = container_test.Heartbeat(15.0, clock)
    beat.observe("Collecting pytest\n")
    beat.observe("MOTP-STAGE venv\n")
    clock.now = 160.0
    assert beat.status("x") == "progress: ct x stage=venv elapsed=60s lines=2"


def test_podman_command_mounts_the_tree_read_only() -> None:
    cmd = container_test.podman_command("podman", "docker.io/library/almalinux:9", ["-k", "x"])
    assert cmd[:2] == ["podman", "run"]
    assert f"{ROOT}:/src:ro" in cmd
    assert "--init" in cmd  # orphans are reaped, so zombies never fill a process limit
    assert cmd[-4:] == ["/bin/sh", "/src/tools/container/unit_tests.sh", "-k", "x"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs fcntl")
def test_container_runs_queue_on_a_host_lock(tmp_path: Path) -> None:
    import fcntl

    path = str(tmp_path / "ct.lock")
    holder = os.open(path, os.O_RDWR | os.O_CREAT)
    fcntl.flock(holder, fcntl.LOCK_EX)
    out = io.StringIO()
    got: list[Optional[int]] = []
    waiter = threading.Thread(
        target=lambda: got.append(container_test.host_lock(path, "img", out, interval=0.2))
    )
    waiter.start()
    time.sleep(1.0)
    assert not got, "the second run did not wait"
    assert "stage=queued" in out.getvalue()
    os.close(holder)
    waiter.join(5)
    assert got and got[0] is not None
    os.close(got[0])


# --- the level-3 runners: a crashed check script must fail the run (phase 11 issue) ----

import login_test  # noqa: E402
import systemd_test  # noqa: E402


def test_a_check_script_that_crashed_partway_fails_the_part() -> None:
    lines = ["CHECK a ok", "CHECK b ok", "Traceback (most recent call last):", "KeyError: 'x'"]
    checks = systemd_test.part_checks(lines, "after")
    assert checks[:2] == ["CHECK a ok", "CHECK b ok"]
    assert len(checks) == 3 and checks[2].startswith("CHECK checks_done_after FAIL")


def test_a_finished_check_script_adds_nothing() -> None:
    lines = ["CHECK a ok", "CHECK b FAIL x", "CHECKS-DONE failures=1"]
    assert systemd_test.part_checks(lines, "before") == ["CHECK a ok", "CHECK b FAIL x"]


def test_a_count_that_differs_from_the_fail_lines_fails_the_part() -> None:
    lines = ["CHECK a ok", "CHECKS-DONE failures=2"]
    checks = systemd_test.part_checks(lines, "before")
    assert checks[-1].startswith("CHECK checks_done_before FAIL")


def test_the_login_runner_needs_the_final_line_too() -> None:
    assert login_test.login_lines(["CHECK a ok", "NOTE n x", "CHECKS-DONE failures=0"]) == [
        "CHECK a ok",
        "NOTE n x",
    ]
    crashed = login_test.login_lines(["CHECK a ok", "NOTE n x"])
    assert any(c.startswith("CHECK checks_done_login FAIL") for c in crashed)


# --- the level-3 containers: the same options on every host (first CI run) --------------


def _option(cmd: "list[str]", flag: str) -> "list[str]":
    return [cmd[i + 1] for i, word in enumerate(cmd[:-1]) if word == flag]


def test_systemd_containers_boot_without_the_apparmor_mount_ban() -> None:
    """GitHub's runners enforce AppArmor, whose container profile denies mount: systemd 257
    did not boot and older ones could not build the collector's sandbox. WSL has no
    AppArmor, so only the command can show that both runners turn the profile off."""
    runner = systemd_test.Runner("podman", io.StringIO())
    cmd = runner.run_argv("n", "localhost/motp-systemd:debian12")
    assert cmd[:3] == ["podman", "run", "-d"] and cmd[-1] == "localhost/motp-systemd:debian12"
    assert "--systemd=always" in cmd and _option(cmd, "--cap-add") == ["SYS_ADMIN"]
    assert _option(cmd, "--security-opt") == ["apparmor=unconfined"]  # seccomp stays on
    assert "--privileged" not in cmd and f"{ROOT}:/src:ro" in cmd

    login = login_test.LoginRunner("podman", io.StringIO())
    cmd = login.run_argv("n", "localhost/motp-login:debian12", "--cap-add", "NET_ADMIN")
    assert _option(cmd, "--security-opt") == ["apparmor=unconfined"]
    assert _option(cmd, "--cap-add") == ["SYS_ADMIN", "NET_ADMIN"]
