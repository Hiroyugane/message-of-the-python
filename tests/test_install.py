"""``motp install``, ``motp uninstall`` and ``motp doctor`` (blueprint 4.11, 4.12, D24,
D31, D33, T2, T24, T25, invariant 7).

The pure tests run everywhere: sudoers parsing, manifest scope and decoding, archive
member checks, the unit texts, the stderr log. The rest run as root inside the containers
of ``tools/container_test.py`` against a whole fake system below ``/var/lib`` (``Box``):
its own ``/opt``, ``/etc``, ``/var/lib``, ``/run`` and account files. Accounts are made by
a test double that edits the box's account files; bytecode is compiled for real with
``/usr/bin/python3``. The systemd test images (``tools/systemd_test.py``) run the same
installer against the real system.
"""

import io
import os
import stat
import subprocess
import sys
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Optional

import pytest

import build_pyz
from motp.collect import errlog
from motp.core import config, i18n, proc
from motp.core.model import ContractError
from motp.install import accounts, admingroup, doctor, hooks, installer, manifest, units
from motp.install.installer import Out, Target
from motp.install.manifest import Entry

from .conftest import SRC, TEST_USER, account

PY3 = "/usr/bin/python3"
owner = pytest.mark.needs_linux_owner


# --- sudoers and the admin group (D33) ---------------------------------------------------


@pytest.mark.parametrize(
    ("line", "groups"),
    [
        ("%sudo   ALL=(ALL:ALL) ALL", {"sudo"}),
        ("%wheel  ALL=(ALL)       ALL", {"wheel"}),
        ("%wheel,%admin ALL=(ALL) NOPASSWD: ALL", {"wheel", "admin"}),
        ("%sudo ALL=(ALL:ALL) ALL   # the admins", {"sudo"}),
        ("# %wheel ALL=(ALL) ALL", set()),
        ("#%sudo ALL=(ALL) ALL", set()),
        ("!%sudo ALL=(ALL) ALL", set()),
        ("%:sudo ALL=(ALL) ALL", set()),
        ("root ALL=(ALL:ALL) ALL", set()),
        ("#1000 ALL=(ALL) ALL", set()),
        ("Defaults env_reset", set()),
        ("User_Alias ADMINS = %sudo", set()),
        ("%sudo", set()),
        ("", set()),
    ],
)
def test_sudoers_rules(line: str, groups: set[str]) -> None:
    assert admingroup.groups_in_rule(line) == groups


def test_the_admin_group_is_sudo_or_wheel_granted_and_local_and_never_adm() -> None:
    local = {"sudo": 27, "wheel": None}
    assert admingroup.choose({"sudo", "adm"}, local) == "sudo"
    assert admingroup.choose({"wheel"}, local) == ""  # granted, but not a local group
    assert admingroup.choose({"adm", "admin"}, {"sudo": 27, "wheel": 10, "adm": 4}) == ""
    assert admingroup.choose(set(), {"sudo": 27, "wheel": 10}) == ""


def test_the_starter_config_carries_the_chosen_group() -> None:
    text = installer.starter_config("wheel").decode()
    assert 'admin_group = "wheel"' in text and installer.STARTER_ADMIN_LINE not in text
    assert not config.check_content(text.encode())
    assert installer.starter_config("").decode().count(installer.STARTER_ADMIN_LINE) == 1


# --- manifest: scope and decoding (T25) -------------------------------------------------

SCOPE = manifest.Scope(exact=("/etc/cron.d/motp",), trees=("/opt/motp", "/etc/motp"))


@pytest.mark.parametrize(
    ("path", "allowed"),
    [
        ("/opt/motp", True),
        ("/opt/motp/lib/motp/cli.py", True),
        ("/etc/cron.d/motp", True),
        ("/etc/motp/config.toml", True),
        ("/opt/motpx/evil", False),
        ("/opt/motp/../../etc/passwd", False),
        ("/opt/motp/./lib", False),
        ("/opt/motp//lib", False),
        ("/opt/motp/lib/", False),
        ("opt/motp/lib", False),
        ("/etc/passwd", False),
        ("/etc/cron.d/motp2", False),
        ("/", False),
        ("/opt/motp/\x00x", False),
    ],
)
def test_scope(path: str, allowed: bool) -> None:
    assert SCOPE.allows(path) is allowed


def test_manifest_round_trip() -> None:
    m = manifest.Manifest(
        version="1.0",
        entries=(
            Entry("/opt/motp", "dir"),
            Entry("/opt/motp/bin/motp", "file", sha256="a" * 64),
            Entry("/usr/local/bin/motp", "link", target="/opt/motp/bin/motp"),
            Entry("/etc/motp/config.toml", "file", role="config", sha256="b" * 64),
        ),
        accounts=(manifest.Account("motp", 990, 990),),
        admin_group="sudo",
        scheduler="systemd",
    )
    assert manifest.decode(manifest.encode(m)) == m


@pytest.mark.parametrize(
    "doc",
    [
        b"{}",
        b"[]",
        b'{"schema": 2}',
        b"not json",
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron","accounts":[],'
        b'"entries":[{"path":"/x","kind":"fifo","role":"program"}]}',
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron","accounts":[],'
        b'"entries":[{"path":"/x","kind":"file","role":"program","sha256":"XYZ"}]}',
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron","accounts":[],'
        b'"entries":[{"path":"/x","kind":"file","role":"owner","sha256":""}]}',
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"at","accounts":[],"entries":[]}',
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron",'
        b'"accounts":[{"name":"motp","uid":0,"gid":5}],"entries":[]}',
        # Final review, security item 1: uninstall removes every listed account, so only
        # MOTP's own names may appear, each once.
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron",'
        b'"accounts":[{"name":"alice","uid":1000,"gid":1000}],"entries":[]}',
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron",'
        b'"accounts":[{"name":"root","uid":1,"gid":1}],"entries":[]}',
        b'{"schema":1,"version":"1","admin_group":"","scheduler":"cron",'
        b'"accounts":[{"name":"motp","uid":990,"gid":990},'
        b'{"name":"motp","uid":991,"gid":991}],"entries":[]}',
    ],
)
def test_a_malformed_manifest_is_refused(doc: bytes) -> None:
    with pytest.raises(ContractError):
        manifest.decode(doc)


# --- archive members --------------------------------------------------------------------


def _zip(names: dict[str, bytes], link: Optional[str] = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in names.items():
            zf.writestr(name, data)
        if link is not None:
            info = zipfile.ZipInfo(link)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


GOOD = {"__main__.py": b"", "motp/__init__.py": b"", "motp/core/x.py": b"x = 1\n"}


def test_a_good_archive_passes() -> None:
    assert [n for n, _ in installer.members(_zip(GOOD))] == list(GOOD)


@pytest.mark.parametrize(
    "bad",
    ["../evil.py", "/etc/passwd", "motp/../../etc/x", "motp/./x.py", "motp//x.py", "other/x.py",
     "motp/.hidden", "motp/x y.py", "motp/sub/"],
)  # fmt: skip
def test_an_archive_with_an_unexpected_name_is_refused(bad: str) -> None:
    with pytest.raises(ContractError):
        installer.members(_zip({**GOOD, bad: b"x"}))


def test_an_archive_with_a_link_or_without_the_package_is_refused() -> None:
    with pytest.raises(ContractError):
        installer.members(_zip(GOOD, link="motp/evil.py"))
    with pytest.raises(ContractError):
        installer.members(_zip({"__main__.py": b""}))
    with pytest.raises(ContractError):
        installer.members(b"not a zip")


def test_the_real_archive_passes() -> None:
    names = [n for n, _ in installer.members(_zip(build_pyz.collect(SRC)))]
    assert "motp/install/installer.py" in names and "motp/locale/en.mo" in names


# --- unit texts (4.11) ------------------------------------------------------------------

BASELINE = """Type=oneshot
TimeoutStartSec=90
UMask=0077
RuntimeDirectory=motp
RuntimeDirectoryPreserve=yes
StateDirectory=motp
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN
TasksMax=128
MemoryMax=256M
Nice=10
IOSchedulingClass=idle""".splitlines()


def test_the_service_has_the_baseline_and_each_addition_has_a_reason() -> None:
    lines = units.SERVICE_TEXT.splitlines()
    for directive in BASELINE:
        assert directive in lines, directive
    for directive in units.ADDITIONS:
        assert directive in lines, directive
    service = [ln for ln in lines if "=" in ln and not ln.startswith("#")]
    unit_section = {"Description", "After"}
    for ln in service:
        key = ln.split("=", 1)[0]
        assert ln in BASELINE or ln in units.ADDITIONS or key in unit_section, ln
    assert "ProtectProc=invisible" not in units.SERVICE_TEXT  # the cleanup must see probes


# The capability table of blueprint 4.11 after phase 11: the drop to the probe users, the
# cleanup of their processes, the group of admin.json. CAP_NET_ADMIN stayed out (O12).
CAPABILITIES = {"CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_CHOWN"}


def test_the_capability_set_is_the_table_of_4_11() -> None:
    lines = [ln for ln in units.SERVICE_TEXT.splitlines() if ln.startswith("CapabilityBounding")]
    assert len(lines) == 1 and set(lines[0].split("=", 1)[1].split()) == CAPABILITIES
    assert units.MODULE_ADDITIONS == {}  # no module adds to the unit, so nothing to apply


def test_every_root_module_says_what_it_uses_of_the_unit() -> None:
    from motp.modules import registry

    root = {m.name for m in registry.cached_modules() if m.needs_root}
    assert root <= set(units.MODULE_EXPOSURE), root - set(units.MODULE_EXPOSURE)
    assert {"sec_firewall", "app_containers", "sec_fail2ban"} <= set(units.MODULE_EXPOSURE)


def test_every_program_runs_isolated_and_without_site() -> None:
    """T2 and invariant 7: the wrapper is the only way in, and it uses ``-I -S``."""
    assert f"exec {units.SYSTEM_PYTHON} -I -S {units.LIB_DIR} " in units.WRAPPER_TEXT
    assert f"ExecStart={units.WRAPPER} collect --in-unit\n" in units.SERVICE_TEXT
    assert f"root {units.WRAPPER} collect --no-sandbox\n" in units.CRON_TEXT
    assert "OnBootSec=20s" in units.TIMER_TEXT and "OnUnitActiveSec=5min" in units.TIMER_TEXT


# --- the fake system ---------------------------------------------------------------------


class FakeTools:
    """Creates and removes accounts by editing the box's account files."""

    def __init__(self, files: accounts.Files) -> None:
        self.files = files
        self.next_id = 960
        self.calls: list[tuple[str, str]] = []

    def _edit(self, path: str, keep: Callable[[str], bool], add: str = "") -> None:
        lines = [ln for ln in Path(path).read_text().splitlines(keepends=True) if keep(ln)]
        Path(path).write_text("".join(lines) + add)

    def create(self, name: str, shell: str) -> None:
        self.calls.append(("create", name))
        n = self.next_id
        self.next_id += 1
        self._edit(
            self.files.passwd, lambda ln: True, f"{name}:x:{n}:{n}:MOTP:/nonexistent:{shell}\n"
        )
        self._edit(self.files.group, lambda ln: True, f"{name}:x:{n}:\n")
        self._edit(self.files.shadow, lambda ln: True, f"{name}:!:19000::::::\n")

    def delete_user(self, name: str) -> None:
        self.calls.append(("delete_user", name))
        for path in (self.files.passwd, self.files.shadow, self.files.group):
            self._edit(path, lambda ln: not ln.startswith(name + ":"))

    def delete_group(self, name: str) -> None:
        self.calls.append(("delete_group", name))
        self._edit(self.files.group, lambda ln: not ln.startswith(name + ":"))


class FakeSystem:
    """Compiles for real; records ``systemctl`` and wrapper runs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.real = installer.RealSystem()
        self.fail = False
        self.timeout = True

    def compile(self, python: str, tree: str) -> tuple[str, tuple[int, int]]:
        return self.real.compile(python, tree)

    def systemctl(self, *args: str) -> bool:
        self.calls.append(("systemctl", *args))
        return not self.fail

    def run_wrapper(self, wrapper: str, *args: str) -> tuple[bool, bytes]:
        self.calls.append(("wrapper", *args))
        return True, b"[ok] doctor report\n"

    def timeout_ok(self, timeout: str, python: str) -> bool:
        self.calls.append(("timeout_ok", timeout))
        return self.timeout


class Box:
    """A whole fake system below a root-owned directory."""

    def __init__(self, root: Path, archive: Path, systemd: bool = True) -> None:
        self.root = root
        self.archive = archive
        for d in (
            "opt",
            "etc",
            "etc/systemd/system",
            "etc/cron.d",
            "etc/profile.d",
            "etc/tmpfiles.d",
            "var/lib",
            "run",
            "usr/local/bin",
        ):
            (root / d).mkdir(parents=True, exist_ok=True)
            (root / d).chmod(0o755)
        if systemd:
            (root / "run/systemd/system").mkdir(parents=True)
        etc = root / "etc"
        (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
        (etc / "group").write_text("root:x:0:\nsudo:x:27:\nwheel:x:10:\ndisk:x:6:\n")
        (etc / "shadow").write_text("root:*:19000::::::\n")
        (etc / "shadow").chmod(0o600)
        self.sudoers("%sudo ALL=(ALL:ALL) ALL\n")
        self.files = accounts.Files(
            passwd=str(etc / "passwd"),
            group=str(etc / "group"),
            shadow=str(etc / "shadow"),
            login_defs=str(etc / "login.defs"),
            check_nss=False,
        )
        self.target = Target(
            prefix=str(root / "opt/motp"),
            config_root=str(etc / "motp"),
            state_dir=str(root / "var/lib/motp"),
            cache_dir=str(root / "run/motp"),
            unit_dir=str(etc / "systemd/system"),
            cron_file=str(etc / "cron.d/motp"),
            local_bin_link=str(root / "usr/local/bin/motp"),
            systemd_marker=str(root / "run/systemd/system"),
            sudoers=str(etc / "sudoers"),
            system_python=PY3,
            account_files=self.files,
            profile_hook=str(etc / "profile.d/motp.sh"),
            zprofiles=(str(etc / "zsh/zprofile"), str(etc / "zprofile")),
            tmpfiles_file=str(etc / "tmpfiles.d/motp.conf"),
            motd_dir=str(root / "run/motd.d"),
        )
        self.tools = FakeTools(self.files)
        self.system = FakeSystem()
        self.text = io.StringIO()

    def sudoers(self, text: str) -> None:
        path = self.root / "etc/sudoers"
        path.write_text(text)
        path.chmod(0o440)

    def out(self) -> Out:
        return Out(self.text, i18n.translator("en"))

    def install(self, **kwargs: object) -> int:
        return installer.install(
            self.target,
            program=str(kwargs.pop("program", self.archive)),
            system=self.system,
            tools=self.tools,
            out=self.out(),
            **kwargs,  # type: ignore[arg-type]
        )

    def uninstall(self, **kwargs: object) -> int:
        return installer.uninstall(
            self.target,
            system=self.system,
            tools=self.tools,
            out=self.out(),
            **kwargs,  # type: ignore[arg-type]
        )

    def snapshot(self) -> set[str]:
        out = set()
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in [*dirnames, *filenames]:
                out.add(os.path.relpath(os.path.join(dirpath, name), self.root))
        return out

    def manifest(self) -> manifest.Manifest:
        m = manifest.read(self.target.state_dir)
        assert m is not None
        return m


@pytest.fixture(scope="module")
def archive() -> Iterator[Path]:
    import shutil
    import tempfile

    if not (sys.platform.startswith("linux") and os.geteuid() == 0):
        pytest.skip("needs Linux and root (runs inside the CI containers)")
    d = Path(tempfile.mkdtemp(prefix="motp-pyz-", dir="/var/lib"))
    d.chmod(0o755)
    path = d / "motp.pyz"
    build_pyz.build(SRC, path)
    yield path
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def box(trusted_dir: Path, archive: Path) -> Box:
    return Box(trusted_dir, archive)


def mode(path: "str | Path") -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# --- install ------------------------------------------------------------------------------


@owner
def test_install_sets_up_tree_accounts_config_units_and_manifest(box: Box) -> None:
    before = box.snapshot()
    assert box.install() == 0, box.text.getvalue()
    t = box.target
    lib = Path(t.lib_dir)
    assert (lib / "__main__.py").is_file() and (lib / "motp/install/installer.py").is_file()
    pycs = list(lib.rglob("*.pyc"))
    assert pycs and all(p.stat().st_uid == 0 and mode(p) == 0o644 for p in pycs)
    for path in [lib, *lib.rglob("*")]:
        st = os.lstat(path)
        assert st.st_uid == 0 and st.st_gid == 0 and not st.st_mode & 0o022, path
    assert Path(t.wrapper).read_text() == t.wrapper_text() and mode(t.wrapper) == 0o755
    assert f"-I -S {t.lib_dir} " in t.wrapper_text()
    assert Path(t.service_path).read_text() == t.service_text() and mode(t.service_path) == 0o644
    assert Path(t.timer_path).read_text() == units.TIMER_TEXT
    conf = Path(t.config_file)
    assert 'admin_group = "sudo"' in conf.read_text() and mode(conf) == 0o644
    assert not config.load(t.config_root).problems
    users = {ln.split(":")[0] for ln in Path(box.files.passwd).read_text().splitlines()}
    assert {"motp", "motp-plugin"} <= users
    m = box.manifest()
    assert mode(Path(t.state_dir) / manifest.NAME) == 0o600 and mode(t.state_dir) == 0o700
    assert {a.name for a in m.accounts} == {"motp", "motp-plugin"}
    assert m.admin_group == "sudo" and m.scheduler == "systemd"
    for e in m.entries:
        if e.kind == "file":
            assert manifest.sha256_bytes(Path(e.path).read_bytes()) == e.sha256, e.path
    assert os.readlink(t.local_bin_link) == t.wrapper
    assert ("systemctl", "enable", units.TIMER_NAME) in box.system.calls
    assert ("systemctl", "start", units.SERVICE_NAME) in box.system.calls
    assert ("wrapper", "doctor") in box.system.calls
    assert "[ok] doctor report" in box.text.getvalue()
    assert not {p for p in box.snapshot() - before if "lib.new" in p or "lib.old" in p}


@owner
def test_dry_run_changes_nothing(box: Box) -> None:
    before = {p: os.lstat(box.root / p).st_mtime_ns for p in box.snapshot()}
    assert box.install(dry_run=True) == 0, box.text.getvalue()
    after = {p: os.lstat(box.root / p).st_mtime_ns for p in box.snapshot()}
    assert before == after
    text = box.text.getvalue()
    assert "plan: create the system account motp" in text and "dry run" in text
    assert box.tools.calls == [] and box.system.calls == []


@owner
@pytest.mark.parametrize(
    ("passwd", "group"),
    [
        ("motp:x:1000:1000:A Person:/home/motp:/bin/bash\n", "motp:x:1000:\n"),
        ("motp:x:950:950::/nonexistent:/usr/sbin/nologin\n", "motp:x:950:\n"),  # a system one
        ("", "motp-plugin:x:951:\n"),  # a group alone
    ],
)
def test_a_foreign_account_stops_the_installer_before_any_change(
    box: Box, passwd: str, group: str
) -> None:
    """T24: an account or group named like MOTP's that the manifest does not list."""
    with open(box.files.passwd, "a") as fh:
        fh.write(passwd)
    with open(box.files.group, "a") as fh:
        fh.write(group)
    before = box.snapshot()
    assert box.install() == 1
    assert "stopped before any change" in box.text.getvalue()
    assert "was not created by MOTP" in box.text.getvalue()
    assert box.snapshot() == before
    assert box.tools.calls == [] and box.system.calls == []


@owner
def test_reinstall_keeps_accounts_and_an_edited_config(box: Box) -> None:
    assert box.install() == 0, box.text.getvalue()
    ids = {(a.name, a.uid) for a in box.manifest().accounts}
    conf = Path(box.target.config_file)
    conf.write_text('[visibility]\nadmin_group = "wheel"\n')
    pyc = next(Path(box.target.lib_dir).rglob("*.pyc"))
    old_inode = pyc.stat().st_ino
    box.text.truncate(0)
    assert box.install() == 0, box.text.getvalue()
    assert {(a.name, a.uid) for a in box.manifest().accounts} == ids
    assert [c for c in box.tools.calls if c[0] == "create"] == [
        ("create", "motp"),
        ("create", "motp-plugin"),
    ]
    assert conf.read_text() == '[visibility]\nadmin_group = "wheel"\n'
    text = box.text.getvalue()
    assert (
        "kept the existing config" in text and "the config says wheel, sudoers grant sudo" in text
    )
    assert pyc.stat().st_ino != old_inode  # a fresh tree, compiled again


@owner
def test_reinstall_never_widens_an_admins_stricter_config_modes(box: Box) -> None:
    """Final review, security item 4: the old code re-applied 0755 on every install.
    A first install still gives 0755 (code review of phase 14b: it gave 0700)."""
    assert box.install() == 0, box.text.getvalue()
    root = Path(box.target.config_root)
    for path in (root, root / "conf.d", root / "plugins.d"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o755, path
    stricter = {root: 0o711, root / "conf.d": 0o700, root / "plugins.d": 0o750}
    for path, mode in stricter.items():
        os.chmod(path, mode)
    os.chmod(root / "plugins.d", 0o2750)  # a setgid bit is still taken away
    box.text.truncate(0)
    assert box.install() == 0, box.text.getvalue()
    for path, mode in stricter.items():
        assert stat.S_IMODE(path.stat().st_mode) == mode, path


@owner
def test_uninstall_leaves_only_the_config(box: Box) -> None:
    before = box.snapshot()
    assert box.install() == 0, box.text.getvalue()
    run = Path(box.target.cache_dir)  # what a collector run leaves
    run.mkdir(mode=0o755, exist_ok=True)
    (run / "user").mkdir(mode=0o711)
    for name in ("public.json", "admin.json", "render.json", "collect.lock", "user/1000.json"):
        (run / name).write_text("{}")
    for name in ("state.json", errlog.NAME):
        (Path(box.target.state_dir) / name).write_text("{}")
    assert box.uninstall() == 0, box.text.getvalue()
    left = box.snapshot() - before
    assert left == {"etc/motp", "etc/motp/config.toml", "etc/motp/conf.d", "etc/motp/plugins.d"}
    users = {ln.split(":")[0] for ln in Path(box.files.passwd).read_text().splitlines()}
    assert not {"motp", "motp-plugin"} & users
    assert not any("motp" in ln for ln in Path(box.files.group).read_text().splitlines())
    assert ("systemctl", "disable", "--now", units.TIMER_NAME) in box.system.calls


@owner
def test_purge_removes_the_unchanged_config_and_leaves_a_changed_one(box: Box) -> None:
    assert box.install() == 0
    assert box.uninstall(purge=True) == 0, box.text.getvalue()
    assert not Path(box.target.config_root).exists()
    assert box.install() == 0
    Path(box.target.config_file).write_text("# mine\n")
    assert box.uninstall(purge=True) == 1
    assert Path(box.target.config_file).read_text() == "# mine\n"
    assert "changed since install" in box.text.getvalue()


@owner
def test_a_tampered_manifest_deletes_nothing_outside_its_prefixes(box: Box) -> None:
    """T25: paths outside the prefixes, a traversal, a swapped link on the way."""
    assert box.install() == 0
    decoy = box.root / "etc/decoy"
    decoy.write_text("keep me")
    trap = box.root / "etc/trapdir"
    trap.mkdir()
    victim = trap / "cli.py"
    victim.write_bytes((Path(box.target.lib_dir) / "motp/cli.py").read_bytes())
    m = box.manifest()
    digest = manifest.sha256_bytes(b"keep me")
    forged = (
        Entry(str(decoy), "file", sha256=digest),
        Entry(box.target.prefix + "/../../etc/decoy", "file", sha256=digest),
        Entry(str(box.root / "etc"), "dir"),
        Entry(str(trap), "dir"),
        Entry(box.target.config_root + "/../decoy", "file", sha256=digest),
    )
    state_fd = os.open(box.target.state_dir, os.O_RDONLY)
    try:
        manifest.write(state_fd, manifest.Manifest(m.version, m.entries + forged, m.accounts))
    finally:
        os.close(state_fd)
    # Swap the program's motp/ directory for a link into the trap: same names, same hashes.
    lib = Path(box.target.lib_dir)
    real_pkg = lib / "motp"
    real_pkg.rename(lib / "moved")
    real_pkg.symlink_to(trap)
    assert box.uninstall() == 1
    assert decoy.read_text() == "keep me"
    assert victim.exists(), "a file was deleted through a link"
    text = box.text.getvalue()
    assert "outside the installer" in text and "a link or non-directory lies on the way" in text


@owner
def test_a_manifest_others_can_write_stops_uninstall(box: Box) -> None:
    assert box.install() == 0
    path = Path(box.target.state_dir) / manifest.NAME
    os.chown(path, account(TEST_USER)[0], -1)
    assert box.uninstall() == 1
    assert "not root's own file" in box.text.getvalue()
    assert Path(box.target.wrapper).exists()


@owner
def test_without_systemd_the_cron_entry_runs_the_collector(
    trusted_dir: Path, archive: Path
) -> None:
    box = Box(trusted_dir, archive, systemd=False)
    assert box.install() == 0, box.text.getvalue()
    cron = Path(box.target.cron_file).read_text()
    assert f"root {box.target.wrapper} collect --no-sandbox" in cron
    assert not Path(box.target.service_path).exists()
    assert box.manifest().scheduler == "cron"
    assert ("wrapper", "collect", "--no-sandbox") in box.system.calls
    assert not [c for c in box.system.calls if c[0] == "systemctl"]
    assert box.uninstall() == 0 and not Path(box.target.cron_file).exists()


@owner
def test_install_from_the_installed_tree_rebuilds_the_bytecode(box: Box) -> None:
    assert box.install(no_start=True) == 0
    pycs = list(Path(box.target.lib_dir).rglob("*.pyc"))
    for p in pycs[:5]:
        p.unlink()
    assert box.install(program=box.target.lib_dir, no_start=True) == 0, box.text.getvalue()
    assert all(p.exists() for p in pycs[:5])
    for e in box.manifest().entries:
        if e.kind == "file":
            assert manifest.sha256_bytes(Path(e.path).read_bytes()) == e.sha256


@owner
def test_no_start_starts_nothing(box: Box) -> None:
    assert box.install(no_start=True) == 0
    assert ("systemctl", "enable", units.TIMER_NAME) in box.system.calls
    assert not [c for c in box.system.calls if c[:2] == ("systemctl", "start")]
    assert not [c for c in box.system.calls if c[0] == "wrapper"]


@owner
def test_the_link_needs_a_directory_only_root_can_write(box: Box) -> None:
    (box.root / "usr/local/bin").chmod(0o2775)  # Debian's group staff layout
    assert box.install(no_start=True) == 0
    assert not os.path.lexists(box.target.local_bin_link)
    assert "no link" in box.text.getvalue()


@owner
def test_without_a_sudoers_rule_the_admin_tier_is_root_only(box: Box) -> None:
    box.sudoers("root ALL=(ALL:ALL) ALL\n# %sudo ALL=(ALL) ALL\n")
    assert box.install(no_start=True) == 0
    assert installer.STARTER_ADMIN_LINE in Path(box.target.config_file).read_text()
    assert box.manifest().admin_group == ""
    assert "admin details are for root only" in box.text.getvalue()


@owner
def test_sudoers_includes_and_untrusted_files(box: Box) -> None:
    d = box.root / "etc/sudoers.d"
    d.mkdir(mode=0o755)
    (d / "10-admins").write_text("%wheel ALL=(ALL) ALL\n")
    (d / "skipped.conf").write_text("%sudo ALL=(ALL) ALL\n")  # a dot: sudo skips it
    box.sudoers(f"@includedir {d}\n")
    assert admingroup.granted_groups(box.target.sudoers) == {"wheel"}
    (d / "10-admins").chmod(0o666)  # sudo refuses a file others can write; so do we
    assert admingroup.granted_groups(box.target.sudoers) == set()


# --- accounts (T24) ---------------------------------------------------------------------


@owner
@pytest.mark.parametrize(
    ("line", "group", "shadow", "msg"),
    [
        ("motp:x:960:960::/nonexistent:/bin/bash", "motp:x:960:", "motp:!:1", "login shell"),
        (
            "motp:x:960:960::/nonexistent:/usr/sbin/nologin",
            "motp:x:960:",
            "motp:$6$x:1",
            "not locked",
        ),
        (
            "motp:x:960:6::/nonexistent:/usr/sbin/nologin",
            "motp:x:960:",
            "motp:!:1",
            "primary group",
        ),
        (
            "motp:x:960:960::/nonexistent:/usr/sbin/nologin",
            "motp:x:960:alice",
            "motp:!:1",
            "primary group",
        ),
        (
            "motp:x:1960:1960::/nonexistent:/usr/sbin/nologin",
            "motp:x:1960:",
            "motp:!:1",
            "not one local",
        ),
    ],
)
def test_an_account_that_does_not_check_out_is_refused(
    box: Box, line: str, group: str, shadow: str, msg: str
) -> None:
    for path, text in (
        (box.files.passwd, line),
        (box.files.group, group),
        (box.files.shadow, shadow),
    ):
        with open(path, "a") as fh:
            fh.write(text + "\n")
    with pytest.raises(ContractError) as err:
        accounts.verify("motp", box.files)
    tr = i18n.translator("en")
    assert msg in tr.text(err.value.message)


@owner
@pytest.mark.skipif(not os.path.exists("/usr/sbin/useradd"), reason="image without useradd")
def test_the_system_tools_create_a_checked_account_and_remove_it() -> None:
    files = accounts.Files()
    tools = accounts.SystemTools()
    name = "motp-p7check"
    try:
        made = accounts.create(name, files, tools)
        assert 0 < made.uid <= 999 and made.gid > 0
        assert accounts.remove(made, files, tools) is None
        assert not accounts.look_up(name, files).exists
    finally:
        subprocess.run(["/usr/sbin/userdel", name], capture_output=True, check=False)


# --- doctor and invariant 7 -------------------------------------------------------------


@owner
def test_search_path_problems_flag_what_others_can_write(trusted_dir: Path) -> None:
    good = trusted_dir / "good"
    good.mkdir(mode=0o755)
    bad = trusted_dir / "bad"
    bad.mkdir()
    bad.chmod(0o775)
    missing = trusted_dir / "missing.zip"
    under_bad = bad / "missing.zip"
    problems = doctor.search_path_problems([str(good), str(bad), str(missing), str(under_bad), ""])
    assert [p for p, _ in problems] == [str(bad), str(under_bad), "."]


@owner
def test_invariant_7_the_installed_program_runs_with_a_root_only_search_path(box: Box) -> None:
    """Run the installed wrapper as root and as an ordinary user: its ``sys.path`` (the
    tree and the interpreter's own library) is writable by root only. Then make the tree
    group-writable and watch the check fail."""
    assert box.install(no_start=True) == 0, box.text.getvalue()
    wrapper = box.target.wrapper
    uid, gid = account(TEST_USER)

    def doctor_output(drop: Optional[proc.Drop]) -> str:
        result = proc.run(proc.Spec(argv=(wrapper, "doctor"), timeout=60, drop=drop))
        return result.stdout.decode()

    for drop in (None, proc.Drop(uid, gid)):
        text = doctor_output(drop)
        assert "Python search path:" in text and "all writable by root only" in text, text
        assert "search path entry" not in text, text
    os.chmod(box.target.lib_dir, 0o775)
    text = doctor_output(proc.Drop(uid, gid))
    assert f"Python search path entry {box.target.lib_dir}" in text, text


@owner
def test_doctor_reports_stale_bytecode(box: Box) -> None:
    assert box.install(no_start=True) == 0
    total, stale = doctor.stale_bytecode(box.target.lib_dir)
    assert total > 50 and stale == 0
    for pyc in list(Path(box.target.lib_dir).rglob("*.pyc"))[:3]:
        pyc.unlink()
    assert doctor.stale_bytecode(box.target.lib_dir) == (total, 3)


@owner
def test_doctor_lines_all_have_a_level(box: Box) -> None:
    assert box.install(no_start=True) == 0
    out = io.StringIO()
    places = doctor.Places(
        prefix=box.target.prefix,
        config_root=box.target.config_root,
        cache_dir=box.target.cache_dir,
        unit_dir=box.target.unit_dir,
        cron_file=box.target.cron_file,
        systemd_marker=box.target.systemd_marker,
        account_files=box.files,
    )
    code = doctor.main(out, places)
    lines = out.getvalue().splitlines()
    assert not any(ln.startswith("charset test: ") for ln in lines), "not a terminal"
    assert all(ln.split("]")[0] in ("[ok", "[info", "[warn", "[FAIL") for ln in lines), lines
    assert "[ok] account motp: a locked system account with a group of its own" in lines
    assert "[ok] admin group: sudo" in lines
    assert code in (0, 1)


# --- review findings of phase 7 -------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "groups"),
    [
        ("%sudo ALL=(ALL) /usr/bin/apt", set()),  # one command only
        ("%wheel otherhost=ALL", set()),  # another host
        ("%sudo ALL=(postgres) ALL", set()),  # another run-as user
        ("%sudo ALL=(:adm) ALL", set()),  # a group only: runs as the invoking user
        ("%wheel ALL=(root) NOPASSWD: ALL", {"wheel"}),
        ("%wheel ALL = ALL", {"wheel"}),
    ],
)
def test_only_full_sudo_rights_make_admins(line: str, groups: set[str]) -> None:
    assert admingroup.groups_in_rule(line) == groups


@owner
def test_an_unsafe_own_directory_stops_before_any_change(box: Box) -> None:
    conf = Path(box.target.config_root)
    conf.mkdir()
    conf.chmod(0o775)
    before = box.snapshot()
    assert box.install() == 1
    assert "stopped before any change" in box.text.getvalue()
    assert box.snapshot() == before and box.tools.calls == []


@owner
def test_an_archive_others_can_write_is_refused(box: Box, trusted_dir: Path) -> None:
    copy = trusted_dir / "loose.pyz"
    copy.write_bytes(box.archive.read_bytes())
    copy.chmod(0o666)
    assert box.install(program=copy) == 1
    assert "can be changed by users other than its owner" in box.text.getvalue()


@owner
def test_a_failure_after_the_accounts_leaves_them_in_the_manifest(
    box: Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Code review, high: an install that stopped after creating the accounts must not
    leave accounts that no later install or uninstall knows as its own."""

    def broken(*args: object) -> None:
        raise installer._fail("install.error.io")

    monkeypatch.setattr(installer, "install_config", broken)
    assert box.install() == 1
    assert {a.name for a in box.manifest().accounts} == {"motp", "motp-plugin"}
    monkeypatch.undo()
    assert box.install(no_start=True) == 0, box.text.getvalue()  # adopts them again
    assert box.uninstall() == 0, box.text.getvalue()
    users = {ln.split(":")[0] for ln in Path(box.files.passwd).read_text().splitlines()}
    assert not {"motp", "motp-plugin"} & users


@owner
def test_uninstall_keeps_a_manifest_while_an_account_is_left(box: Box) -> None:
    assert box.install() == 0
    real = box.tools.delete_user

    def busy(name: str) -> None:
        raise accounts._fail("install.error.tool_failed", tool="userdel", code=8)

    box.tools.delete_user = busy  # type: ignore[method-assign]
    assert box.uninstall() == 1
    assert [a.name for a in box.manifest().accounts] == ["motp", "motp-plugin"]
    box.tools.delete_user = real  # type: ignore[method-assign]
    assert box.uninstall() == 0, box.text.getvalue()
    assert not (Path(box.target.state_dir) / manifest.NAME).exists()


@owner
def test_an_upgrade_with_new_unit_text_reports_nothing_left(
    box: Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert box.install(no_start=True) == 0
    monkeypatch.setattr(units, "TIMER_TEXT", units.TIMER_TEXT + "# changed\n")
    box.text.truncate(0)
    box.text.seek(0)
    assert box.install(no_start=True) == 0, box.text.getvalue()
    assert "left in place" not in box.text.getvalue()
    assert Path(box.target.timer_path).read_text().endswith("# changed\n")
    assert ("systemctl", "stop", units.TIMER_NAME, units.SERVICE_NAME) in box.system.calls


@owner
def test_a_failed_scheduler_fails_the_install(box: Box) -> None:
    box.system.fail = True
    assert box.install() == 1
    assert "systemctl could not load, enable or start the units" in box.text.getvalue()


@owner
def test_install_waits_for_a_running_collection(box: Box) -> None:
    from motp.collect import store

    cache_fd = store.prepare_dir(box.target.cache_dir, store.CACHE_DIR_MODE)
    lock = store.acquire_lock(cache_fd)
    assert lock is not None
    try:
        with pytest.raises(ContractError):
            installer.collector_lock(box.target, box.out(), wait=1.0)
    finally:
        os.close(lock)
        os.close(cache_fd)
    os.close(installer.collector_lock(box.target, box.out(), wait=1.0))


@owner
def test_search_path_problems_cover_the_tree_ancestors_and_flags(
    box: Box, trusted_dir: Path
) -> None:
    """Security review: a writable file inside the tree, a missing entry below a writable
    ancestor, and a process without -I -S all count."""
    assert box.install(no_start=True) == 0
    lib = box.target.lib_dir
    assert doctor.search_path_problems([lib], lib) == []
    inner = Path(lib) / "motp" / "core" / "proc.py"
    inner.chmod(0o664)
    assert [p for p, _ in doctor.search_path_problems([lib], lib)] == [str(inner)]
    inner.chmod(0o644)
    loose = trusted_dir / "loose"
    loose.mkdir()
    loose.chmod(0o777)
    deep = str(loose / "a" / "b" / "python3.zip")
    assert [p for p, _ in doctor.search_path_problems([deep])] == [deep]
    assert [p for p, _ in doctor.search_path_problems([], isolated=False)] == ["-I -S"]


# --- login hooks and static mode (phase 8: 4.10, D7, O10, O11) ----------------------------

DEBIAN_ZPROFILE = "# /etc/zsh/zprofile: system-wide .zprofile file for zsh(1).\n"
FEDORA_ZPROFILE = "_src_etc_profile()\n{\n    emulate -L ksh\n    source /etc/profile\n}\n"


def zprofile(box: Box, name: str, text: str) -> Path:
    path = box.root / "etc" / name
    path.parent.mkdir(mode=0o755, exist_ok=True)
    path.write_text(text)
    path.chmod(0o644)
    return path


@owner
def test_hybrid_install_writes_the_login_hook_and_the_zsh_block(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    assert box.install() == 0, box.text.getvalue()
    t = box.target
    hook = Path(t.profile_hook)
    assert hook.read_text() == hooks.profile_hook(t.wrapper, t.timeout_program)
    assert mode(hook) == 0o644 and hook.stat().st_uid == 0
    assert zp.read_text() == DEBIAN_ZPROFILE + hooks.zsh_block(t.profile_hook)
    assert mode(zp) == 0o644
    m = box.manifest()
    assert m.mode == "hybrid"
    kinds = {e.path: e.kind for e in m.entries}
    assert kinds[t.profile_hook] == "file" and kinds[str(zp)] == "block"
    assert units.STATIC_LINE not in Path(t.service_path).read_text().splitlines()
    assert not Path(t.tmpfiles_file).exists() and not Path(t.motd_dir).exists()
    # A second install replaces its block, never adds one more.
    assert box.install() == 0, box.text.getvalue()
    assert zp.read_text().count("# BEGIN motp") == 1


@owner
def test_without_gnu_timeout_the_hook_calls_the_program_directly(box: Box) -> None:
    box.system.timeout = False
    assert box.install() == 0, box.text.getvalue()
    assert Path(box.target.profile_hook).read_text() == hooks.profile_hook(box.target.wrapper, None)


@owner
def test_a_zprofile_that_reads_etc_profile_gets_no_block(box: Box) -> None:
    zp = zprofile(box, "zprofile", FEDORA_ZPROFILE)
    assert box.install(dry_run=True) == 0
    assert "none needed" in box.text.getvalue()
    assert box.install() == 0, box.text.getvalue()
    assert zp.read_text() == FEDORA_ZPROFILE
    assert all(e.kind != "block" for e in box.manifest().entries)


@owner
def test_a_zprofile_others_can_write_is_left_alone(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    zp.chmod(0o666)
    assert box.install() == 0, box.text.getvalue()
    assert zp.read_text() == DEBIAN_ZPROFILE
    assert all(e.kind != "block" for e in box.manifest().entries)


@owner
def test_uninstall_takes_out_the_block_and_keeps_the_admins_lines(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    assert box.install() == 0
    with zp.open("a") as fh:
        fh.write("alias ll='ls -l'\n")
    assert box.uninstall() == 0, box.text.getvalue()
    assert zp.read_text() == DEBIAN_ZPROFILE + "alias ll='ls -l'\n"
    assert mode(zp) == 0o644
    assert not Path(box.target.profile_hook).exists()


@owner
def test_an_edited_block_is_left_and_reported(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    assert box.install() == 0
    zp.write_text(zp.read_text().replace("emulate sh", "emulate  sh"))
    assert box.uninstall() == 1
    assert "emulate  sh" in zp.read_text()
    assert "changed since install" in box.text.getvalue()


@owner
def test_static_install_prepares_the_unit_tmpfiles_and_directory(box: Box) -> None:
    assert box.install(mode="static") == 0, box.text.getvalue()
    t = box.target
    service = Path(t.service_path).read_text()
    assert service == t.service_text("static")
    assert f"ReadWritePaths=-{t.motd_dir}" in service.splitlines()
    assert Path(t.tmpfiles_file).read_text() == units.TMPFILES_TEXT.replace(
        units.MOTD_DIR, t.motd_dir
    )
    motd = Path(t.motd_dir)
    assert motd.is_dir() and mode(motd) == 0o755 and motd.stat().st_uid == 0
    assert not Path(t.profile_hook).exists()
    assert 'mode = "static"' in Path(t.config_file).read_text()
    assert config.load(t.config_root).config.general.mode == "static"
    assert box.manifest().mode == "static"
    # The collector's file goes with uninstall; the shared directory stays.
    (motd / "10-motp").write_text("text\n")
    (motd / "20-other").write_text("someone else\n")
    assert box.uninstall() == 0, box.text.getvalue()
    assert sorted(p.name for p in motd.iterdir()) == ["20-other"]
    assert not Path(t.tmpfiles_file).exists()


@owner
def test_a_mode_that_differs_from_the_config_stops_before_any_change(box: Box) -> None:
    assert box.install() == 0
    before = {p: os.lstat(box.root / p).st_mtime_ns for p in box.snapshot()}
    box.text.truncate(0)
    assert box.install(mode="static") == 1
    assert "sets mode hybrid" in box.text.getvalue()
    assert before == {p: os.lstat(box.root / p).st_mtime_ns for p in box.snapshot()}


@owner
def test_switching_modes_removes_the_other_modes_files(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    assert box.install() == 0
    conf = Path(box.target.config_file)
    conf.write_text(conf.read_text().replace('# mode = "hybrid"', 'mode = "static"'))
    assert box.install(mode="static") == 0, box.text.getvalue()
    assert not Path(box.target.profile_hook).exists()
    assert zp.read_text() == DEBIAN_ZPROFILE
    motd = Path(box.target.motd_dir) / "10-motp"
    motd.write_text("old static text\n")
    conf.write_text(conf.read_text().replace('mode = "static"', 'mode = "hybrid"'))
    assert box.install() == 0, box.text.getvalue()
    assert not motd.exists() and Path(box.target.profile_hook).exists()
    assert not Path(box.target.tmpfiles_file).exists()
    assert units.STATIC_LINE not in Path(box.target.service_path).read_text().splitlines()


@owner
def test_doctor_reports_the_mode_and_its_login_side(box: Box) -> None:
    assert box.install() == 0
    places = doctor.Places(
        prefix=box.target.prefix,
        config_root=box.target.config_root,
        cache_dir=box.target.cache_dir,
        unit_dir=box.target.unit_dir,
        cron_file=box.target.cron_file,
        systemd_marker=box.target.systemd_marker,
        account_files=box.files,
        profile_hook=box.target.profile_hook,
        motd_dir=box.target.motd_dir,
    )
    settings = config.load(box.target.config_root).config
    r = doctor.Report()
    doctor.check_login(r, settings, places, 0)
    assert [(lvl, m.id) for lvl, m in r.lines] == [("info", "doctor.mode"), ("ok", "doctor.hook")]
    static = replace_mode(settings, "static")
    r = doctor.Report()
    doctor.check_login(r, static, places, 0)
    ids = [m.id for _, m in r.lines]
    assert "doctor.other_mode_left" in ids and "doctor.static_unit" in ids
    assert "doctor.static_missing" in ids


def replace_mode(settings: config.Config, mode_name: str) -> config.Config:
    from dataclasses import replace as dc_replace

    return dc_replace(settings, general=dc_replace(settings.general, mode=mode_name))


def test_the_unit_for_static_mode_adds_exactly_its_line() -> None:
    hybrid = units.service_text_for("hybrid").splitlines()
    static = units.service_text_for("static").splitlines()
    assert hybrid == units.SERVICE_TEXT.splitlines()
    assert [ln for ln in static if ln not in hybrid] == [units.STATIC_LINE]
    assert units.MODE_ADDITIONS["static"][0] == units.STATIC_LINE


def test_the_collector_unit_keeps_run_read_only_except_its_own_directories() -> None:
    """Phase 14: on systemd 252 ``ProtectSystem=strict`` together with
    ``ProtectKernelTunables=`` left ``/run`` writable, so root probes could write there."""
    for mode in ("hybrid", "static"):
        lines = units.service_text_for(mode).splitlines()
        assert "ReadOnlyPaths=/run" in lines
        assert "ReadWritePaths=/run/motp" in lines
    static = units.service_text_for("static").splitlines()
    assert units.STATIC_LINE in static  # /run/motd.d stays writable in static mode only
    assert units.STATIC_LINE not in units.service_text_for("hybrid").splitlines()


def test_the_starter_config_carries_the_mode() -> None:
    text = installer.starter_config("sudo", "static").decode()
    assert '\nmode = "static"' in text and "# mode =" not in text
    assert config.check_content(text.encode()) == []
    assert '# mode = "hybrid"' in installer.starter_config("sudo").decode()


def test_a_phase_7_manifest_without_a_mode_reads_as_hybrid() -> None:
    m = manifest.Manifest(version="0", scheduler="cron")
    data = manifest.encode(m)
    assert b'"mode":"hybrid",' in data
    old = data.replace(b'"mode":"hybrid",', b"")
    assert manifest.decode(old).mode == "hybrid"
    with pytest.raises(ContractError):
        manifest.decode(data.replace(b'"hybrid"', b'"loud"'))


@owner
def test_timeout_as_a_coreutils_script_counts_as_usable(trusted_dir: Path) -> None:
    """O11 on the RHEL family: /usr/bin/timeout is a script of the multi-call coreutils
    binary. The hook runs it as the user, so the root-only launcher rule must not refuse
    it (phase 8: the hook on almalinux:9 had no outer limit)."""
    real = "/usr/bin/timeout"
    if not os.path.exists(real):
        pytest.skip("no timeout here")
    bin_dir = trusted_dir / "bin"
    bin_dir.mkdir(mode=0o755)
    multi = bin_dir / "coreutils"
    multi.write_text(f'#!/bin/sh\nshift 2\nexec {real} "$@"\n')
    multi.chmod(0o755)
    script = bin_dir / "timeout"
    script.write_text(f"#!{multi} --coreutils-prog-shebang=timeout\n")
    script.chmod(0o755)
    system = installer.RealSystem()
    assert system.timeout_ok(str(script), PY3)
    assert system.timeout_ok(real, PY3)
    assert not system.timeout_ok(str(bin_dir / "missing"), PY3)


def test_the_zsh_block_is_found_by_its_markers() -> None:
    block = hooks.zsh_block().encode()
    assert manifest.find_block(block) == (0, len(block))
    text = b"# distro zprofile\nPATH=x\n" + block + b"tail\n"
    start, end = manifest.find_block(text)  # type: ignore[misc]
    assert text[start:end] == block
    assert manifest.find_block(b"PATH=x\n") is None
    # An editor dropped the last line feed: still the one block, up to the end of file.
    cut = text[: text.index(b"tail")].rstrip(b"\n")
    assert manifest.find_block(cut) == (text.index(block), len(cut))


@pytest.mark.parametrize(
    "text",
    [
        b"x\n# BEGIN motp: half removed\nalias ll='ls -l'\n",  # an orphan begin line
        b"x\nalias ll='ls -l'\n# END motp\n",  # an orphan end line
        b"# END motp\n# BEGIN motp: wrong order\n",
        b"x # BEGIN motp: not at a line start\n# END motp\n",
        hooks.zsh_block().encode() * 2,
    ],
)
def test_marker_lines_that_are_not_one_whole_block_are_refused(text: bytes) -> None:
    """Phase 8 reviews: a half-removed or doubled block must never make the span reach
    over the admin's own lines."""
    with pytest.raises(manifest.BrokenBlock):
        manifest.find_block(text)


@owner
def test_an_orphan_marker_line_keeps_the_installer_away_from_the_file(box: Box) -> None:
    text = DEBIAN_ZPROFILE + "# BEGIN motp: half removed\nalias ll='ls -l'\n"
    zp = zprofile(box, "zsh/zprofile", text)
    assert box.install(dry_run=True) == 0
    assert "not one whole block" in box.text.getvalue()
    assert box.install() == 0, box.text.getvalue()
    assert box.install() == 0, box.text.getvalue()
    assert zp.read_text() == text
    assert all(e.kind != "block" for e in box.manifest().entries)


@owner
def test_a_block_whose_last_line_feed_was_dropped_is_still_removed(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    assert box.install() == 0
    zp.write_text(zp.read_text().rstrip("\n"))
    assert box.uninstall() == 0, box.text.getvalue()
    assert zp.read_text() == DEBIAN_ZPROFILE


@owner
def test_a_zprofile_that_names_etc_profile_only_in_a_comment_gets_the_block(box: Box) -> None:
    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE + "# unlike bash, zsh skips /etc/profile\n")
    assert box.install() == 0, box.text.getvalue()
    assert "# BEGIN motp" in zp.read_text()


@owner
def test_a_forged_whole_file_entry_for_a_zprofile_deletes_nothing(box: Box) -> None:
    """Security review, phase 8 (T25): a system zprofile is only ever a block."""
    import json

    zp = zprofile(box, "zsh/zprofile", DEBIAN_ZPROFILE)
    assert box.install() == 0
    path = Path(box.target.state_dir) / manifest.NAME
    doc = json.loads(path.read_text())
    digest = manifest.sha256_bytes(zp.read_bytes())
    doc["entries"] = [e for e in doc["entries"] if e["path"] != str(zp)]
    doc["entries"].append({"path": str(zp), "kind": "file", "role": "program", "sha256": digest})
    path.write_text(json.dumps(doc))
    path.chmod(0o600)
    assert box.uninstall() == 1
    assert zp.exists() and "outside" in box.text.getvalue()


@owner
def test_a_static_file_left_by_a_half_finished_switch_goes_with_the_next_install(
    box: Box,
) -> None:
    """Code review, phase 8: the manifest says hybrid already, the file is still there."""
    assert box.install() == 0
    motd = Path(box.target.motd_dir)
    motd.mkdir(mode=0o755)
    (motd / "10-motp").write_text("old static text\n")
    assert box.manifest().mode == "hybrid"
    assert box.install() == 0, box.text.getvalue()
    assert not (motd / "10-motp").exists()
    (motd / "10-motp").write_text("old static text\n")
    assert box.uninstall() == 0, box.text.getvalue()
    assert not (motd / "10-motp").exists()


@owner
def test_the_timeout_probe_refuses_other_launcher_scripts(trusted_dir: Path) -> None:
    """Security review, phase 8: only the coreutils form is let through the root rules."""
    bin_dir = trusted_dir / "bin2"
    bin_dir.mkdir(mode=0o755)
    for name, line in (
        ("via-env", "#!/usr/bin/env timeout\n"),
        ("other-arg", f"#!{bin_dir}/coreutils --coreutils-prog-shebang=sleep\n"),
    ):
        script = bin_dir / name
        script.write_text(line)
        script.chmod(0o755)
    multi = bin_dir / "coreutils"
    multi.write_text('#!/bin/sh\nshift 2\nexec /usr/bin/timeout "$@"\n')
    multi.chmod(0o755)
    system = installer.RealSystem()
    assert not system.timeout_ok(str(bin_dir / "via-env"), PY3)
    assert not system.timeout_ok(str(bin_dir / "other-arg"), PY3)


@owner
def test_doctor_judges_the_static_file_by_the_timer_period(box: Box) -> None:
    """Code review, phase 8: the age limit came from a fixed 300 s, not render.json."""
    from dataclasses import replace as dc_replace

    from motp.collect import runner, store
    from motp.core import cache

    assert box.install(mode="static") == 0, box.text.getvalue()
    now = 2_000_000_000
    settings = config.load(box.target.config_root).config
    render = dc_replace(runner.render_settings(settings, now, "apt"), timer_period=600)
    run = Path(box.target.cache_dir)
    (run / store.RENDER_NAME).write_bytes(cache.encode_render_file(render))
    static = Path(box.target.motd_dir) / store.MOTD_NAME
    static.write_text("text\n")
    os.utime(static, (now - 1000, now - 1000))
    places = doctor.Places(
        unit_dir=box.target.unit_dir,
        cache_dir=box.target.cache_dir,
        systemd_marker=box.target.systemd_marker,
        profile_hook=box.target.profile_hook,
        motd_dir=box.target.motd_dir,
    )
    r = doctor.Report()
    doctor.check_login(r, settings, places, now)
    assert ("ok", "doctor.static_file") in [(lvl, m.id) for lvl, m in r.lines]
