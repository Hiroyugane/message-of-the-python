"""Per-user data from probe to file (D32 as amended, phase 10): the ``users`` field of the
probe protocol and the ACL entry the store writes. The collector's handling of the files
is in ``test_collect.py`` (as root, in the containers)."""

import json
import struct

import pytest

from motp.collect import child, store
from motp.core import probe
from motp.core.model import ContractError, Login, UserLogins

NOW = 1795600000


def doc(users: object, module: str = "os_login", **extra: object) -> bytes:
    return json.dumps({"api": 1, "module": module, "items": [], "users": users, **extra}).encode()


def one(uid: int = 1000, **login: object) -> dict[str, object]:
    entry = {"started": NOW - 60, "source": "192.0.2.1", "tty": "pts/0", **login}
    return {"uid": uid, "logins": [entry]}


# --- the protocol ----------------------------------------------------------------------


def test_os_login_may_send_users() -> None:
    parsed = probe.validate_builtin(doc([one(1000), one(0)]), "os_login", generated=NOW)
    assert parsed.users == (
        UserLogins(1000, NOW, (Login(NOW - 60, "192.0.2.1", "pts/0"),)),
        UserLogins(0, NOW, (Login(NOW - 60, "192.0.2.1", "pts/0"),)),
    )


def test_a_document_without_users_has_none() -> None:
    data = json.dumps({"api": 1, "module": "os_login", "items": []}).encode()
    assert probe.validate_builtin(data, "os_login").users is None


@pytest.mark.parametrize("module", ["os_units", "os_sessions", "hw_disks"])
def test_no_other_module_may_send_users(module: str) -> None:
    with pytest.raises(ContractError) as err:
        probe.validate_builtin(doc([one()], module=module), module)
    assert err.value.message.id == "probe.error.unknown_field"


def test_a_plugin_may_not_send_users() -> None:
    data = json.dumps({"api": 1, "module": "10-x", "items": [], "users": [one()]}).encode()
    with pytest.raises(ContractError):
        probe.validate_plugin(data, 0, "10-x", public=False)


@pytest.mark.parametrize(
    "users",
    [
        "x",
        [one(1000), one(1000)],  # the same uid twice
        [one(-1)],
        [one(2**32 - 1)],  # (uid_t) -1
        [one(True)],
        [{"uid": 1, "logins": []}],
        [{"uid": 1, "logins": [one()["logins"][0]] * 4}],  # type: ignore[index]
        [{"uid": 1}],
        [{"uid": 1, "logins": [{"started": NOW}], "name": "alice"}],
        [one(started=0)],
        [one(started=2**41)],
        [one(started=1.5)],
        [one(source="x" * 257)],
        [one(tty=7)],
        [one(command="rm -rf /")],
        [one(n) for n in range(probe.MAX_USERS + 1)],
    ],
)
def test_bad_users_reject_the_document(users: object) -> None:
    with pytest.raises(ContractError):
        probe.validate_builtin(doc(users), "os_login")


def test_user_strings_are_sanitised() -> None:
    hostile = "203.0.113.5\x1b]0;owned\x07\x1b[2J‮evil"
    parsed = probe.validate_builtin(doc([one(source=hostile, tty="pts/1\x1b[5m")]), "os_login")
    assert parsed.users is not None
    (login,) = parsed.users[0].logins
    assert "\x1b" not in login.source and "\x07" not in login.source and "‮" not in login.source
    assert "\x1b" not in login.tty


def test_only_os_login_gets_the_larger_document() -> None:
    big = [one(n, source="x" * 200) for n in range(probe.MAX_USERS)]
    data = doc(big)
    assert probe.MAX_DOCUMENT_BYTES < len(data) <= probe.PER_USER_DOCUMENT_BYTES
    assert probe.validate_builtin(data, "os_login").users is not None
    padded = json.dumps({"api": 1, "module": "os_units", "items": [], "x": "y" * len(data)})
    with pytest.raises(ContractError):
        probe.validate_builtin(padded.encode(), "os_units")


def test_the_probe_cuts_the_least_recent_accounts_to_fit() -> None:
    users = [
        UserLogins(n, NOW, tuple(Login(NOW - n, "ä" * 256, "t" * 32) for _ in range(3)))
        for n in range(probe.MAX_USERS)
    ]
    data = child.document("os_login", [], users)
    assert len(data) <= probe.PER_USER_DOCUMENT_BYTES
    parsed = probe.validate_builtin(data, "os_login")
    assert parsed.users is not None and parsed.users[0].uid == 0
    kept = [u.uid for u in parsed.users]
    assert kept == list(range(len(kept))) and len(kept) < probe.MAX_USERS


# --- the ACL entry ---------------------------------------------------------------------


def test_the_acl_names_root_and_one_reader() -> None:
    data = store.reader_acl(1234)
    version, *rest = struct.unpack("<I" + "HHI" * 5, data)
    entries = [tuple(rest[i : i + 3]) for i in range(0, 15, 3)]
    assert version == 2
    assert entries == [
        (store.ACL_USER_OBJ, 4, store.ACL_NO_ID),
        (store.ACL_USER, 4, 1234),
        (store.ACL_GROUP_OBJ, 0, store.ACL_NO_ID),
        (store.ACL_MASK, 4, store.ACL_NO_ID),
        (store.ACL_OTHER, 0, store.ACL_NO_ID),
    ]


@pytest.mark.parametrize("uid", [-1, 2**32 - 1, 2**40, "1000", True])
def test_no_acl_for_a_uid_that_is_not_one(uid: object) -> None:
    with pytest.raises(ContractError):
        store.reader_acl(uid)  # type: ignore[arg-type]
