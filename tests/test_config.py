"""Configuration loader (blueprint 4.7, D9, D33, T1, T17)."""

import os
import sys
from pathlib import Path
from typing import Optional

import pytest

from motp.core import config, i18n, safepath
from motp.core.cache import Layout
from motp.core.config import Loaded, Problem
from motp.core.model import ContractError, MessageRef, contract_error
from motp.core.thresholds import Direction

from .conftest import OTHER_USER, SRC, account

linux_root = pytest.mark.needs_linux_owner
TR = i18n.Translator("en")
STARTER = (SRC / "motp" / "data" / "starter-config.toml").read_bytes()


def plain_read(path: str, max_bytes: int) -> bytes:
    """A reader without the ownership check, for systems without owners."""
    data = Path(path).read_bytes()
    if len(data) > max_bytes:
        raise contract_error("safepath.error.too_large", path=path)
    return data


def tree(root: Path, main: Optional[str] = None, **dropins: str) -> Path:
    if main is not None:
        (root / "config.toml").write_text(main, encoding="utf-8")
    if dropins:
        (root / "conf.d").mkdir(exist_ok=True)
        for name, text in dropins.items():
            (root / "conf.d" / name.replace("_", "-", 1)).write_text(text, encoding="utf-8")
    return root


def load(root: Path) -> Loaded:
    return config.load(str(root), read=plain_read)


def texts(problems: "tuple[Problem, ...] | list[MessageRef]") -> list[str]:
    refs = [p.reason if isinstance(p, Problem) else p for p in problems]
    return [TR.text(r) for r in refs]


def uncommented(starter: bytes) -> bytes:
    """The starter with every commented setting switched on ("## " lines are prose)."""
    lines = starter.decode().splitlines()
    return "\n".join(ln[2:] if ln.startswith("# ") else ln for ln in lines).encode()


# --- defaults and the starter file ----------------------------------------------------


def test_defaults_follow_the_blueprint() -> None:
    c = config.defaults()
    assert (c.general.mode, c.general.language) == ("hybrid", "auto")
    assert (c.limits.render_ms, c.limits.probe_timeout_s, c.limits.collect_total_s) == (
        1000,
        5.0,
        60,
    )
    assert c.visibility.admin_group == ""
    assert c.layout == Layout()
    rules = c.thresholds
    assert (rules["disk_used_percent"].warn, rules["disk_used_percent"].crit) == (80, 90)
    assert (rules["load_per_core"].warn, rules["load_per_core"].crit) == (0.7, 1.0)
    assert rules["cert_days_left"].direction is Direction.LOWER_IS_WORSE
    assert c.module("sec_fail2ban") == config.ModuleConfig("auto", None)
    assert c.plugin("50-x") == config.PluginConfig("motp-plugin", None, "admin")
    assert (c.unit_rows, c.file_age_rows, dict(c.plugins)) == ((), (), {})


def test_starter_file_is_valid_as_written_and_with_every_setting_switched_on() -> None:
    assert config.check_content(STARTER) == []
    switched_on = uncommented(STARTER)
    assert config.check_content(switched_on) == []
    raw, problems = config.read_layer(switched_on)
    assert raw is not None and not problems
    c = config.build(config.merge(config._default_raw(), raw))
    d = config.defaults()
    # The starter shows the defaults, so switching them on changes nothing...
    for name in ("general", "limits", "visibility", "layout", "thresholds"):
        assert getattr(c, name) == getattr(d, name), name
    # ...and its examples are complete.
    assert c.unit_rows[0].name == "nginx.service"
    assert c.file_age_rows[0].warn_after == 26 * 3600
    assert c.file_age_rows[0].crit_after == 3 * 86400
    assert c.plugin("50-backup-status").timeout_s == 5.0
    assert c.module("sec_fail2ban").enabled == "auto"


def test_empty_or_missing_tree_gives_the_defaults(tmp_path: Path) -> None:
    loaded = load(tmp_path / "nonexistent")
    assert loaded.config == config.defaults()
    assert loaded.applied == () and loaded.problems == ()


# --- load order and merging -----------------------------------------------------------


def test_files_load_in_name_order_and_override_key_by_key(tmp_path: Path) -> None:
    tree(
        tmp_path,
        "[limits]\nrender_ms = 800\nprobe_timeout_s = 3\n",
        **{
            "20_b.toml": "[limits]\nrender_ms = 600\n",
            "10_a.toml": "[limits]\nrender_ms = 700\n[general]\nlanguage = 'de'\n",
            "05_c.txt": "[limits]\nrender_ms = 1\n",
            ".30-hidden.toml": "[limits]\nrender_ms = 2\n",
        },
    )
    loaded = load(tmp_path)
    assert loaded.problems == ()
    assert [os.path.basename(p) for p in loaded.applied] == [
        "config.toml",
        "10-a.toml",
        "20-b.toml",
    ]
    c = loaded.config
    assert c.limits.render_ms == 600  # last file wins
    assert c.limits.probe_timeout_s == 3.0  # kept from config.toml
    assert c.limits.collect_total_s == 60  # default
    assert c.general.language == "de"


def test_threshold_tables_merge_with_the_defaults(tmp_path: Path) -> None:
    tree(
        tmp_path,
        "[thresholds.disk_used_percent]\nwarn = 85\n[thresholds.mem]\nwarn = 1\ncrit = 2\n",
    )
    c = load(tmp_path).config
    assert (c.thresholds["disk_used_percent"].warn, c.thresholds["disk_used_percent"].crit) == (
        85,
        90,
    )
    assert c.thresholds["mem"].crit == 2


def test_rows_of_all_files_add_up(tmp_path: Path) -> None:
    row = "[[rows.unit]]\nname = '{0}.service'\nlabel = '{0}'\n"
    tree(tmp_path, row.format("a"), **{"10_x.toml": row.format("b") + row.format("c")})
    c = load(tmp_path).config
    assert [r.name for r in c.unit_rows] == ["a.service", "b.service", "c.service"]


def test_too_many_dropins_are_cut_and_reported(tmp_path: Path) -> None:
    tree(tmp_path, None, **{f"{i:03d}_x.toml": "" for i in range(config.MAX_DROPINS + 3)})
    loaded = load(tmp_path)
    assert len(loaded.applied) == config.MAX_DROPINS
    assert [p.reason.id for p in loaded.problems] == ["config.error.too_many_files"]


# --- validation -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "msg_id", "key", "expected"),
    [
        (
            "[limits]\nrender_ms = 'fast'\n",
            "config.error.integer",
            "limits.render_ms",
            "from 100 to 10000",
        ),
        ("[limits]\nrender_ms = 5\n", "config.error.integer", "limits.render_ms", "whole number"),
        (
            "[limits]\nrender_ms = true\n",
            "config.error.integer",
            "limits.render_ms",
            "whole number",
        ),
        (
            "[limits]\nprobe_timeout_s = 31\n",
            "config.error.number",
            "limits.probe_timeout_s",
            "from 0.5 to 30",
        ),
        (
            "[limits]\nprobe_timeout_s = nan\n",
            "config.error.number",
            "limits.probe_timeout_s",
            "number",
        ),
        ("[general]\nmode = 'both'\n", "config.error.choice", "general.mode", "hybrid, static"),
        (
            "[general]\nlanguage = 'German'\n",
            "config.error.language",
            "general.language",
            "language code",
        ),
        (
            "[general]\nmood = 1\n",
            "config.error.unknown_key",
            "general.mood",
            "not a known setting",
        ),
        ("[extras]\nx = 1\n", "config.error.unknown_key", "extras", "not a known setting"),
        ("general = 1\n", "config.error.table", "general", "must be a table"),
        (
            "[visibility]\nadmin_group = 'adm'\n",
            "config.error.group_adm",
            "visibility.admin_group",
            "adm",
        ),
        (
            "[visibility]\nadmin_group = 'Wheel Group'\n",
            "config.error.group_name",
            "visibility.admin_group",
            "group name",
        ),
        (
            "[layout]\nsections = ['host', 'host']\n",
            "config.error.sections",
            "layout.sections",
            "section names",
        ),
        (
            '[layout]\nheader_text = "a\\u001b[31mb"\n',
            "config.error.label",
            "layout.header_text",
            "plain text",
        ),
        (
            "[modules.sec_fail2ban]\nenabled = 'yes'\n",
            "config.error.bool_or_auto",
            "modules.sec_fail2ban.enabled",
            "true, false",
        ),
        (
            "[modules.Bad-Name]\nenabled = true\n",
            "config.error.name",
            "modules.Bad-Name",
            "lower-case",
        ),
        (
            '[plugins."50-x"]\nrun_as = "nobody"\n',
            "config.error.choice",
            "plugins.50-x.run_as",
            "motp-plugin, root",
        ),
        (
            '[plugins."x50"]\nrun_as = "root"\n',
            "config.error.plugin_name",
            "plugins.x50",
            "two digits",
        ),
        (
            '[plugins."50-x"]\nrun_as = "root"\nshell = "/bin/sh"\n',
            "config.error.unknown_key",
            "plugins.50-x.shell",
            "not a known",
        ),
        (
            "[[rows.unit]]\nname = 'nginx'\nlabel = 'Web'\n",
            "config.error.unit_name",
            "rows.unit.name",
            "unit name",
        ),
        (
            "[[rows.unit]]\nname = 'a.service'\n",
            "config.error.missing_key",
            "rows.unit.label",
            "missing",
        ),
        ("[rows]\nunit = 'a.service'\n", "config.error.rows", "rows.unit", "list of tables"),
        ("[[rows.disk]]\nx = 1\n", "config.error.unknown_key", "rows.disk", "not a known"),
        (
            "[[rows.file_age]]\npath = 'rel'\nlabel = 'B'\nwarn_after = '1h'\ncrit_after = '2h'\n",
            "config.error.absolute_path",
            "rows.file_age.path",
            "absolute",
        ),
        (
            "[[rows.file_age]]\npath = '/x'\nlabel = 'B'\nwarn_after = '1w'\ncrit_after = '2h'\n",
            "config.error.duration",
            "rows.file_age.warn_after",
            "26h",
        ),
        (
            "[thresholds.disk_used_percent]\nwarn = '80%'\n",
            "config.error.any_number",
            "thresholds.disk_used_percent.warn",
            "number",
        ),
        (
            "[thresholds.disk_used_percent]\ndirection = 'up'\n",
            "config.error.choice",
            "thresholds.disk_used_percent.direction",
            "higher, lower",
        ),
    ],
)
def test_wrong_values_name_key_and_expected_type(
    text: str, msg_id: str, key: str, expected: str
) -> None:
    problems = config.check_content(text.encode())
    assert [p.id for p in problems] == [msg_id]
    assert str(problems[0].param_dict()["key"]).replace('"', "") == key
    rendered = TR.text(problems[0])
    assert expected in rendered and "{" not in rendered.replace("[[", "")


@pytest.mark.parametrize(
    ("text", "msg_id"),
    [
        ("[thresholds.disk_used_percent]\nwarn = 95\n", "rule.error.order"),
        ("[thresholds.new_rule]\nwarn = 1\n", "config.error.rule_limits"),
        ("[thresholds.x]\nwarn = 1\ncrit = 1\n", "rule.error.direction"),
        (
            "[[rows.file_age]]\npath = '/x'\nlabel = 'B'\nwarn_after = '3d'\ncrit_after = '26h'\n",
            "config.error.age_order",
        ),
    ],
)
def test_problems_across_keys_are_found_after_merging(text: str, msg_id: str) -> None:
    assert [p.id for p in config.check_content(text.encode())] == [msg_id]


def test_every_problem_of_a_file_is_reported() -> None:
    text = "[general]\nmode = 1\nlanguage = 2\n[limits]\nrender_ms = 'x'\n[nope]\n"
    assert len(config.check_content(text.encode())) == 4


def test_syntax_errors_report_line_and_column_only() -> None:
    problems = config.check_content(b'[general]\nmode = "hybrid"\nsecret = "abc\nmore = 1\n')
    assert [p.id for p in problems] == ["config.error.syntax"]
    params = problems[0].param_dict()
    assert params["line"] == 3
    assert "abc" not in TR.text(problems[0])


def test_non_utf8_and_deep_nesting_are_refused() -> None:
    assert [p.id for p in config.check_content(b"x = '\xff'\n")] == ["config.error.encoding"]
    deep = b"x = " + b"[" * 50_000 + b"]" * 50_000
    assert [p.id for p in config.check_content(deep)] in (
        ["config.error.too_deep"],
        ["config.error.syntax"],
    )


def test_key_paths_quote_names_that_are_not_bare_keys() -> None:
    assert config.key_path("plugins", "50-x", "a") == "plugins.50-x.a"
    assert config.key_path("plugins", 'a b"c', "x") == 'plugins."a b\\"c".x'


def test_a_file_with_any_problem_is_ignored_as_a_whole(tmp_path: Path) -> None:
    tree(
        tmp_path,
        "[limits]\nrender_ms = 700\n",
        **{"10_bad.toml": "[limits]\nrender_ms = 500\ncollect_total_s = 'long'\n"},
    )
    loaded = load(tmp_path)
    assert loaded.config.limits.render_ms == 700  # the bad file's valid key is not applied
    assert [os.path.basename(p.file) for p in loaded.problems] == ["10-bad.toml"]
    assert loaded.problems[0].reason.param_dict()["key"] == "limits.collect_total_s"


def test_a_file_that_breaks_a_merged_rule_is_ignored(tmp_path: Path) -> None:
    tree(
        tmp_path,
        "[thresholds.disk_used_percent]\ncrit = 99\n",
        **{"10_x.toml": "[thresholds.disk_used_percent]\nwarn = 99.5\n"},
    )
    loaded = load(tmp_path)
    rule = loaded.config.thresholds["disk_used_percent"]
    assert (rule.warn, rule.crit) == (80, 99)
    assert [p.reason.id for p in loaded.problems] == ["rule.error.order"]


def test_a_refused_file_is_ignored_with_its_reason(tmp_path: Path) -> None:
    tree(tmp_path, "[limits]\nrender_ms = 700\n", **{"10_x.toml": "[limits]\nrender_ms = 900\n"})

    def refuse_main(path: str, max_bytes: int) -> bytes:
        if path.endswith("config.toml"):
            raise contract_error("safepath.error.writable", path=path)
        return plain_read(path, max_bytes)

    loaded = config.load(str(tmp_path), read=refuse_main)
    assert loaded.config.limits.render_ms == 900
    assert [p.reason.id for p in loaded.problems] == ["safepath.error.writable"]


def test_every_config_message_renders_with_its_parameters() -> None:
    english = i18n.english()
    ids = [i for i in english.ids() if i.startswith(("config.error.", "safepath.error."))]
    assert len(ids) > 40
    for msg_id in ids:
        text = TR.message(msg_id, {"key": "k", "max": 1, "low": 1, "high": 2, "choices": "a",
                                   "line": 1, "column": 1, "path": "/p"})  # fmt: skip
        assert "{" not in text.replace("[[", ""), msg_id


# --- the two parsers ------------------------------------------------------------------

DOCUMENTS = [
    b"[general]\nmode = 'static'\n[limits]\nprobe_timeout_s = 2.5\n",
    b'[plugins."50-a"]\nvisibility = "public"\n[[rows.unit]]\nname = "a.service"\nlabel = "A"\n',
    b"x = 1979-05-27T07:32:00Z\ny = [1, 2.0, 'three']\nz = { a = 1 }\n",
    b"[a]\nx = 1\n[a]\ny = 2\n",
    b"x = 'unterminated\n",
    b"x = 1\nx = 2\n",
    b"[general\n",
    b"x = 0x\n",
]


def _outcome(module: object, data: bytes) -> object:
    try:
        return module.loads(data.decode())  # type: ignore[attr-defined]
    except module.TOMLDecodeError as exc:  # type: ignore[attr-defined]
        match = config.TOML_POSITION.search(str(exc))
        return ("error", match.groups() if match else None)


def test_the_running_python_uses_the_expected_parser() -> None:
    if sys.version_info >= (3, 11):
        assert config.TOML_PARSER == "tomllib"
    else:
        assert config.TOML_PARSER == "motp._vendor.tomli"


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib exists from Python 3.11")
@pytest.mark.parametrize("data", DOCUMENTS)
def test_tomllib_and_the_vendored_tomli_agree(data: bytes) -> None:
    import tomllib  # type: ignore[import-not-found, unused-ignore]

    from motp._vendor import tomli

    assert _outcome(tomllib, data) == _outcome(tomli, data)


@pytest.mark.parametrize("data", DOCUMENTS)
def test_loader_results_do_not_depend_on_the_parser(data: bytes) -> None:
    """Pinned outcomes, so the 3.9 and 3.11+ container runs prove the same results."""
    problems = [(p.id, sorted(p.params)) for p in config.check_content(data)]
    expected = {
        0: [],
        1: [],
        2: [("config.error.unknown_key", [("key", "x")]),
            ("config.error.unknown_key", [("key", "y")]),
            ("config.error.unknown_key", [("key", "z")])],
        3: [("config.error.syntax", [("column", 3), ("line", 3)])],
        4: [("config.error.syntax_end", [])],
        5: [("config.error.syntax", [("column", 6), ("line", 2)])],
        6: [("config.error.syntax", [("column", 9), ("line", 1)])],
        7: [("config.error.syntax", [("column", 6), ("line", 1)])],
    }[DOCUMENTS.index(data)]  # fmt: skip
    assert problems == expected


# --- ownership, Linux as root ---------------------------------------------------------


@linux_root
def test_trusted_tree_loads_through_the_ownership_check(trusted_dir: Path) -> None:
    root = tree(
        trusted_dir, "[limits]\nrender_ms = 700\n", **{"10_x.toml": "[general]\nmode = 'static'\n"}
    )
    os.chmod(root / "conf.d", 0o755)
    for f in (root / "config.toml", root / "conf.d" / "10-x.toml"):
        os.chmod(f, 0o644)
    loaded = config.load(str(root))
    assert loaded.problems == ()
    assert (loaded.config.limits.render_ms, loaded.config.general.mode) == (700, "static")


@linux_root
def test_untrusted_files_are_ignored_and_the_defaults_apply(trusted_dir: Path) -> None:
    root = tree(
        trusted_dir, "[limits]\nrender_ms = 700\n", **{"10_x.toml": "[general]\nmode = 'static'\n"}
    )
    os.chmod(root / "config.toml", 0o644)
    os.chown(root / "config.toml", *account(OTHER_USER))
    os.chmod(root / "conf.d", 0o775)
    loaded = config.load(str(root))
    assert loaded.config == config.defaults()
    reasons = {(os.path.basename(p.file), p.reason.id) for p in loaded.problems}
    assert reasons == {
        ("config.toml", "safepath.error.owner"),
        ("10-x.toml", "safepath.error.writable"),
    }
    assert any(TR.text(p.reason) == f"{root / 'conf.d'} is writable by group or others"
               for p in loaded.problems)  # fmt: skip


def test_refusals_are_contract_errors() -> None:
    assert issubclass(safepath.UnsafePath, ContractError)


def test_python_limits_inside_the_parser_become_a_problem(tmp_path: Path) -> None:
    huge = b"[limits]\nrender_ms = " + b"9" * 5000 + b"\n"
    assert [p.id for p in config.check_content(huge)] == ["config.error.unreadable_value"]
    (tmp_path / "config.toml").write_bytes(huge)
    loaded = load(tmp_path)  # the run goes on without the file
    assert loaded.config == config.defaults()
    assert [p.reason.id for p in loaded.problems] == ["config.error.unreadable_value"]


# --- names that match nothing (final review, usability items 5 and 6) -------------------

TYPOS = (
    "[modules.hw_disk]\n"
    "enabled = false\n"
    "\n"
    "[thresholds.disk_used_pct]\n"
    "warn = 70\n"
    "crit = 90\n"
    "\n"
    "[layout]\n"
    'hide_rows = ["os_host.kernal", "plugin.50-x.y", "hw_disks.var_log"]\n'
)


def test_typos_in_names_are_warnings_with_a_suggestion_and_the_file_still_applies(
    tmp_path: Path,
) -> None:
    """The old code called this file valid and said nothing."""
    loaded = load(tree(tmp_path, TYPOS))
    assert loaded.problems == () and len(loaded.applied) == 1
    got = [(w.reason.id, w.reason.param_dict().get("suggestion"), w.line) for w in loaded.warnings]
    assert got == [
        ("config.warning.module_like", "hw_disks", 1),
        ("config.warning.threshold_like", "disk_used_percent", 4),
        ("config.warning.item_key_like", "os_host.kernel", 9),
    ]
    assert loaded.config.modules["hw_disk"].enabled is False  # applied, without effect


def test_a_name_far_from_any_gets_no_suggestion() -> None:
    _problems, warnings = config.content_report(b"[modules.zzzz]\nenabled = false\n", "f")
    assert [w.reason.id for w in warnings] == ["config.warning.module"]


@pytest.mark.parametrize(
    ("text", "key", "line"),
    [
        ("[limits]\nrender_ms = 'x'\n", "limits.render_ms", 2),
        ("limits.render_ms = 'x'\n", "limits.render_ms", 1),
        ("[general]\n# mode = 'x'\n[limits]\nmode = 1\n", "limits.mode", 4),
        ("[modules.hw_disk]\n", "modules.hw_disk", 1),
        ("[limits]\nx = 1\n[limits]\nx = 2\n", "limits.x", None),  # two places: no line
        ("limits = { render_ms = 'x' }\n", "limits.render_ms", None),  # inline: not found
    ],
)
def test_line_of_finds_one_plain_place_or_none(text: str, key: str, line: Optional[int]) -> None:
    assert config.line_of(text, key) == line


def test_the_item_key_table_matches_what_the_modules_produce() -> None:
    from motp.core import hints
    from motp.modules import registry

    from .test_german import _module_items

    seen: dict[str, set[str]] = {}
    for manager in hints.PACKAGE_MANAGERS:
        for module, _section, item in _module_items(manager):
            assert registry.key_known(item.key), item.key
            if item.key in registry.ITEM_KEYS.get(module, {}):
                label = item.label.id if isinstance(item.label, MessageRef) else ""
                seen.setdefault(item.key, set()).add(label)
    for module, keys in registry.ITEM_KEYS.items():
        assert module in registry.module_names()
        for key, label in keys.items():
            if "*" not in key:
                assert seen.get(key) == {label}, (key, seen.get(key))


def test_the_readme_config_example_is_valid_and_names_only_what_exists() -> None:
    import re

    readme = (SRC.parent / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```toml\n(.*?)```", readme, re.S)
    assert blocks
    for block in blocks:
        problems, warnings = config.content_report(block.encode("utf-8"), "README.md")
        assert problems == [] and warnings == [], (problems, warnings)
