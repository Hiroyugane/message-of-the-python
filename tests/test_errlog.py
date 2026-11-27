"""The root-only log of probe stderr (T11, phase 7): sanitised, bounded, merged per run."""

from motp.collect import errlog


def test_stderr_lines_are_sanitised_and_bounded() -> None:
    lines = errlog.lines_of(b"\x1b[31mred\x07\n\n" + b"x" * 1000 + b"\n" * 2 + b"y\n" * 100)
    assert lines[0] == "[31mred"
    assert len(lines) == errlog.MAX_LINES
    assert all(len(line) <= errlog.LINE_CELLS for line in lines)


def test_stderr_log_merge_and_decode() -> None:
    old = {
        "a": errlog.Entry(1, ("old a",)),
        "b": errlog.Entry(1, ("old b",)),
        "gone": errlog.Entry(1, ("x",)),
    }
    merged = errlog.merge(old, {"a": None, "c": ("new c",)}, ["a", "b", "c"], 9)
    assert merged == {"b": errlog.Entry(1, ("old b",)), "c": errlog.Entry(9, ("new c",))}
    assert errlog.decode(errlog.encode(merged)) == merged
    assert errlog.decode(b"garbage") == {}
    forged = b'{"schema":1,"modules":{"m":{"time":1,"lines":["\\u001b[2Jx"]}}}'
    assert errlog.decode(forged)["m"].lines == ("[2Jx",)
