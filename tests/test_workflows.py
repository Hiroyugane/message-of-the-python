"""Rules for the GitHub workflows (blueprint T15, D13, phase 14), checked as text so the
suite needs no YAML parser: actions pinned by commit hash from an allow-list, no
expression expanded inside a shell command, least-privilege tokens, a draft release."""

import re
from pathlib import Path

import pytest

from .conftest import ROOT

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
PINNED = re.compile(r"(?P<repo>[a-z0-9-]+/[a-z0-9-]+)@[0-9a-f]{40}\Z")
# Official GitHub actions only (the maintainer's rule: official or widely used, pinned).
ALLOWED = {
    "actions/checkout",
    "actions/setup-python",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/attest-build-provenance",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_the_workflows_exist() -> None:
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "release.yml", "nightly.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_allowed_and_pinned_by_hash(path: Path) -> None:
    for line in _text(path).splitlines():
        m = USES.match(line)
        if not m:
            continue
        pinned = PINNED.match(m.group(1))
        assert pinned, f"{path.name}: not pinned by commit hash: {line.strip()}"
        assert pinned.group("repo") in ALLOWED, f"{path.name}: action not allowed: {line}"
        assert re.search(r"#\s*v[0-9]", m.group(2)), f"{path.name}: no version comment: {line}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def run_scripts(text: str) -> "list[str]":
    """The shell text of every ``run:`` step: the line itself, and for a block scalar every
    following line indented deeper than the ``run:`` key (blank lines included)."""
    scripts: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", lines[i])
        i += 1
        if not m:
            continue
        key_indent = len(m.group(1)) + (2 if lines[i - 1].lstrip().startswith("-") else 0)
        body = [m.group(2)]
        while i < len(lines) and (
            not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > key_indent
        ):
            body.append(lines[i])
            i += 1
        scripts.append("\n".join(body))
    return scripts


def test_run_scripts_take_the_whole_block() -> None:
    """The scanner must not stop at a line that only looks like a key (code review)."""
    text = "    steps:\n      - run: |\n          a: b\n          echo ${{ x }}\n      - uses: y\n"
    assert run_scripts(text) == ["|\n          a: b\n          echo ${{ x }}"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_expression_is_expanded_inside_a_shell_command(path: Path) -> None:
    """Tag names and refs reach the shell through env only (script injection)."""
    scripts = run_scripts(_text(path))
    assert scripts, f"{path.name}: no run step found"
    for script in scripts:
        assert "${{" not in script, f"{path.name}: {script[:120]}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_untrusted_trigger_and_no_secret(path: Path) -> None:
    text = _text(path)
    assert "pull_request_target" not in text
    assert "workflow_run" not in text
    assert "secrets." not in text, "only the built-in token is used"


def test_the_release_workflow_is_least_privilege_and_drafts_only() -> None:
    text = _text(ROOT / ".github" / "workflows" / "release.yml")
    assert re.search(r"^permissions: \{\}$", text, re.MULTILINE)
    assert 'tags: ["v*"]' in text
    assert "tools/check_tag.py" in text and "merge-base --is-ancestor" in text
    assert "--draft" in text and "--verify-tag" in text
    assert "attestations: write" in text and "id-token: write" in text
    # write access only where it is needed
    assert text.count("contents: write") == 1
    assert text.count("id-token: write") == 1
    # Security and code review of phase 14: the attestation is checked for this workflow and
    # this tag, and the attached checksum is the one the build job computed.
    assert '--source-ref "$GITHUB_REF"' in text
    assert 'test "$(cut -d\' \' -f1 SHA256SUMS)" = "$A"' in text
    assert "git fetch" not in text  # fetch-depth: 0 already has origin/main
    for artefact in ("dist/motp.pyz", "dist/SHA256SUMS", "dist/motp.pyz.sigstore.json"):
        assert artefact in text


@pytest.mark.parametrize("name", ["ci.yml", "nightly.yml"])
def test_ci_and_nightly_tokens_are_read_only(name: str) -> None:
    text = _text(ROOT / ".github" / "workflows" / name)
    assert re.search(r"^permissions:\n  contents: read$", text, re.MULTILINE)
    assert "write" not in text


def _job(text: str, name: str) -> str:
    """The text of one job of a workflow, up to the next job (two-space key)."""
    m = re.search(rf"^  {re.escape(name)}:\n(?P<body>(?:(?:    .*)?\n)*)", text, re.MULTILINE)
    assert m, f"no job {name}"
    return m.group("body")


def test_container_unit_tests_start_through_the_local_tool() -> None:
    """The first CI run (2026-11-26): a hand-written ``docker run`` lacked ``--init``, so
    pytest was PID 1 inside the container and the collector tests ran as PID 1 too. CI must
    start the container with the options the local runs use, from one place."""
    job = _job(_text(ROOT / ".github" / "workflows" / "ci.yml"), "test-container")
    assert 'python3 tools/container_test.py --podman docker "$IMAGE"' in job
    assert "unit_tests.sh" not in "".join(run_scripts(job))
