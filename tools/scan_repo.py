#!/usr/bin/env python3
"""Repository hygiene scan (blueprint invariant 3). Prints one line per match, exit 1 if any.

Checks tracked files (git ls-files) or, outside a git repo, all files under the root:
  * IPv4 addresses outside RFC 5737 and loopback
  * e-mail addresses outside example.com and users.noreply.github.com
  * strings from the old fork's hygiene findings (blueprint section 1)
"""

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\d)")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
OK_DOMAINS = ("example.com", "users.noreply.github.com")
ALLOWED_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8")
]
# Hygiene strings (section 1): file names of the old fork's leaky artefacts and the
# field that held an address.
HYGIENE = ("__email__", "original.png", "roadmap-preview.png", "docs/help/documentation.md")


def files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
        ).stdout.split("\n")
        names = [n for n in out if n]
    except (OSError, subprocess.CalledProcessError):
        names = []
    if not names:
        names = [
            str(p.relative_to(ROOT))
            for p in ROOT.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]
    return [ROOT / n for n in names]


def scan() -> list[str]:
    hits: list[str] = []
    for path in files():
        if path.resolve() == SELF or not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            hits.append(f"{rel}: not readable as UTF-8 text (binary file?)")
            continue
        for no, line in enumerate(text.splitlines(), 1):
            for m in IPV4.finditer(line):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                if not any(ip in net for net in ALLOWED_NETS):
                    hits.append(f"{rel}:{no}: address {m.group(1)}")
            for m in EMAIL.finditer(line):
                dom = m.group(1).lower()
                if not any(dom == d or dom.endswith("." + d) for d in OK_DOMAINS):
                    hits.append(f"{rel}:{no}: e-mail address at {dom}")
            for s in HYGIENE:
                if s in line:
                    hits.append(f"{rel}:{no}: hygiene string {s}")
    return hits


if __name__ == "__main__":
    found = scan()
    for h in found:
        print(h)
    print(f"scan: {len(found)} match(es)", file=sys.stderr)
    sys.exit(1 if found else 0)
