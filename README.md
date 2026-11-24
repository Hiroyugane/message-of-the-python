# Message of the Python (MOTP)

A customizable message of the day for Linux, written in Python. It shows host, system, security and
disk information at SSH login and in local terminals, with threshold-coloured values, framed sections
and a header in a bundled font.

**Status: planning done, no release yet.** There is no code in this repository so far. The plan is
[`plans/motp-blueprint.md`](plans/motp-blueprint.md); decisions are logged in
[`docs/notes/chat-log.md`](docs/notes/chat-log.md).

## Target look (text mock, demo data)

```
┌─────────────────────────────────────────────────────────────┐
│   web01                                                     │
├──────────┤ Attention ├──────────────────────────────────────┤
│  12 updates, 3 security ........ sudo apt upgrade           │
├──────────┤ Host ├───────────────────────────────────────────┤
│  Hostname.........:  web01.example.com                      │
│  Local address....:  192.0.2.10                             │
│  Uptime...........:  41 days 3 hours                        │
├──────────┤ Disks ├──────────────────────────────────────────┤
│  /  ................................ 56% of 40 GiB          │
│  ██████████████████████░░░░░░░░░░░░░░░░░                    │
└─────────────────────────────────────────────────────────────┘
```

## Origin

This project is a from-scratch rewrite. It started as a fork of
[fedya/fastmotd](https://github.com/fedya/fastmotd), whose idea and look it carries on; no code from
the earlier versions is reused.

## Licence

GPL-3.0-or-later, see [`LICENSE`](LICENSE).
