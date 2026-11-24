# Contributing

The plan is `plans/motp-blueprint.md`; decisions are logged in `docs/notes/chat-log.md`.

- One phase is one branch (`feat/pN-short-name`) and one pull request, merged without squashing.
- Commits follow Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`, `build`)
  with a body that says what changed and why. Tests ship in the commit of the code they cover.
- Nothing in the repository may contain real hostnames, IP addresses, user names, e-mail addresses or secrets.
  Use RFC 5737 addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `example.com`.
  Run `python tools/scan_repo.py` before every push.
- Commits use your GitHub noreply address (`ID+name@users.noreply.github.com`).
- Licence: GPL-3.0-or-later; contributions are made under the same terms.
