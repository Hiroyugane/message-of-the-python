# Releasing MOTP (maintainer's runbook)

Every step that changes something on GitHub is the maintainer's. Nothing in this repository
pushes, tags or publishes on its own; the release workflow only creates a **draft**.

## Before the first push (1.0 only)

1. Decide which open checks must be done first (a real server, a real Raspberry Pi, a native
   speaker for the German text, SELinux in enforcing mode, the dates Fedora and Red Hat publish);
   [`known-limitations.md`](known-limitations.md) lists what was not verified.
2. Read the maintainer's own notes on decisions that may still be overruled (they are kept
   outside this repository).
3. Check the local state:

   ```sh
   git status                     # clean
   git log --oneline main         # the first commit and the one release commit
   python tools/scan_repo.py      # scan: 0 match(es)
   python -m pytest -q
   ```

4. GitHub settings (Settings of the repository): issues on; **private vulnerability reporting**
   on (Security, then Advanced Security); secret scanning with push protection on; Actions
   allowed, with "Read repository contents" as the default workflow permission and "Allow
   GitHub Actions to create and approve pull requests" off; branch protection (or a ruleset) on
   `main`: pull request required, the CI checks required, no force push. Two-factor login on
   the account.
5. **Required before the first tag: a tag ruleset.** Settings, Rules, Rulesets, New tag
   ruleset: target `refs/tags/v*`, enforcement active, restrict creation, update and deletion,
   bypass list the maintainer alone. The release workflow runs from the tagged commit, so a tag
   on an unreviewed commit could carry a workflow without the "on main" check and still get a
   valid attestation; only GitHub's ruleset stops that (T15, security review of phase 14).

## The pull request

The rewrite goes up as one pull request with one commit. On GitHub, `main` holds only the
repository's first commit. The development history was flattened into a single commit on top
of it (the maintainer keeps the full history locally); that commit is local `main` and goes up
under the branch name `release/1.0`.

```sh
git ls-remote origin                       # expect main at the repository's first commit only
git rev-list --max-parents=0 main          # the same hash
git push origin main:refs/heads/release/1.0
gh pr create --base main --head release/1.0 --title "Release 1.0" --body-file CHANGELOG.md
```

If `git ls-remote` shows anything else on `main`, do not force-push over it without deciding
first.

The local pre-push hook scans the pushed commit with gitleaks. The first CI run is the first
time the workflows run at all: work through every failing job before merging. Merge with a
merge commit or a fast-forward, **not by squashing or rebasing**: both give the commit a new
hash, and local `main` could then no longer fast-forward to GitHub's.

## Tagging the release candidate

Before the first tag:

- The repository must be **public**: build attestations are not available for private
  repositories of a personal account, and the release job's checks read `main` without
  credentials. Making it public passes no push hook, so scan the whole history first (the
  local pre-push gitleaks scan and `python tools/scan_repo.py` on a fresh clone).
- The tag ruleset of step 5 above exists.

```sh
git switch main
git pull --ff-only origin main
python tools/check_tag.py v1.0.0rc1      # must print "tag v1.0.0rc1 releases version 1.0.0rc1"
git tag -s v1.0.0rc1 -m "MOTP 1.0.0rc1"  # or -a without a signing key
git push origin v1.0.0rc1
```

The tag starts `.github/workflows/release.yml`. It refuses a tag that does not name the source
version or that is not on `main`; it builds, writes `SHA256SUMS`, attests the build, rebuilds on an
arm64 runner and compares, verifies, and creates a draft prerelease with `motp.pyz`,
`SHA256SUMS` and `motp.pyz.sigstore.json`.

## Checking and publishing the draft

1. Open the draft under Releases. It must hold exactly the three files.
2. A draft's files are not served at the `releases/download/` address the README uses, so
   download the three files from the draft page into an empty directory on a Linux machine,
   then run the README's checks and install by hand from that directory:

   ```sh
   sha256sum --check SHA256SUMS
   gh attestation verify motp.pyz --repo Hiroyugane/message-of-the-python \
     --signer-workflow Hiroyugane/message-of-the-python/.github/workflows/release.yml \
     --source-ref refs/tags/v1.0.0rc1
   gh attestation verify motp.pyz --bundle motp.pyz.sigstore.json \
     --repo Hiroyugane/message-of-the-python
   sudo /usr/bin/python3 -I -S ./motp.pyz install
   ```

   After publishing, the README's install block as written must work too.

3. Rebuild it yourself and compare: on a checkout of the tag, `python3 tools/build_pyz.py` must
   print the SHA-256 in `SHA256SUMS` (on Windows, `python tools/repro_check.py --ref v1.0.0rc1`
   compares a Windows and a Linux build).
4. Edit the draft's notes if needed (the changelog section), then **Publish release**.

## From the release candidate to 1.0.0

1. On a branch: `src/motp/__init__.py` to `1.0.0`, the README's `VERSION=` line and status line
   to `1.0.0`, and the changelog heading (drop "release candidate"). `tests/test_release.py`
   fails until the README's `VERSION=` line, the README status line and the changelog heading
   all name the source version (a candidate's heading must say "release candidate", a final
   one must not). Pull request, merge.
2. Tag `v1.0.0` as above; the workflow makes a draft (not a prerelease); check and publish it.

## If something goes wrong

- A failed workflow run leaves at most a draft: delete the draft, fix on a branch, merge, and tag
  the next candidate (`v1.0.0rc2`). Never move or reuse a tag that was pushed.
- A published release with a problem: publish a fixed version; mark the bad release as such in its
  notes. Do not replace its files.
