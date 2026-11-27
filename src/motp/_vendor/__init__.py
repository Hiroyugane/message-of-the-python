"""Third-party code bundled with MOTP, unchanged, at pinned versions (blueprint D9, D23, T16).

``manifest.json`` records each package's version, source release, the SHA-256 of that
release as published on PyPI, and the SHA-256 of every file copied from it;
``tests/test_vendor.py`` checks the files against it. Files here are never edited: an
update replaces them from a new release and updates the manifest.
"""
