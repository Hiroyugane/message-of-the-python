# ADR-0002: Probe protocol and message contract

- **Status:** accepted, 2026-11-24 (phase 2)
- **Source of truth:** the blueprint (the maintainer's design document, not part of this repository), sections 4.4, 4.5, 4.6 (text width, language), 5.5, decisions D19, D26, D27, D34, threats T6, T7, T8, T22. Details the blueprint left open were recorded in the maintainer's decision log under "Phase 2".

## Probe protocol, version 1

A built-in probe prints one JSON document `{"api": 1, "module": ..., "items": [...]}` with the item fields of the table in 4.4. A plugin prints either the same document (with literal texts) or one line of text and exits with 0, 1, 2 or 3 (D26).

Acceptance (`core/probe.py`): at most 64 KiB; UTF-8 with replacement; JSON without `NaN`, infinities, repeated keys, nesting deeper than 8 or integers longer than 19 digits; only known fields with the expected types; at most 32 items and 16 details per item; strings at most 1024 characters before sanitising; the module name of the probe that was started. Anything else fails the module for this run, with a reason that is a message id whose quoted input is sanitised and bounded (`model.contract_error`).

Plugin rules: keys are forced into `plugin.<name>.*`; labels, texts and hints are literal text only, never a message id, a hint id or a template; a `command` field is refused anywhere, in both forms and inside message parameters (D34); keys starting with `plugin.` are refused from built-in probes; items are admin-only unless the config sets the plugin public (D27); the renderer adds the fixed `[plugin <name>]` prefix from `Item.origin`.

## Thresholds (4.5)

A rule has a name, two inclusive limits and a direction. `core.thresholds.classify` is the single classifier for cached and live values; anything that is not a finite number is `unknown`.

## Sanitiser (5.5)

`core.sanitize.sanitize(text, limit, ascii_only=False)` is the only cleaner. It runs when the collector accepts output and again whenever a cache file is read, and a second pass changes nothing. Dot-like characters, and dash- or frame-like characters, each form one run class cut to three; a single space or a combining mark does not end a run. Output is at most `max_chars(limit)`, three characters per cell. Its emoji, frame and filler tables are fixed code point ranges, so results do not depend on the interpreter's Unicode version, except for unassigned code points.

## Cache files (4.4)

`core/cache.py` defines the schemas of `public.json`, `admin.json`, `render.json` and `user/<uid>.json`, their encoders (the phase 6 writers only serialise), and a bounded reader: no link following, non-blocking open, regular file of the expected owner, no group or other write bit, byte cap, schema check, sanitising again. A module entry that breaks the schema is skipped and counted (`TierCache.unreadable`); only a broken file header rejects a file. The tier encoder refuses what the reader would refuse and, when a file would exceed its cap, empties the largest modules one by one and marks them failed, so whatever the collector accepts stays readable.

## Messages (D19, invariant 5)

- Every user-visible string has a symbolic message id. Catalogues are `src/motp/locale/<lang>.po`, compiled to `.mo` by `tools/compile_catalogs.py` (pure Python) and read as bytes through the package loader.
- Only catalogue strings are templates. `core.i18n.substitute` replaces `{name}` and nothing else; it is not `str.format`, runs in one pass, and leaves attribute access, indexing, conversions and format specifications as literal text. Parameters are reduced to numbers or sanitised strings without calling any method of a foreign object (T22).
- A parameter named `count` selects the plural form, by a fixed rule table per language; the `Plural-Forms` header is never evaluated.

## Hints (D34, T7)

`core/hints.py` maps a hint id to a message id and a command per package manager. The table is literal, read-only, and `lookup` takes only the hint id and the package manager; nothing from collected data can become part of a command.

## Consequences

- Changing a field, a limit or a schema is a protocol change: update this record and bump `api` or `schema` when old documents would be read differently.
- Later phases add message ids and hint entries; the invariant 5 test (`tests/test_messages.py`) fails if code names an id the English catalogue lacks, if the catalogue holds an id nothing uses, or if a text literal reaches an output sink.
