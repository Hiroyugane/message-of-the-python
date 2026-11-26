# Languages, `motp explain` and tips

## Which language you see

MOTP speaks English and German. The language is the reader's, picked at the moment the message is
drawn: the first of `LC_ALL`, `LC_MESSAGES` and `LANG` that is set names the locale, and `LANGUAGE`
(a colon list) is honoured as GNU programs do. With `C`, `POSIX`, no locale or a language without a
catalogue the message is in English. MOTP needs no installed system locale for this: it reads the
variables and brings its own texts.

To force one language for everyone:

```toml
[general]
language = "de"   # or "en"; "auto" follows each user
```

In static mode one file serves all users. It is written in the configured language, or with `"auto"`
in the system's locale, as the collector's service gets it from systemd.

**Over SSH** the server only learns your locale if it accepts it. Two things on the server can keep a
German user in English, and both apply to other programs too:

- `sshd` takes `LANG` from the client only with an `AcceptEnv` line that names it
  (`AcceptEnv LANG LC_*`). Debian and Ubuntu have one by default; check yours with
  `sudo sshd -T | grep -i acceptenv`.
- Fedora, the RHEL family and Ubuntu reset a `LANG` whose locale is not installed to `C.UTF-8`
  at login, before MOTP runs (`/etc/profile.d/lang.sh` there, `/etc/profile.d/01-locale-fix.sh`
  on Ubuntu). Install the locale: `sudo dnf install glibc-langpack-de` on the RHEL family and
  Fedora, `sudo locale-gen de_DE.UTF-8` on Ubuntu. Debian passes `LANG` on as it is.

On a terminal without UTF-8 the German umlauts are written as `ae`, `oe`, `ue` and `ss`. The static
file of static mode is always ASCII, so it spells them out too, unless the config says
`charset = "unicode"`: pam_motd prints that file to every kind of terminal.

Not translated: commands, file names and setting names; the states systemd reports (`active`,
`failed`); the units `KiB`, `GiB`; the decimal point; dates, which are written `2028-06-30`; the
usage lines Python's argument parser prints; and the text of plugins, which translate themselves:
a plugin's `label`, `text` and `hint` each take `{"text": ..., "i18n": {"de": ...}}`, and the
reader's language picks the translation (see [`plugins.md`](plugins.md)).

## `motp explain`

`motp explain` lists the topics; `motp explain disks` says what the disk rows mean, when they warn,
what to do, which limits are in force and which commands the message suggests. It speaks the same
language as the message. Once the collector has run on a system with apt or dnf, only that package
manager's commands are listed; otherwise each is marked with the one it is for. An unknown topic exits
with code 2.

## Tips

```toml
[layout]
tips = true
```

shows one short tip about MOTP below the message, a different one each day (counted in UTC). Tips
are off by default and left out on terminals narrower than 40 columns.

## Adding a language

1. Copy `src/motp/locale/en.po` to `src/motp/locale/<code>.po` and translate every `msgstr`. Keep
   the ids. Set the `Language` and `Plural-Forms` headers.
2. Add the language to `PLURAL_RULES` in `src/motp/core/i18n.py`. The rule is a function in code;
   the `Plural-Forms` expression of the file is not evaluated, and a test compares only the number of
   forms.
3. Templates take plain `{name}` placeholders and nothing else. Keep the same placeholders in every
   form as the English text has. A message is one line, without control characters.
4. Where your language needs another form of a day count after "ago" (as German does: "2 Tage", but
   "vor 2 Tagen"), translate `unit.days_ago` accordingly.
5. If your language's letters have a customary ASCII spelling, add them to `_SPELLED` in
   `src/motp/core/sanitize.py`; otherwise accents are dropped and other letters become `?`.
6. Plugins and the renderer need no change. Extend the checks in `tests/test_german.py` to your
   language: same ids as English, same placeholders, nothing left empty, and no text cut at 80
   columns. Add golden files with `MOTP_UPDATE_GOLDEN=1` and read the diff.
7. `python tools/compile_catalogs.py` compiles the `.mo` files for the source tree (they are not
   tracked); `tools/build_pyz.py` compiles them into the archive.

Room is short on an 80-column screen: a label has 17 columns (15 for an indented detail row), a value
about 55. Shorten the wording, not the layout.

### Words used in German

The German text is written as an administrator would write it, with the infinitive instead of "Sie"
or "du" ("Updates installieren"), and one word per thing:

| English | German | | English | German |
|---|---|---|---|---|
| message of the day | MOTD | | warning / critical | Warnung / kritisch |
| update | Update | | running / stopped (container) | aktiv / gestoppt |
| reboot, restart | Neustart | | unknown | unbekannt |
| unit (systemd) | Unit | | login | Anmeldung |
| service | Dienst | | session | Sitzung |
| container | Container | | support (end of) | Support |
| plugin | Plugin | | backup | Sicherung |
| firewall, kernel, cache | Firewall, Kernel, Cache | | file system | Dateisystem |
| collector | Sammler | | disk (section) | Datenträger |
| probe | Abfrage | | host name | Rechnername |
| load | Auslastung | | host (machine) | Rechner |
| memory | Arbeitsspeicher | | configuration | Konfiguration |
