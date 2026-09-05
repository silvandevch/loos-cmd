# LoOS cmd.exe — Documentation

## About LoOS

LoOS is a custom desktop operating system built on top of the leaked
Windows XP / Server 2003 source code. The goals of the project are:

- **No telemetry.** No Cortana, no activity history upload, no
  diagnostic-data scheduling tasks. The components that ship with
  LoOS do not call home. Behavioural tracking services are removed
  at install time and replaced with local-only stubs.
- **Modern look and feel.** The shell, taskbar, start menu, file
  explorer and consoles are restyled to look like Windows 10 / 11
  (rounded corners, dark-mode tokens, Segoe UI Variable, Mica-style
  surfaces) while keeping the NT 5.2 kernel family underneath for
  stability and tiny footprint.
- **Modern app compatibility.** LoOS ships a *shim layer* on top of
  the NT 5.2 kernel that re-implements the NT 6.x / NT 10.x system
  calls (`NtCreateFileEx`, the new Job objects, the URB layout used
  by USB 3.0 stacks, the WinRT activation plumbing, the modern
  threadpool, etc.) so unmodified Windows 10 / 11 user-mode binaries
  load and run. 32- and 64-bit MSIX / Appx packages work, and so do
  the modern Chromium-based Edge, VS Code, and Electron apps.

`cmd.exe` is the native command processor for LoOS — it replaces
Windows' `cmd.exe` wholesale. It is a clean-room reconstruction of
the decompiled Windows `cmd.exe` (~46 kloc of raw Ghidra output)
rewritten in a single, human-readable C file, then extended with
three flagship features inspired by PowerShell:

1. **Object handling** — hashtables, `$obj.key` access, JSON / XML
   `ConvertFrom-` / `ConvertTo-` builtins.
2. **Advanced autocompletion** — context-aware `TAB` for commands,
   file paths, env vars, and object keys.
3. **Complex data types** — real `SET /A` arithmetic, native arrays,
   and `FUNC` / `CALL` user-defined functions with no `GOTO`
   required.

The interactive console also ships a tabbed TUI on top of the
standard `cmd.exe` prompt, full line-editing (backspace, arrows,
history) and a persistent command history.

---

## Builtin commands — full syntax and examples

All commands below are case-insensitive. `$` sigil names are
case-sensitive when they refer to user objects / arrays.

### `OBJ` — create or extend an object

```
OBJ <name> = @{ key1 = value1 ; key2 = value2 ; ... }
OBJ $name .key = value
OBJ <name> key = value
```

An *object* is an in-memory hashtable of `wchar_t` -> `wchar_t`
key/value pairs. There is no nesting yet — values are strings.

```cmd
OBJ user = @{name=Alice; age=30; city=Bern}
OSET $user.email = alice@example.com
OBJ project = @{name=LoOS; language=C; license=MIT}

OBJECTS
REM $user = @{name=Alice; age=30; city=Bern; email=alice@example.com}
REM $project = @{name=LoOS; language=C; license=MIT}
```

Values may be quoted to include spaces, `;` or `=`:

```cmd
OBJ msg = @{subject=Hello World; body=this is a longer message}
OBJ cfg = @{url="https://example.com/?q=1&p=2"}
```

### `OSET` — set a single field

```
OSET $name.key = value
```

Equivalent to setting a key on an existing object. Creates the
object if it does not exist.

```cmd
OSET $user.age = 31
OBJECTS
REM $user = @{name=Alice; age=31; city=Bern; email=alice@example.com}
```

### `OGET` — read a field (or whole object)

```
OGET $name
OGET $name.key
```

Without a key, dumps the whole object. With a key, prints just that
key's value.

```cmd
OGET $user.name
REM Alice

OGET $user
REM $user = @{name=Alice; age=31; ...}
```

### `OBJECTS` / `ODEL` — list and delete

```
OBJECTS                REM list all objects in the session
OBJECTS DEL $name      REM delete the named object
ODEL $name             REM same as OBJECTS DEL
```

### `ARRAY` — create or replace an array

```
ARRAY <name> = value1, value2, value3, ...
```

Values may be quoted strings. The comma is the separator (no quoting
inside the value is recognised yet).

```cmd
ARRAY primes = 2,3,5,7,11,13
ARRAY colors = red,green,blue,"light blue","dark green"
```

Re-running `ARRAY name = ...` replaces the previous array (it does
not append).

### `AGET` — read an element

```
AGET $name [ index ]
```

Index is 0-based. Out-of-range indices are an error.

```cmd
ARRAY primes = 2,3,5,7,11
AGET $primes[0]    REM 2
AGET $primes[3]    REM 7
AGET $primes[9]    REM Error: AGET: index out of range
```

The `$name[idx]` syntax is also expanded wherever `%FOO%` would be,
so:

```cmd
ECHO prime #3 = %primes[3]%
REM prime #3 = 7
```

### `ASET` — set an element

```
ASET $name [ index ] = value
```

The array auto-grows if `index` is past the end (intermediate
elements are empty strings).

```cmd
ARRAY primes = 2,3,5,7,11
ASET $primes[5] = 13
ASET $primes[10] = 29      REM primes now has 11 elements, indices 6..9 are empty

ARRAYS
REM $primes[11] = (2, 3, 5, 7, 11, 13, , , , , 29)
```

### `ARRAYS` / `ADEL` — list and delete

```
ARRAYS                REM list all arrays in the session
ARRAYS DEL $name      REM delete the named array
ADEL $name            REM same as ARRAYS DEL
```

### `FUNC` — define a user function

```
FUNC <name> { stmt1 ; stmt2 ; stmt3 }
```

The body is everything between `{` and `}` on a single line.
Statements are separated by `;`. Parameters are *not declared*; the
function body sees its arguments through `$1`..`$8`.

```cmd
FUNC greet {ECHO Hello $1}
CALL greet World
REM Hello World

FUNC avg {SET /A $__RET = ($1 + $2) / 2 ; ECHO avg = $__RET}
CALL avg 10 20
REM avg = 15
```

### `CALL` — invoke a user function (or a batch file)

```
CALL <name> [arg1 [arg2 ...]]
```

Arguments bind to `$1`..`$8` in the function body. The same `CALL`
command still works on batch files (`.bat` / `.cmd`) the way the
classic `cmd.exe` does — if `<name>` matches a defined function the
function is run, otherwise `CALL` looks for a batch file of that
name on disk and falls back to a normal command lookup.

```cmd
FUNC square {SET /A $1 = $1 * $1 ; ECHO $1}
CALL square 7
REM 49
```

### `FUNCS` / `FUNCDEL` — list and delete

```
FUNCS              REM list every defined function
FUNCDEL <name>     REM delete the named function
```

### `CONVERTFROM-JSON` / `CONVERTTO-JSON` — JSON ↔ object

```
CONVERTFROM-JSON <json-text>
CONVERTTO-JJSON <object-name>      (typo, kept for back-compat)
CONVERTTO-JSON   <object-name>
CONVERTFROM-XML  <xml-text>
CONVERTTO-XML    <object-name>
```

JSON input is parsed into a fresh object named `__conv`. The parser
is intentionally minimal — only flat `{"key": value}` objects,
where `value` may be a string, number, `true`, `false` or `null`.
Nested arrays / objects are not supported yet.

```cmd
CONVERTFROM-JSON {"host":"server01","port":8080,"debug":true}
REM Loaded JSON into $__conv (3 keys)

ECHO $__conv.host    REM server01
ECHO $__conv.port    REM 8080

CONVERTTO-JSON __conv
REM {"host":"server01", "port":"8080", "debug":"true"}
```

Short aliases: `CFJ`, `CTJ`, `CFX`, `CTX`.

### XML conversion

```
CONVERTFROM-XML <root><child>value</child></root>
```

The XML parser is *shallow*: every direct child of the root
element becomes a key on the resulting object. Nested elements
are not recursed into — only the first level of children is
captured.

```cmd
CONVERTFROM-XML <config><host>server01</host><port>8080</port></config>
REM Loaded XML into $__conv (2 keys)

CONVERTTO-XML __conv
REM <__conv>
REM   <host>server01</host>
REM   <port>8080</port>
REM </__conv>
```

### `SET` — environment / arithmetic

`SET` with no arguments lists every environment variable.
`SET FOO=bar` sets one. `SET FOO=` deletes it. `SET FOO` (with no
`=`) prints all variables whose name starts with `FOO`.

`SET /A <name>=<expression>` evaluates an arithmetic expression and
stores it (as a decimal string) in the env var `<name>`.

Operators: `+ - * / %` and parentheses. Identifiers are looked up
in the environment, in any defined object, or in any defined
array. Undefined identifiers evaluate to `0` (matches CMD).
Syntax errors print an error message and leave the variable
unchanged.

```cmd
SET /A x = 1 + 2 * 3          REM x = 7
SET /A y = (x + 5) * 2        REM y = 24
SET /A z = y % x              REM z = 3
SET /A w = $user.age + 1      REM w = 31 (looks up $user.age via loos_resolve)

ECHO x=%x% y=%y% z=%z% w=%w%
```

`SET /P <name>=<prompt>` reads a line of input from stdin and
stores it in the env var, after printing `<prompt>` first.

### `TAB` / `TABN` / `TABP` / `TABGO` / `TABCLOSE` — tab navigation

```
TAB          open a new tab (up to 8)      shortcut: Ctrl+T
TABN         switch to the next tab        shortcut: Ctrl+Tab
TABP         switch to the previous tab    shortcut: Ctrl+Shift+Tab
TABGO <n>    switch to tab <n> (1..8)      shortcut: Alt+1 .. Alt+8
TABCLOSE     close the current tab         shortcut: Ctrl+W (keeps ≥1)
```

Every tab action exists both as a command (scriptable, works over
`cmd /C` and pipes) and as a keyboard shortcut (interactive only —
shortcuts are swallowed by the line editor and never leak into the
buffer). You can also click a tab in the strip to switch.

The tab strip travels with the prompt: a one-row `[1*] [2] [3]`
line is printed directly above every prompt, so the tabs are always
visible exactly when you type. (A fixed bar at the top of the
screen would scroll out of view on the first command output, which
is why the strip moves instead.) Clicks hit-test the strip's
recorded row, so they keep working no matter how far the session
has scrolled. `TABNAME <text>` renames the current tab / console
title.

### `HISTORY` — persistent command history

Commands entered at the prompt are appended to
`%USERPROFILE%\.loos_history` (one per line, UTF-8). `HISTORY`
prints the in-memory ring buffer.

### `HELP` — list every command

```
HELP                 REM prints the full command index
HELP <command>       REM prints short help for a specific command
```

---

## Tab completion (`TAB` key at the prompt)

| Cursor context               | Completes                                  |
|------------------------------|--------------------------------------------|
| First token on a line        | A builtin command name (case-insensitive)  |
| `name` (looks like a file)   | Files / directories in the CWD             |
| `name\more`                  | Files in that subdirectory                |
| `$prefix`                    | Env var names                              |
| `$prefix` (env miss)         | Object / array names                       |
| `$obj.<prefix>`              | Keys of object `obj`                       |

Press Tab repeatedly to walk the matching set. Unique matches
update the buffer silently; ambiguous matches beep.

---

## Variable expansion

`cmd_expand_env_vars` runs Windows'
[`ExpandEnvironmentStringsW`](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsw)
first — so `%FOO%`, `%USERPROFILE%`, `%PATH%`, etc. all work — and
then runs a second pass that handles three additional syntaxes
that Windows doesn't know about:

| Syntax            | Resolves to                                          |
|-------------------|------------------------------------------------------|
| `$name`           | Env var / object / array named `name`               |
| `$name.key`       | Key `key` of object `name`                          |
| `$name[3]`        | Index `3` of array `name`                           |
| `$1` .. `$8`      | The 1st through 8th argument to the current `CALL` |

Order of resolution: positional call args → object dot-access →
array index-access → plain env var.

---

## Examples (cut and paste)

```cmd
REM ------- OBJECTS -------
OBJ user = @{name=Alice; age=30; city=Bern}
ECHO $user.name
REM Alice

OSET $user.email = alice@example.com
OGET $user
REM $user = @{name=Alice; age=30; city=Bern; email=alice@example.com}

OBJECTS

REM ------- ARRAYS -------
ARRAY primes = 2,3,5,7,11,13
AGET $primes[3]
REM 7

ASET $primes[7] = 17
ARRAYS

REM ------- ARITHMETIC -------
SET /A x = (2 + 3) * 4 - 1
ECHO %x%
REM 19

SET /A y = x * x
SET /A z = y % 100

REM ------- JSON / XML -------
CONVERTFROM-JSON {"a":1,"b":"two","c":[1,2,3]}
ECHO $__conv.b
REM two

CONVERTTO-JSON __conv
REM {"a":"1", "b":"two", "c":"[1,2,3]"}

CONVERTFROM-XML <root><name>Alice</name><age>30</age></root>
CONVERTTO-XML __conv
REM <__conv>
REM   <name>Alice</name>
REM   <age>30</age>
REM </__conv>

REM ------- USER FUNCTIONS -------
FUNC greet {ECHO Hello $1 $2}
CALL greet Alice Wonder
REM Hello Alice Wonder

FUNC hypot {SET /A $__RET = $1*$1 + $2*$2 ; ECHO $__RET}
CALL hypot 3 4
REM 25

REM ------- TABS -------
TAB
TABN
TABGO 1
TABCLOSE
TABCLOSE

REM ------- HISTORY -------
HISTORY
```

---

## Files

| File                                  | Purpose                                          |
|---------------------------------------|--------------------------------------------------|
| `cmd.c`                               | Single-file C source. ~4 500 lines.             |
| `cmd.exe`                             | Compiled MSVC binary, ready to run.              |
| `build.bat`                           | One-shot MSVC build script.                      |
| `README.md`                           | Quick-start guide, build / install instructions. |
| `docs.md`                             | This file — full command reference.              |

## Unix aliases (translated to native commands in real time)

Every alias is rewritten to its Windows equivalent and executed
through the normal dispatch table — flags are carried over:

| Alias | Runs as | Example |
|---|---|---|
| `LS [path]` | `DIR /B [path]` | `LS C:\LoOS` |
| `RM <file...>` | `DEL /Q <file...>` | `RM old.log` |
| `CAT <file>` | `TYPE <file>` | `CAT C:\Windows\System32\drivers\etc\hosts` |
| `CP <src> <dst>` | `COPY <src> <dst>` | `CP a.txt b.txt` |
| `MV <src> <dst>` | `MOVE <src> <dst>` | `MV a.txt sub\` |
| `MKDIR <dir>` | `MD <dir>` | `MKDIR build` |
| `RMDIR <dir>` | `RD <dir>` | `RMDIR build` |
| `TOUCH <file>` | `COPY /B NUL <file>` | `TOUCH new.txt` |
| `CLEAR` | `CLS` | `CLEAR` |
| `PWD` | `CD` (no args) | `PWD` |
| `MAN <cmd>` | `HELP <cmd>` | `MAN DIR` |
| `GREP <pat> [files]` | `FINDSTR <pat> [files]` | `GREP localhost hosts` |
| `HEAD` | `FINDSTR /N` | `HEAD pattern file` |
| `TAIL` | `FINDSTR /V` | `TAIL pattern file` |
| `WC` | `FIND /C /V ""` | `TYPE f.txt \| WC` |
| `WHICH <name>` | `WHERE <name>` | `WHICH cmd.exe` |
| `UNAME` | `VER` | `UNAME` |
| `DF` | `FSUTIL VOLUME DISKREFS` | `DF` |
| `FREE` | `WMIC OS GET ...` | `FREE` |
| `ENV` | `SET` (no args) | `ENV` |

## SUDO — run a command elevated

```
SUDO <command> [args ...]
```

Relaunches the rest of the line through
`powershell -NoProfile -Command "Start-Process ... -Verb RunAs"`,
so Windows shows the normal UAC prompt. Works for builtins and
externals:

```cmd
SUDO notepad C:\Windows\System32\drivers\etc\hosts
SUDO REG ADD HKLM\Software\LoOS /v Installed /t REG_DWORD /d 1 /f
```

## THEME — palette swapper

```
THEME LIST
THEME <default|solarized-light|solarized-dark|dracula>
THEME SET <name>        (same as THEME <name>)
```

Custom themes are JSON files in `%USERPROFILE%\.loos_themes\`:

```json
{ "fg": 7, "bg": 0 }
```

`fg`/`bg` accept 0–15 or `0x` hex (only the low 4 bits are used —
the Windows console is 16 colours).

```cmd
THEME LIST
THEME dracula
THEME solarized-light
THEME default
```

## CURSOR — cursor shape

```
CURSOR <block|underscore|bar|off>
```

```cmd
CURSOR block
CURSOR underscore
CURSOR bar
CURSOR off
```

(`off` hides the cursor. In a redirected / non-console session the
command is a silent no-op.)

## Typo correction ("Did you mean ...?")

Unknown commands are matched against every builtin name (and recent
history first-words) with Levenshtein distance. In interactive mode
you get:

```cmd
ech hello
REM Did you mean ECHO? [Y/n] y
REM hello
iponcfg
REM Did you mean IPCONFIG? [Y/n] n
```

Thresholds scale with word length (≤3 chars: distance 1; ≤6: 2;
longer: 3). In `cmd /C` batch mode no prompt is shown — the command
just fails with 9009 as before. `DIDYOUMEAN <word>` forces the
lookup manually.

## Line editor extras

- **Fish-style ghost:** as you type, the best history match is shown
  dim after the cursor. `Right Arrow` takes one character, `End`
  takes the whole suggestion.
- **Auto-closing pairs:** typing `" ' ( [ {` inserts the matching
  closer with the cursor in the middle. Typing the closer when it is
  already under the cursor just steps over it. Backspace on an empty
  pair (`""`, `()`, ...) deletes both characters.
- **Backspace / Delete** are handled as editing keys first and
  control characters are never inserted into the buffer, so stray
  glyphs (the old "house" character) cannot appear. All three wire
  formats are accepted: `VK_BACK`/`VK_DELETE`, `Ctrl+H`/`DEL`
  (`0x7F`, which is what VT-input consoles deliver for Backspace),
  and hardware scan codes (`0x0E`/`0x53`).
- **Arrows / Home / End** match by virtual key, by scan code
  (`4B/48/4D/50/47/4F`) when the event carries no character, *and* as
  VT escape sequences (`ESC [ A/B/C/D/H/F`, `ESC [ 3~`, `1~/4~/7~/8~`,
  `ESC O ...`, `Shift+Tab` as `ESC [ Z`) — whichever wire format the
  console delivers is translated before dispatch. A lone `ESC` still
  clears the line. The scan fallback requires `ch == 0`, so Numpad
  digits typed with NumLock on still insert normally.
- **Up / Down** walk history, **Esc** clears the line,
  **Ctrl+L** clears the screen.
- **Keyboard layouts:** the editor inserts the console's translated
  character verbatim, so US, Swiss German/French, German, French, …
  all type correctly. **AltGr** (which Windows reports as
  `Ctrl + RightAlt`) is recognized as a character modifier, so
  `@ € [ ] { } | ~ ´ ` and friends type normally instead of being
  swallowed as shortcut modifiers. Genuine `Ctrl` / `Alt` shortcuts
  (with LeftAlt, without the AltGr combination) keep working.
- **Ctrl+C** copies the current input line to the clipboard
  (silent; nothing to copy on an empty line).
- **Ctrl+V** pastes clipboard text at the cursor. A multi-line
  clipboard asks `[Paste N lines? Y/n]` first; on confirm, newlines
  become spaces and other control characters are dropped.

## Piping and redirection

`>`, `>>`, `<` and `|` work as in stock `cmd.exe`, plus:

```cmd
DIR missing 2>&1 | FINDSTR /I error
TYPE file.txt > out.txt 2>&1
```

- `2>&1` merges stderr into stdout (parsed before `>`/`<`).
- `GREP` is an alias for `FINDSTR`, so `... | GREP foo` works.

## Console visuals (plain conhost compatible)

All of these are opt-in and off by default, so stock `conhost.exe`
behaviour is unchanged unless you ask for them:

| Command | Effect |
|---|---|
| `HYPERLINKS` / `NOHYPERLINKS` | Emit (or stop emitting) OSC 8 escape sequences around `http(s)://` URLs and absolute paths so capable terminals (Windows Terminal, VS Code, WezTerm) make them Ctrl+clickable. Plain conhost ignores unknown escapes only when off — keep it off there. |
| `SESSION-SAVE` / `SESSION-RESTORE` | Snapshot tab count + cwd to `%USERPROFILE%\.loos_session.json` on exit (automatic) and on demand; restore/print on demand. |
| `QUAKE` | Slide the console down from the top of the screen (best-effort `SetWindowPos` slide; global `Ctrl+`` hotkey wiring is future work). |
| `AUTOCOPY` | Toggle QuickEdit-based copy-on-select. |
| `BLUR` | Best-effort Mica backdrop via `dwmapi.dll` `DwmSetWindowAttribute` (Windows 10 1903+; prints a notice when unsupported). |
| `TABNAME <text>` | Rename the current tab / console title. |
| Block select | Hold `Alt` while dragging in conhost to select a column. |
| Multi-line paste | Conhost itself warns before pasting runs containing newlines. |

## Caveats

- `OBJ` literals do not currently support nested objects. Use
  multiple `OBJ` statements plus `OSET` to build up structure.
- The JSON / XML converters are deliberately minimal (no streaming,
  no attributes on the XML side, no array values in JSON).
- All new objects, arrays and functions live only for the lifetime
  of the `cmd.exe` process. They do not persist across invocations.
- `$1`..`$8` are populated only inside a `CALL`'d function body.
  Classic CMD batch-script semantics inside `.bat` files are
  preserved (legacy behaviour via `cmd_run_batch_file`).
- Set `LOOSDEBUG=1` in the environment to enable verbose developer
  logs on stderr.

## License

This is a clean-room reconstruction of the decompiled Windows
`cmd.exe` output, modified and extended under the LoOS project.
Use at your own risk.