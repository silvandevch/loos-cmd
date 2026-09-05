# LoOS cmd.exe:PowerShell-inspired Command Processor

A modernised, drop-in replacement for `cmd.exe` written in a single C file.
Built on top of the Ghidra-decompiled Windows `cmd.exe` and re-written
in a human-readable form, then extended with three flagship PowerShell
features:

1. **Object handling** — hashtables (`@{}`), JSON / XML conversion,
   `$obj.key` field access.
2. **Advanced autocompletion** — context-aware `TAB` completion for
   commands, file paths, env var names, and object keys.
3. **Complex data types** — real `SET /A` arithmetic evaluator, native
   arrays, and `FUNC` / `CALL` user-defined functions (no `GOTO`
   required).

It also ships a tabbed TUI on top of the standard `cmd.exe` prompt
(up to 8 tabs), interactive line editing with proper backspace / arrow /
history support, and a persistent command history.

LoOS is a custom desktop OS built on the leaked Windows XP / Server
2003 source code, modernised to look like Windows 10 / 11 and run
modern apps, with all telemetry stripped. See
[`docs.md`](./docs.md) for the project background and the full
command reference.

The single source file is `cmd.c` (~4 500 lines, no third-party
dependencies — only the Windows SDK and standard C runtime).

```
$ OBJ user = @{name=Alice; age=30; city=Bern}
$ ECHO $user.name
Alice
$ ARRAY primes = 2,3,5,7,11
$ AGET $primes[3]
7
$ SET /A x=(2+3)*4-1
19
$ FUNC greet {ECHO Hello $1} & CALL greet World
Hello World
$ CONVERTFROM-JSON {"host":"server01","port":8080}
Loaded JSON into $__conv (2 keys)
$ CONVERTTO-XML __conv
<__conv>
  <host>server01</host>
  <port>8080</port>
</__conv>
```

## Features

### Object handling (`OBJ`)
Create hashtables with a PowerShell-style literal syntax and access
fields with dotted notation.

| Command | Description |
|---|---|
| `OBJ name = @{k1=v1; k2=v2}` | Define or extend an object. |
| `OSET $name.key = value` | Set (or add) a key on an object. |
| `OGET $name.key` | Print a single key. `OGET $name` dumps the whole object. |
| `OBJECTS` | List all objects in the current session. |
| `OBJECTS DEL $name` (or `ODEL`) | Remove an object. |
| `$name.key` (inline) | Expanded wherever `%FOO%` would be. |

Objects live in the in-process hashtable registry (not as env vars),
so they survive across `&` chains and `CALL` invocations, but they
disappear when `cmd.exe` exits.

### Advanced autocompletion (`TAB`)
The custom line editor (`le_read_line`) uses `ReadConsoleInputW` to
read keystrokes one event at a time. When you press **Tab** at the
prompt, completion is dispatched by context:

| Cursor context | Completes |
|---|---|
| First token of the line | A builtin command name (case-insensitive). |
| `name` (looks like a file) | Files and directories in the CWD (uses `FindFirstFileW`). |
| `name\more` | Files in that subdirectory. |
| `$prefix` | Env var names (via `GetEnvironmentStringsW`). |
| `$prefix` (no env hit) | Object / array names. |
| `$obj.<prefix>` | Keys of the object `obj`. |

Press Tab repeatedly to walk the matching set. When the completion is
unique the buffer is updated silently; when it is ambiguous the editor
emits the standard console beep (`\a`).

### Complex data types
#### Real `SET /A`
```bat
SET /A x = 1 + 2 * 3          REM 7
SET /A y = (x + 5) * 2        REM 24
SET /A z = y % x              REM 3
SET /A w = A + 1              REM A is env-var; undefined vars become 0
```
Operators: `+ - * / %` and parentheses. Identifiers are looked up in
the environment, in any defined object, or in any defined array.
Syntax errors are reported on stderr.

#### Native arrays
```bat
ARRAY primes = 2,3,5,7,11
AGET $primes[3]                REM prints 7
ASET $primes[5] = 13           REM auto-grows if index past end
ARRAYS                         REM list all arrays
ARRAYS DEL $primes  (or ADEL)  REM remove
```

#### User-defined functions
```bat
FUNC greet {ECHO Hello $1 $2}
CALL greet Alice Wonder
FUNC avg {SET /A $__RET = ($1 + $2) / 2; ECHO $__RET}
```
- Body is everything between `{` and `}` on a single line; statements
  are separated by `;`.
- Call arguments bind to `$1`..`$8` in the body. `$1` references are
  resolved by `loos_resolve` against the `__CALLPARAM<n>` env vars
  that `CALL` injects for the duration of the body.
- Functions are stored in the in-memory `g_funcs[]`` table; they live
  for the lifetime of the `cmd.exe` process and are shared across
  every TUI tab.

### JSON / XML conversion
```bat
CONVERTFROM-JSON {"a":1,"b":"two"}     REM populates $__conv
CONVERTTO-JSON __conv                   REM prints JSON
CONVERTFROM-XML <root><x>1</x></root>  REM populates $__conv
CONVERTTO-XML __conv                    REM prints XML
```
Short aliases: `CFJ / CTJ / CFX / CTX`.

The JSON parser is intentionally minimal: flat `{"key": value}`
objects only, where `value` may be a string, number, `true`, `false`,
or `null`. The XML parser is shallow — every top-level child element
becomes a key on the resulting object.

### Tabbed TUI
The interactive prompt is a fixed top tab bar (line 0/1 of the screen)
followed by the prompt on line 2. Up to 8 tabs are supported.

| Command | Action |
|---|---|
| `TAB` | Open a new tab. |
| `TABN` | Switch to the next tab. |
| `TABP` | Switch to the previous tab. |
| `TABGO n` | Switch to tab `n` (1..8). |
| `TABCLOSE` | Close the current tab (must leave at least one). |
| Mouse click on a tab | Switch to that tab. |

There are no global keyboard shortcuts (Alt+T, Ctrl+W, etc.) — every
tab action has a command equivalent so it works identically in
interactive mode and in scripts. (Ctrl+C still clears the current
line, Ctrl+L clears the screen, Escape clears the line, arrow keys
navigate the buffer, and Up/Down navigate history.)

### Interactive line editor
The custom editor reads raw `INPUT_RECORD`s and handles every key
that the real Windows console generates:

| Key | Action |
|---|---|
| Printable character | Insert at cursor, advance. |
| Backspace | Delete char before cursor (also catches Ctrl+H). |
| Delete | Delete char at cursor. |
| Left / Right | Move cursor. |
| Home / End | Jump to start / end. |
| Up / Down | Walk command history. |
| Tab | Run context-aware completion. |
| Enter | Submit line. |
| Escape | Clear current line. |
| Ctrl+C | Clear current line. |
| Ctrl+L | Clear screen. |

The editor uses `FillConsoleOutputCharacterW` to clear the prompt line
so it never paints uninitialised stack memory to the screen (the
"house emoji on backspace" bug from earlier revisions is gone), and
it only redraws the prompt row when the buffer state has actually
changed so there is no cursor flicker.

### Persistent command history
Commands entered at the prompt are appended to
`%USERPROFILE%\.loos_history` (one command per line, UTF-8). The
`HISTORY` builtin prints the buffer.

## Build

Tested with **MSVC 14.44 (Visual Studio Build Tools 2022)** on Windows
10 22H2. No external libraries — only `kernel32`, `user32`, `advapi32`,
`shell32`, `ws2_32`, `iphlpapi`,`, `dnsapi`, `netapi32`,`,
`winhttp`.

### One-liner
```cmd
cl /EHsc /O2 /W0 cmd.c /Fe:cmd.exe ^
   ws2_32.lib iphlpapi.lib dnsapi.lib netapi32.lib winhttp.lib ^
   advapi32.lib shell32.lib user32.lib kernel32.lib
```

### With vcvarsall
```cmd
call "C:\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /EHsc /O2 /W0 cmd.c /Fe:cmd.exe ^
   ws2_32.lib iphlpapi.lib dnsapi.lib netapi32.lib winhttp.lib ^
   advapi32.lib shell32.lib user32.lib kernel32.lib
```

### clang-cl
```cmd
clang-cl /O2 cmd.c /Fe:cmd.exe ^
   ws2_32.lib iphlpapi.lib dnsapi.lib netapi32.lib winhttp.lib ^
   advapi32.lib shell32.lib user32.lib kernel32.lib
```

The release binary in this repository (`cmd.exe`, ~336 KB) was
produced with MSVC 14.44 at `/O2 /EHsc`.

## Install

To replace `cmd.exe` on a LoOS system:
```cmd
copy /Y cmd.exe C:\Windows\System32\cmd.exe
copy /Y cmd.exe C:\LoOS\out\cmd.exe
```

## Architecture notes

The binary is a single translation unit. There is no runtime
dependency beyond the Windows SDK / CRT. Notable internal subsystems:

- **TUI** — `tabs_*` and `cmd_main_loop` draw a fixed tab bar at the
  top of the screen. The custom line editor (`le_read_line`) handles
  every key and redraws the prompt row only when necessary.
  Console mode is set to `ENABLE_VIRTUAL_TERMINAL_INPUT |
  ENABLE_EXTENDED_FLAGS` and **QuickEdit is explicitly disabled** so
  mouse events reach the program instead of being consumed by
  selection.
- **Dispatch** — `cmd_dispatch` walks the `g_builtins[]` table and
  falls back to `cmd_try_external` (which uses `CreateProcessW` or,
  for `.bat` / `.cmd` files, `cmd_run_batch_file`). If the target is a
  defined `FUNC`, `CALL` routes to `cmd_builtin_callfunc` so user
  functions take priority over same-named batch files.
- **Variable expansion** — `cmd_expand_env_vars` runs the standard
  Windows `ExpandEnvironmentStringsW` first (handles `%FOO%`), then
  a second pass that handles `$obj.key`, `$arr[idx]`, and `$1`..`$8`.
- **Arithmetic** — `loos_eval_expr` is a small recursive-descent
  parser for `+ - * / %` and parens, returning `LLONG_MIN` on syntax
  errors. Identifiers resolve through `loos_resolve` which already
  handles object / array / env-var lookup, so `SET /A x=$user.age + 1`
  works.

## Caveats

- `$1`..`$8` are only bound inside a `CALL`'d function. They are not
  populated for batch scripts invoked by `CALL script.bat arg1 arg2` —
  the legacy `cmd.exe` batch-script semantics in
  `cmd_run_batch_file` are preserved.
- `OBJ` literals do not currently support nested objects
  (`@{a=@{b=1}}`). Use multiple `OBJ` declarations and `OSET` to
  build structure incrementally.
- The JSON / XML converters are deliberately minimal (no streaming,
  no attributes on the XML side, no array values in JSON).
- All new objects, arrays, and functions live only for the lifetime
  of the `cmd.exe` process. They do not persist across `cmd.exe`
  invocations.

## Development log

- Set `LOOSDEBUG=1` in the environment before launching `cmd.exe` to
  get verbose developer logging (`[loosdbg] ...`) on stderr.
- When stdin is redirected (e.g. `cmd.exe < script.txt`) the program
  falls back to `fgetws` line reading and skips the custom line
  editor so batch-mode scripts work.

## Files

| File        | Purpose                                                           |
|-------------|-------------------------------------------------------------------|
| `cmd.c`     | Single-file C source. ~4 500 lines. No third-party dependencies. |
| `cmd.exe`   | Pre-compiled MSVC binary, ready to run on Windows 10 / 11.       |
| `build.bat` | One-shot MSVC build script (auto-calls vcvarsall if needed).     |
| `README.md` | This file — quick start and overview.                             |
| `docs.md`   | Full command reference, syntax, examples, LoOS project background. |

## License

This is a clean-room reconstruction of the decompiled Windows
`cmd.exe` output, modified and extended under the LoOS project.
Use at your own risk.
