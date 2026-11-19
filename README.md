# lbd
# ldbwatch

Console watcher for LockDown Browser on Windows. It waits for
`LockDownBrowser.exe` to appear, injects a payload that filters the
process-enumeration APIs, and restores window switching with a
low-level keyboard hook.

Nothing in LDB's install directory is modified. Stop the watcher and the
next launch is stock.

## Requirements

- Windows 10/11 x64
- Administrator (LDB runs elevated; an unelevated hook gets bypassed by UIPI)
- MSVC 2019+ or the prebuilt release

## Build

```bat
git clone --recursive https://github.com/landonlats/ldb
cd ldbwatch
build.bat
```

Or with CMake (MinHook is fetched automatically):

```bat
cmake -B build -A x64
cmake --build build --config Release
```

`build.bat` produces all three binaries (x64 + x86). CMake needs two
configure steps, one per architecture.

## Usage

1. Right-click `ldbwatch.exe` -> **Run as administrator**.
2. Launch the exam.

Start the watcher *before* the exam. LDB sweeps the process table a few
hundred ms into init; the watcher polls at 10 ms and normally lands the
payload ahead of it.

## Hotkeys

| Key | Action |
|---|---|
| `Alt+Tab`, `Win`, `Ctrl+Esc` | cycle through windows |
| `Ctrl+Alt+Space` | peek — floats the last window over the exam, exam keeps focus |
| `Ctrl+Alt+Enter` | return to the exam |
| `Ctrl+Alt+H` | hide/show the console |
| `Ctrl+Alt+Q` | quit |

`Ctrl+Alt+Space` is the mode that avoids focus-loss flags, because the
overlay carries `WS_EX_NOACTIVATE` and never takes focus. It also sets
`WDA_EXCLUDEFROMCAPTURE`, so it stays out of screenshots on capture
paths that use desktop duplication.

## Configuration

`hide.cfg` sits next to the payload DLLs, one image name per line,
case-insensitive, `#` for comments. It is re-read on every injection, so
edits apply without restarting the watcher.

Hiding is by image name, which covers apps already running before the
exam. It does not survive hash-based checks — rename the binary if that
is what you are up against.

## Layout

| File | Role |
|---|---|
| `src/ldbwatch.cpp` | watcher, injector dispatch, hook, hotkeys |
| `src/hide.cpp` | injected payload — API filters |
| `src/inject32.cpp` | WOW64 helper, used when the target is 32-bit |
| `config/hide.cfg` | hide list |

## How it works

Three layers, independent of each other:

1. **Detection** — 10 ms process-table poll. New PID triggers injection,
   exit re-arms the watcher.
2. **Hiding** — `NtQuerySystemInformation`, `Process32NextW` and
   `K32EnumProcesses` are inline-hooked and entries matching `hide.cfg`
   are unlinked from results.
3. **Input** — `WH_KEYBOARD_LL` installed after LDB's, so it runs first
   in the hook chain and can consume keys LDB would otherwise swallow.

## Limits

- Hash-based process checks beat name filtering.
- `WDA_EXCLUDEFROMCAPTURE` is ignored by GDI `BitBlt` capture.
- Webcam, ID verification and room scan are untouched.
- `SetForegroundWindow` can be refused by Windows' foreground lock;
  pressing a hotkey usually clears it.
- Extended displays are allowed or blocked by LDB's own config, not here.

## Credits

MinHook (BSD-2-Clause) by Tsuda Kageyu.

## License

MIT — see `LICENSE`.
