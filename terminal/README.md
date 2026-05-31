# Weeehook Terminal Runner

This folder provides a terminal-first launcher for `weehok-scanner.exe`.
It keeps the original Rust scanner behavior but adds:

- live progress bars
- colorized status/log output
- compact finding stream in terminal

## Requirements

- Python 3.10+
- Built scanner binary at one of:
  - `..\src\weehok-scanner\target\release\weehok-scanner.exe`
  - `..\src\weehok-scanner\target\debug\weehok-scanner.exe`

## Setup

```powershell
cd terminal
python -m pip install -r requirements.txt
```

## Run

Default deep scan (all drives, memory + network enabled):

```powershell
python run_weehook_terminal.py
```

Scoped scan:

```powershell
python run_weehook_terminal.py --path "C:\Users\Public" --threads 6 --max-file-mb 512
```

### Useful flags

- `--path <dir-or-file>`: repeat to add multiple roots
- `--all-drives`: force full mounted-drive scan
- `--no-scan-memory`: disable process memory scan phase
- `--no-scan-network`: disable network/DNS/runtime snapshot phase
- `--emit-secrets-to-ui`: include full webhook secret in terminal events
- `--unsafe-reveal-secrets`: also write full webhook secrets to findings file
- `--out <file>`: output file path (default `..\findings.txt`)
