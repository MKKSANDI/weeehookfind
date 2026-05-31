# Weeehookfind

Weeehookfind is a Windows webhook and stealer-indicator scanner built around a Rust engine.
This repository is terminal-first and includes only the scanner core plus terminal launcher.

## Repository layout

- `src/weehok-scanner`: core scanner binary (`weehok-scanner.exe`)
- `terminal/`: terminal frontend
- `run_terminal.bat`: quick launcher for terminal mode

## Scanner capabilities

- scans selected paths or all mounted drives
- detects Discord webhook patterns and common obfuscation variants
- supports optional process-memory and runtime network snapshot stages
- emits JSON events (`started`, `progress`, `finding`, `log`, `finished`, `fatal`)
- writes findings to output file with secret redaction by default

## Build

```powershell
cd src\weehok-scanner
cargo build --release
```

## Run: terminal mode

```powershell
cd terminal
python -m pip install -r requirements.txt
python run_weehook_terminal.py
```

Scoped scan example:

```powershell
python run_weehook_terminal.py --path "C:\Users\Public" --threads 6 --max-file-mb 512
```

## Run: scanner directly

```powershell
.\src\weehok-scanner\target\release\weehok-scanner.exe --all-drives --out findings.txt --threads 6 --max-file-mb 512
```

## Safety

- scanner does not delete or modify scanned files
- webhook secrets are redacted in output by default
- full secret output requires explicit unsafe flags
