# Weeehookfind

Weeehookfind is a Windows webhook and stealer-indicator scanner built around a Rust engine.
The scanner can be used from either:

- a desktop WPF app (`src/Weehok.App`)
- a terminal runner with live progress UI (`terminal/run_weehook_terminal.py`)

## Repository layout

- `src/weehok-scanner`: core scanner binary (`weehok-scanner.exe`)
- `src/Weehok.App`: desktop frontend
- `terminal/`: terminal frontend
- `build.ps1`: desktop build entry script

## Scanner capabilities

- scans selected paths or all mounted drives
- detects Discord webhook patterns and common obfuscation variants
- supports optional process-memory and runtime network snapshot stages
- emits JSON events (`started`, `progress`, `finding`, `log`, `finished`, `fatal`)
- writes findings to output file with secret redaction by default

## Build

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind\src\weehok-scanner"
cargo build --release
```

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind"
.\build.ps1
```

## Run: terminal mode

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind\terminal"
python -m pip install -r requirements.txt
python run_weehook_terminal.py
```

Scoped scan example:

```powershell
python run_weehook_terminal.py --path "C:\Users" --threads 6 --max-file-mb 512
```

## Run: scanner directly

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind"
.\src\weehok-scanner\target\release\weehok-scanner.exe --all-drives --out findings.txt --threads 6 --max-file-mb 512
```

## Safety

- scanner does not delete or modify scanned files
- webhook secrets are redacted in output by default
- full secret output requires explicit unsafe flags
