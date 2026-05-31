# Weeehookfind

Weeehookfind is a Windows-first webhook and stealer-indicator scanner.
It combines a high-throughput Rust scanner with two frontends:

- WPF desktop app (`src/Weehok.App`)
- terminal runner (`terminal/run_weehook_terminal.py`)

## Components

- `src/weehok-scanner`: Rust scanner engine (`weehok-scanner.exe`)
- `src/Weehok.App`: desktop UI that launches scanner with JSON event streaming
- `terminal/`: terminal-first launcher with progress bars and colorized output

## Core scanner behavior

- scans files across selected paths or all mounted drives
- supports staged detection for webhook URLs and common obfuscation
- supports optional process-memory and network/runtime snapshot scans
- emits line-delimited JSON events: `started`, `progress`, `finding`, `log`, `finished`, `fatal`
- writes a text findings report to disk
- redacts webhook secrets by default unless unsafe flags are explicitly enabled

## Build

Build scanner:

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind\src\weehok-scanner"
cargo build --release
```

Build WPF app:

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind"
.\build.ps1
```

## Run (Desktop)

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind"
.\src\Weehok.App\bin\Release\net9.0-windows\Weehok.exe
```

## Run (Terminal)

```powershell
cd "D:\Moved From C\Desktop\Projects\Weeehookfind\terminal"
python -m pip install -r requirements.txt
python run_weehook_terminal.py
```

Scoped scan example:

```powershell
python run_weehook_terminal.py --path "C:\Users" --threads 6 --max-file-mb 512
```

## Scanner CLI reference

```powershell
.\src\weehok-scanner\target\release\weehok-scanner.exe --all-drives --out findings.txt --threads 6 --max-file-mb 512
```

Important flags:

- `--path <root>`: add scan root (repeatable)
- `--all-drives`: scan mounted drives
- `--scan-memory`: include memory scan stage
- `--scan-network`: include network/runtime stage
- `--emit-secrets-to-ui`: expose raw webhook secrets in event stream
- `--unsafe-reveal-secrets`: write raw secrets to findings output (not recommended)

## Safety notes

- no file deletion or mutation is performed by scanner stages
- output is append/write-only to selected findings path
- sensitive values are redacted by default
