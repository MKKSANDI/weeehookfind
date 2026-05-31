from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "findings.txt"


@dataclass
class FindingPreview:
    path: str
    method: str
    confidence: str
    source: str
    threat_label: str
    threat_score: int
    secret_preview: str


@dataclass
class ScanState:
    queued: int = 0
    scanned: int = 0
    bytes_scanned: int = 0
    findings: int = 0
    skipped: int = 0
    errors: int = 0
    enumerating: bool = True
    status: str = "Starting scanner"
    started_at: float = field(default_factory=time.time)
    roots: list[str] = field(default_factory=list)
    output: str = ""
    threads: int = 0
    max_file_mb: int | None = None
    recent_logs: list[tuple[str, str]] = field(default_factory=list)
    recent_findings: list[FindingPreview] = field(default_factory=list)
    fatal_message: str = ""
    exit_code: int | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Terminal UX wrapper for weehok-scanner.exe",
    )
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="Path to scan. Repeat for multiple roots.",
    )
    parser.add_argument(
        "--all-drives",
        action="store_true",
        help="Scan mounted drives A:..Z: (default if no --path is provided).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=max(2, min(10, (os.cpu_count() or 4) - 1)),
        help="Worker thread count passed to scanner.",
    )
    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=0,
        help="Max file size in MB for scan (0 disables cap).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Findings output file path.",
    )
    parser.add_argument(
        "--emit-secrets-to-ui",
        action="store_true",
        help="Allow full webhook secret text in terminal events.",
    )
    parser.add_argument(
        "--unsafe-reveal-secrets",
        action="store_true",
        help="Allow full webhook secrets in output file.",
    )
    parser.add_argument(
        "--scan-memory",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable process memory scan stage.",
    )
    parser.add_argument(
        "--scan-network",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable network/runtime scan stage.",
    )
    return parser.parse_args()


def resolve_scanner_path() -> Path:
    candidates = [
        PROJECT_ROOT / "src" / "weehok-scanner" / "target" / "release" / "weehok-scanner.exe",
        PROJECT_ROOT / "src" / "weehok-scanner" / "target" / "debug" / "weehok-scanner.exe",
        PROJECT_ROOT / "weehok-scanner.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "weehok-scanner.exe was not found. Build scanner first from src/weehok-scanner."
    )


def build_command(args: argparse.Namespace, scanner_path: Path) -> list[str]:
    roots = [Path(p).expanduser() for p in args.path]
    use_all_drives = args.all_drives or not roots

    cmd = [
        str(scanner_path),
        "--json",
        "--out",
        str(args.out),
        "--threads",
        str(max(1, args.threads)),
        "--max-file-mb",
        str(max(0, args.max_file_mb)),
    ]

    if use_all_drives:
        cmd.append("--all-drives")
    else:
        for root in roots:
            cmd.extend(["--path", str(root)])

    if args.emit_secrets_to_ui:
        cmd.append("--emit-secrets-to-ui")
    if args.unsafe_reveal_secrets:
        cmd.append("--unsafe-reveal-secrets")
    if args.scan_memory:
        cmd.append("--scan-memory")
    if args.scan_network:
        cmd.append("--scan-network")

    return cmd


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(value)
    unit_index = 0
    while amount >= 1024 and unit_index < len(units) - 1:
        amount /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(amount)} {units[unit_index]}"
    return f"{amount:.1f} {units[unit_index]}"


def format_secret(secret: str) -> str:
    if not secret:
        return "-"
    if len(secret) <= 16:
        return secret
    return f"{secret[:8]}...{secret[-8:]}"


def append_bounded(items: list[Any], value: Any, limit: int) -> None:
    items.append(value)
    if len(items) > limit:
        del items[0 : len(items) - limit]


def make_summary_panel(state: ScanState) -> Panel:
    elapsed = int(time.time() - state.started_at)
    lines = [
        f"[bold]Status:[/bold] {state.status}",
        f"[bold]Elapsed:[/bold] {elapsed}s",
        f"[bold]Queued:[/bold] {state.queued:,}  [bold]Scanned:[/bold] {state.scanned:,}",
        f"[bold]Findings:[/bold] {state.findings:,}  [bold]Skipped:[/bold] {state.skipped:,}  [bold]Errors:[/bold] {state.errors:,}",
        f"[bold]Bytes:[/bold] {format_bytes(state.bytes_scanned)}",
    ]
    if state.output:
        lines.append(f"[bold]Output:[/bold] {state.output}")
    if state.roots:
        lines.append(f"[bold]Roots:[/bold] {', '.join(state.roots)}")
    if state.fatal_message:
        lines.append(f"[bold red]Fatal:[/bold red] {state.fatal_message}")
    return Panel("\n".join(lines), title="Scan Summary", border_style="cyan")


def make_findings_table(state: ScanState) -> Table:
    table = Table(title="Recent Findings", expand=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Method", width=18)
    table.add_column("Conf", width=8)
    table.add_column("Src", width=8)
    table.add_column("Threat", width=12)
    table.add_column("Score", width=6, justify="right")
    table.add_column("Secret", width=20)

    if not state.recent_findings:
        table.add_row("-", "-", "-", "-", "-", "-", "-")
        return table

    for finding in state.recent_findings[-6:]:
        table.add_row(
            finding.path,
            finding.method,
            finding.confidence,
            finding.source,
            finding.threat_label,
            str(finding.threat_score),
            finding.secret_preview,
        )
    return table


def make_logs_panel(state: ScanState) -> Panel:
    if not state.recent_logs:
        body = Text("No scanner logs yet.", style="dim")
        return Panel(body, title="Recent Logs", border_style="blue")

    lines = []
    for level, message in state.recent_logs[-8:]:
        if level.lower() == "error":
            style = "bold red"
        elif level.lower() == "warn":
            style = "yellow"
        else:
            style = "white"
        lines.append(Text(f"[{level.upper()}] ", style=style) + Text(message))
    return Panel(Group(*lines), title="Recent Logs", border_style="blue")


def apply_event(state: ScanState, event: dict[str, Any]) -> None:
    event_type = str(event.get("type", "")).strip().lower()
    if event_type == "started":
        state.status = "Running"
        state.roots = [str(r) for r in event.get("roots", [])]
        state.output = str(event.get("output", ""))
        state.threads = int(event.get("threads", 0) or 0)
        state.max_file_mb = event.get("max_file_mb")
    elif event_type == "progress":
        state.queued = int(event.get("queued", 0) or 0)
        state.scanned = int(event.get("scanned", 0) or 0)
        state.bytes_scanned = int(event.get("bytes", 0) or 0)
        state.findings = int(event.get("findings", 0) or 0)
        state.skipped = int(event.get("skipped", 0) or 0)
        state.errors = int(event.get("errors", 0) or 0)
        state.enumerating = bool(event.get("enumerating", True))
        state.status = "Enumerating files" if state.enumerating else "Scanning"
    elif event_type == "finding":
        finding = event.get("finding", {}) or {}
        preview = FindingPreview(
            path=str(finding.get("path", "-")),
            method=str(finding.get("method", "-")),
            confidence=str(finding.get("confidence", "-")),
            source=str(finding.get("source", "-")),
            threat_label=str(finding.get("threat_label") or "-"),
            threat_score=int(finding.get("threat_score", 0) or 0),
            secret_preview=format_secret(str(finding.get("secret") or "")),
        )
        append_bounded(state.recent_findings, preview, 24)
    elif event_type == "log":
        level = str(event.get("level", "info"))
        message = str(event.get("message", ""))
        append_bounded(state.recent_logs, (level, message), 40)
    elif event_type == "finished":
        state.queued = int(event.get("queued", state.queued) or state.queued)
        state.scanned = int(event.get("scanned", state.scanned) or state.scanned)
        state.bytes_scanned = int(event.get("bytes", state.bytes_scanned) or state.bytes_scanned)
        state.findings = int(event.get("findings", state.findings) or state.findings)
        state.skipped = int(event.get("skipped", state.skipped) or state.skipped)
        state.errors = int(event.get("errors", state.errors) or state.errors)
        state.output = str(event.get("output", state.output))
        state.status = "Finished"
        state.enumerating = False
    elif event_type == "fatal":
        state.fatal_message = str(event.get("message", "Unknown fatal error"))
        state.status = "Fatal error"


def build_ui(state: ScanState, progress: Progress) -> Group:
    return Group(
        make_summary_panel(state),
        progress,
        make_findings_table(state),
        make_logs_panel(state),
    )


def main() -> int:
    args = parse_args()
    console = Console()

    try:
        scanner_path = resolve_scanner_path()
    except FileNotFoundError as error:
        console.print(f"[bold red]{error}[/bold red]")
        return 1

    args.out = args.out.expanduser().resolve()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    cmd = build_command(args, scanner_path)

    state = ScanState(status="Launching scanner")

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=44),
        TextColumn("{task.completed:,}/{task.total:,} files"),
        TimeElapsedColumn(),
        expand=True,
    )
    task_id = progress.add_task("Waiting for first progress event", total=1, completed=0)

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        cmd,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
    )

    with Live(build_ui(state, progress), console=console, refresh_per_second=12) as live:
        try:
            assert process.stdout is not None
            for raw_line in process.stdout:
                line = raw_line.strip()
                if not line:
                    continue

                event: dict[str, Any] | None = None
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        event = parsed
                except json.JSONDecodeError:
                    append_bounded(state.recent_logs, ("info", line), 40)

                if event:
                    apply_event(state, event)

                queue_total = max(state.queued, state.scanned, 1)
                progress.update(
                    task_id,
                    description=state.status,
                    total=queue_total,
                    completed=min(state.scanned, queue_total),
                )
                live.update(build_ui(state, progress))

            process.wait()
            state.exit_code = int(process.returncode)
            if state.exit_code == 0 and state.status != "Fatal error":
                state.status = "Finished"
            elif state.status != "Fatal error":
                state.status = f"Failed (exit {state.exit_code})"
            progress.update(
                task_id,
                description=state.status,
                total=max(state.queued, state.scanned, 1),
                completed=max(state.scanned, 0),
            )
            live.update(build_ui(state, progress))
        except KeyboardInterrupt:
            process.kill()
            state.status = "Cancelled by user"
            state.exit_code = 130
            progress.update(task_id, description=state.status)
            live.update(build_ui(state, progress))

    if state.exit_code == 0:
        console.print(f"[bold green]Scan complete.[/bold green] Findings file: {args.out}")
    else:
        console.print(f"[bold red]Scan failed.[/bold red] Exit code: {state.exit_code}")

    return int(state.exit_code or 0)


if __name__ == "__main__":
    sys.exit(main())
