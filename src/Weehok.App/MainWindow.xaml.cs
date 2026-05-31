using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace Weehok.App;

public partial class MainWindow : Window
{
    private static readonly HttpClient Http = CreateHttpClient();
    private static readonly HttpClient GeminiHttp = CreateGeminiHttpClient();
    private readonly ObservableCollection<FindingItem> _findings = new();
    private readonly ObservableCollection<WebhookGroupItem> _webhookGroups = new();
    private readonly ObservableCollection<ThreatItem> _threats = new();
    private readonly ObservableCollection<HistoryItem> _history = new();
    private readonly Dictionary<string, WebhookGroupItem> _webhookGroupsByHash = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HistoryItem> _historyByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _workspaceRoot;
    private readonly string _findingsPath;
    private string _lastExportPath = "";
    private ICollectionView? _findingsView;
    private ICollectionView? _webhookGroupsView;
    private ICollectionView? _threatsView;
    private Process? _scannerProcess;
    private CancellationTokenSource? _scanCts;
    private Storyboard? _pulseStoryboard;
    private bool _scanCompleted;
    private bool _stopRequested;
    private bool _stopExported;
    private string _customScanPath = "";
    private string _geminiApiKey = "";
    private string _lastAiReportMarkdown = "";

    private const int WmNcHitTest = 0x0084;
    private const int HtClient = 1;
    private const int HtCaption = 2;
    private const int HtLeft = 10;
    private const int HtRight = 11;
    private const int HtTop = 12;
    private const int HtTopLeft = 13;
    private const int HtTopRight = 14;
    private const int HtBottom = 15;
    private const int HtBottomLeft = 16;
    private const int HtBottomRight = 17;
    private const double ResizeBorder = 8;
    private const double CaptionHeight = 58;
    private const string GeminiModel = "gemini-2.5-flash";
    private const int AiPromptReportLimit = 120_000;

    public MainWindow()
    {
        InitializeComponent();
        _workspaceRoot = ResolveWorkspaceRoot();
        _findingsPath = System.IO.Path.Combine(_workspaceRoot, "findings.txt");
        _lastExportPath = _findingsPath;
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        HwndSource.FromHwnd(new WindowInteropHelper(this).Handle)?.AddHook(WindowProc);
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        _findingsView = CollectionViewSource.GetDefaultView(_findings);
        _webhookGroupsView = CollectionViewSource.GetDefaultView(_webhookGroups);
        _threatsView = CollectionViewSource.GetDefaultView(_threats);
        _findingsView.Filter = FilterFinding;
        _webhookGroupsView.Filter = FilterWebhookGroup;
        _threatsView.Filter = FilterThreat;
        FindingsList.ItemsSource = _findingsView;
        WebhookGroupsList.ItemsSource = _webhookGroupsView;
        ThreatsList.ItemsSource = _threatsView;
        AiHistoryList.ItemsSource = _history;
        OutputPathText.Text = _findingsPath;
        var elevated = IsAdministrator();
        ElevationText.Text = elevated ? "ADMIN TOKEN" : "STANDARD TOKEN";
        ElevationText.Foreground = BrushFromHex(elevated ? "#2F6BFF" : "#FBBF24");
        LogConsole("Ready. Webhook report will be written to " + _findingsPath);
        LogConsole(elevated
            ? "Running elevated. Scanner child process will inherit the administrator token."
            : "Not elevated. The app manifest should request administrator rights at launch.");
        UpdateResultsSummary();
        UpdateAiHistorySummary();
        RenderMarkdown(AiReportBox, "### AI report\n\nAdd a Gemini API key, then run **AI analyse** after a scan.");
        RootVisual.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(280)));
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
        await StartScanAsync(null, includeRuntimeSurfaces: true);
    }

    private async Task StartScanAsync(string? targetPath, bool includeRuntimeSurfaces)
    {
        if (_scannerProcess is not null)
        {
            return;
        }

        var scannerPath = ResolveScannerPath();
        if (scannerPath is null)
        {
            LogConsole("Scanner executable was not found. Build the project once so cargo can produce weehok-scanner.exe.");
            SetStatus("Scanner missing", "#F87171");
            return;
        }

        var scopedTarget = !string.IsNullOrWhiteSpace(targetPath) ? targetPath : null;
        if (scopedTarget is not null && !File.Exists(scopedTarget) && !Directory.Exists(scopedTarget))
        {
            LogConsole("Selected scan target no longer exists: " + scopedTarget);
            SetStatus("Target missing", "#F87171");
            return;
        }

        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_findingsPath)!);
        _findings.Clear();
        _webhookGroups.Clear();
        _webhookGroupsByHash.Clear();
        _threats.Clear();
        _history.Clear();
        _historyByKey.Clear();
        ConsoleBox.Clear();
        ResetCounters();
        UpdateResultsSummary();
        UpdateAiHistorySummary();
        _scanCompleted = false;
        _stopRequested = false;
        _stopExported = false;
        SetRunning(true);
        SetStatus("Scanning", "#2F6BFF");
        LogConsole(scopedTarget is null
            ? "Launching staged Rust scanner across all drives with below-normal process priority and no per-file size cap."
            : "Launching deep scoped scan for " + scopedTarget + ".");

        var workerCount = Math.Clamp(Environment.ProcessorCount - 1, 2, 10);
        var startInfo = new ProcessStartInfo
        {
            FileName = scannerPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = _workspaceRoot
        };
        if (scopedTarget is null)
        {
            startInfo.ArgumentList.Add("--all-drives");
        }
        else
        {
            startInfo.ArgumentList.Add("--path");
            startInfo.ArgumentList.Add(scopedTarget);
        }
        startInfo.ArgumentList.Add("--json");
        startInfo.ArgumentList.Add("--out");
        startInfo.ArgumentList.Add(_findingsPath);
        startInfo.ArgumentList.Add("--threads");
        startInfo.ArgumentList.Add(workerCount.ToString());
        startInfo.ArgumentList.Add("--max-file-mb");
        startInfo.ArgumentList.Add("0");
        startInfo.ArgumentList.Add("--emit-secrets-to-ui");
        if (includeRuntimeSurfaces)
        {
            startInfo.ArgumentList.Add("--scan-memory");
            startInfo.ArgumentList.Add("--scan-network");
        }

        _scanCts = new CancellationTokenSource();
        var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };
        _scannerProcess = process;

        process.OutputDataReceived += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Data))
            {
                Dispatcher.Invoke(() => HandleScannerLine(args.Data));
            }
        };
        process.ErrorDataReceived += (_, args) =>
        {
            if (!string.IsNullOrWhiteSpace(args.Data))
            {
                Dispatcher.Invoke(() => LogConsole("[stderr] " + args.Data));
            }
        };

        try
        {
            process.Start();
            try
            {
                process.PriorityClass = ProcessPriorityClass.BelowNormal;
            }
            catch
            {
                LogConsole("Could not lower process priority on this system.");
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await process.WaitForExitAsync(_scanCts.Token);

            if (process.ExitCode != 0 && !_stopRequested)
            {
                SetStatus("Error", "#F87171");
                LogConsole("Scanner exited with code " + process.ExitCode + ".");
            }
        }
        catch (OperationCanceledException)
        {
            LogConsole("Scan cancellation acknowledged.");
        }
        catch (Exception ex)
        {
            SetStatus("Error", "#F87171");
            LogConsole("Failed to run scanner: " + ex.Message);
        }
        finally
        {
            process.Dispose();
            if (ReferenceEquals(_scannerProcess, process))
            {
                _scannerProcess = null;
            }

            _scanCts?.Dispose();
            _scanCts = null;
            SetRunning(false);

            if (_stopRequested)
            {
                SetStatus("Stopped", "#FBBF24");
                if (!_stopExported)
                {
                    ExportCurrentFindings("Stopped scan. Exported visible webhook findings.");
                }
            }
            else if (_scanCompleted)
            {
                ExportCurrentFindings("Scan complete. Exported webhook report.");
            }
            else if (!_scanCompleted && StatusText.Text == "Scanning")
            {
                SetStatus("Idle", "#596477");
            }
        }
    }

    private void StopScan_Click(object sender, RoutedEventArgs e)
    {
        _stopRequested = true;
        SetStatus("Stopping", "#FBBF24");
        LogConsole("Stopping scan.");

        try
        {
            if (_scannerProcess is { HasExited: false } process)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(1500);
            }
        }
        catch (Exception ex)
        {
            LogConsole("Could not stop scanner: " + ex.Message);
        }

        _scanCts?.Cancel();
        ExportCurrentFindings("Stop requested. Exported visible webhook findings.");
    }

    private void OpenFindings_Click(object sender, RoutedEventArgs e)
    {
        var path = File.Exists(_lastExportPath) ? _lastExportPath : _findingsPath;
        if (!File.Exists(path))
        {
            LogConsole("No findings.txt exists yet.");
            return;
        }

        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo(_workspaceRoot) { UseShellExecute = true });
    }

    private void ChooseCustomFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select file to scan",
            CheckFileExists = true,
            Multiselect = false,
            Filter = "All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == true)
        {
            SetCustomScanTarget(dialog.FileName);
        }
    }

    private void ChooseCustomFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Select folder to scan",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) == true)
        {
            SetCustomScanTarget(dialog.FolderName);
        }
    }

    private async void StartCustomScan_Click(object sender, RoutedEventArgs e)
    {
        if (!HasCustomScanTarget())
        {
            CustomTargetStatusText.Text = "Choose or drop a file/folder first.";
            CustomTargetStatusText.Foreground = BrushFromHex("#FBBF24");
            return;
        }

        ResultsTabs.SelectedIndex = 0;
        await StartScanAsync(_customScanPath, CustomRuntimeCheckBox.IsChecked == true);
    }

    private async void CustomAiAnalyze_Click(object sender, RoutedEventArgs e)
    {
        ResultsTabs.SelectedIndex = 4;
        await AnalyzeWithGeminiAsync();
    }

    private void OpenCustomTarget_Click(object sender, RoutedEventArgs e)
    {
        if (HasCustomScanTarget())
        {
            OpenFileLocation(_customScanPath);
        }
    }

    private void ClearCustomTarget_Click(object sender, RoutedEventArgs e)
    {
        SetCustomScanTarget("");
    }

    private void CustomTarget_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void CustomTarget_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } paths)
        {
            SetCustomScanTarget(paths[0]);
        }

        e.Handled = true;
    }

    private bool HasCustomScanTarget()
    {
        return !string.IsNullOrWhiteSpace(_customScanPath)
               && (File.Exists(_customScanPath) || Directory.Exists(_customScanPath));
    }

    private void SetCustomScanTarget(string path)
    {
        _customScanPath = path;
        if (string.IsNullOrWhiteSpace(path))
        {
            CustomTargetBox.Text = "";
            CustomTargetTypeText.Text = "No target selected";
            CustomTargetStatusText.Text = "Select a file/folder or drop it here.";
            CustomTargetStatusText.Foreground = BrushFromHex("#7F8790");
            return;
        }

        var isFile = File.Exists(path);
        var isDirectory = Directory.Exists(path);
        CustomTargetBox.Text = path;
        CustomTargetTypeText.Text = isFile ? "File selected" : isDirectory ? "Folder selected" : "Missing target";
        CustomTargetStatusText.Text = isFile || isDirectory
            ? "Ready for a scoped deep scan."
            : "Target no longer exists.";
        CustomTargetStatusText.Foreground = BrushFromHex(isFile || isDirectory ? "#2F6BFF" : "#F87171");
    }

    private void ResultsSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _findingsView?.Refresh();
        _webhookGroupsView?.Refresh();
        _threatsView?.Refresh();
        UpdateResultsSummary();
    }

    private bool FilterFinding(object item)
    {
        if (item is not FindingItem finding)
        {
            return false;
        }

        var filter = ResultsSearchBox?.Text;
        return string.IsNullOrWhiteSpace(filter)
            || ContainsFilter(finding.Confidence, filter)
            || ContainsFilter(finding.Source, filter)
            || ContainsFilter(finding.Method, filter)
            || ContainsFilter(finding.Evidence, filter)
            || ContainsFilter(finding.Path, filter)
            || ContainsFilter(finding.ThreatLabel, filter)
            || ContainsFilter(finding.ThreatReasons, filter);
    }

    private bool FilterThreat(object item)
    {
        if (item is not ThreatItem threat)
        {
            return false;
        }

        var filter = ResultsSearchBox?.Text;
        return string.IsNullOrWhiteSpace(filter)
            || ContainsFilter(threat.Label, filter)
            || ContainsFilter(threat.Source, filter)
            || ContainsFilter(threat.Reasons, filter)
            || ContainsFilter(threat.Path, filter)
            || ContainsFilter(threat.Score.ToString(), filter);
    }

    private bool FilterWebhookGroup(object item)
    {
        if (item is not WebhookGroupItem group)
        {
            return false;
        }

        var filter = ResultsSearchBox?.Text;
        return string.IsNullOrWhiteSpace(filter)
            || ContainsFilter(group.DisplayName, filter)
            || ContainsFilter(group.RedactedWebhook, filter)
            || ContainsFilter(group.ThreatLabel, filter)
            || group.Locations.Any(location => ContainsFilter(location.Display, filter));
    }

    private static bool ContainsFilter(string value, string filter)
    {
        return value.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateResultsSummary()
    {
        var visibleWebhooks = _webhookGroupsView?.Cast<object>().Count() ?? _webhookGroups.Count;
        var visibleFindings = _findingsView?.Cast<object>().Count() ?? _findings.Count;
        var suffix = string.IsNullOrWhiteSpace(ResultsSearchBox?.Text) ? "" : " visible";
        ResultsSummaryText.Text = visibleWebhooks.ToString("N0") + " webhooks, " +
                                  visibleFindings.ToString("N0") + " raw webhook hits" + suffix;
    }

    private void UpdateAiHistorySummary()
    {
        AiHistorySummaryText.Text = _webhookGroups.Count.ToString("N0") + " webhooks, " +
                                    _findings.Count.ToString("N0") + " raw webhook hits loaded";
    }

    private void GoToAiTab_Click(object sender, RoutedEventArgs e)
    {
        ResultsTabs.SelectedIndex = 4;
    }

    private void SaveGeminiKey_Click(object sender, RoutedEventArgs e)
    {
        var key = GeminiKeyBox.Password.Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            AiStatusText.Text = "Enter a Gemini API key first.";
            AiStatusText.Foreground = BrushFromHex("#FBBF24");
            return;
        }

        _geminiApiKey = key;
        GeminiKeyBox.Password = "";
        AiKeyPanel.Visibility = Visibility.Collapsed;
        AiWorkspace.Visibility = Visibility.Visible;
        AiStatusText.Text = "Gemini key loaded for this session.";
        AiStatusText.Foreground = BrushFromHex("#2F6BFF");
        UpdateAiHistorySummary();
    }

    private void ChangeGeminiKey_Click(object sender, RoutedEventArgs e)
    {
        _geminiApiKey = "";
        AiWorkspace.Visibility = Visibility.Collapsed;
        AiKeyPanel.Visibility = Visibility.Visible;
        AiStatusText.Text = "Key cleared from memory.";
        AiStatusText.Foreground = BrushFromHex("#FBBF24");
        UpdateAiHistorySummary();
    }

    private async void AiAnalyze_Click(object sender, RoutedEventArgs e)
    {
        await AnalyzeWithGeminiAsync();
    }

    private async Task AnalyzeWithGeminiAsync()
    {
        if (string.IsNullOrWhiteSpace(_geminiApiKey))
        {
            AiStatusText.Text = "Enter a Gemini API key first.";
            AiStatusText.Foreground = BrushFromHex("#FBBF24");
            return;
        }

        var report = BuildFindingsReport();
        if (_findings.Count == 0 && _webhookGroups.Count == 0 && File.Exists(_findingsPath))
        {
            report = File.ReadAllText(_findingsPath, Encoding.UTF8);
        }

        if (string.IsNullOrWhiteSpace(report) || report.Contains("No raw webhook findings found.", StringComparison.OrdinalIgnoreCase)
            && report.Contains("No Discord webhooks found.", StringComparison.OrdinalIgnoreCase))
        {
            RenderMarkdown(AiReportBox, "### No detections to analyse\n\nRun a scan first, or open an existing `findings.txt` in the workspace.");
            return;
        }

        AiAnalyzeButton.IsEnabled = false;
        AiStatusText.Text = "AI analysis running...";
        AiStatusText.Foreground = BrushFromHex("#C9D0D8");
        RenderMarkdown(AiReportBox, "### Analysing\n\nGemini is reviewing the current detection history.");

        try
        {
            var prompt = BuildAiPrompt(report);
            var markdown = await CallGeminiAsync(prompt);
            _lastAiReportMarkdown = markdown;
            RenderMarkdown(AiReportBox, markdown);
            AiStatusText.Text = "AI analysis complete.";
            AiStatusText.Foreground = BrushFromHex("#2F6BFF");
        }
        catch (Exception ex)
        {
            var message = "### AI analysis failed\n\n" + ex.Message;
            _lastAiReportMarkdown = message;
            RenderMarkdown(AiReportBox, message);
            AiStatusText.Text = "AI analysis failed.";
            AiStatusText.Foreground = BrushFromHex("#F87171");
            LogConsole("AI analysis failed: " + ex.Message);
        }
        finally
        {
            AiAnalyzeButton.IsEnabled = true;
        }
    }

    private string BuildAiPrompt(string report)
    {
        var trimmedReport = report.Length > AiPromptReportLimit
            ? report[..AiPromptReportLimit] + Environment.NewLine + "[Report truncated for AI prompt]"
            : report;

        return """
You are a defensive malware triage assistant inside a local Windows scanner named Weehok.
Analyze Discord webhook findings and decide whether each webhook appears embedded in infostealer, token logger, or benign code.

Rules:
- Do not provide malware-building instructions or code.
- Treat generic library/manual terms as weak evidence unless paired with credential store artifacts, decoded C2, token/session paths, or strong obfuscation evidence.
- Explain which webhooks are likely malicious, which are likely benign/irrelevant, and what evidence is missing.
- Prefer concise Markdown.
- Use these sections:
  ## Verdict
  ## Webhooks To Treat As Real Problems
  ## Webhooks Likely Benign Or Low Confidence
  ## Needs Manual Review
  ## What To Do Next

Evidence model to apply:
- Strong: full Discord webhook, browser credential DB paths (Login Data, Local State, Network\Cookies, logins.json, key4.db), DPAPI/os_crypt extraction, wallet extension IDs plus wallet context, Telegram tdata/session context, password manager vault context, AMSI detection, decoded archive/staged stolen output.
- Medium: exfil APIs combined with credential targets, obfuscation combined with decoded suspicious content, compiled binary with several credential targets.
- Weak: generic words like cookies, history, wallet, keeper, sendmessage, multipart/form-data, VirtualBox, x64dbg, systeminfo, Run keys, upload docs.

Current Weehok report:
""" + Environment.NewLine + trimmedReport;
    }

    private async Task<string> CallGeminiAsync(string prompt)
    {
        var endpoint = "https://generativelanguage.googleapis.com/v1beta/models/" + GeminiModel + ":generateContent";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.TryAddWithoutValidation("x-goog-api-key", _geminiApiKey);

        var payload = new
        {
            contents = new[]
            {
                new
                {
                    role = "user",
                    parts = new[]
                    {
                        new { text = prompt }
                    }
                }
            },
            generationConfig = new
            {
                temperature = 0.2,
                topP = 0.8,
                maxOutputTokens = 4096
            }
        };

        request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var response = await GeminiHttp.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("Gemini returned " + (int)response.StatusCode + ": " + ExtractGeminiError(body));
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        var text = root.GetProperty("candidates")[0]
            .GetProperty("content")
            .GetProperty("parts")
            .EnumerateArray()
            .Select(part => part.TryGetProperty("text", out var value) ? value.GetString() : "")
            .Where(value => !string.IsNullOrWhiteSpace(value));

        return string.Join(Environment.NewLine, text).Trim();
    }

    private static string ExtractGeminiError(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.TryGetProperty("error", out var error)
                && error.TryGetProperty("message", out var message))
            {
                return message.GetString() ?? body;
            }
        }
        catch
        {
        }

        return body.Length > 500 ? body[..500] : body;
    }

    private void CopyAiReport_Click(object sender, RoutedEventArgs e)
    {
        CopyText(_lastAiReportMarkdown);
    }

    private bool ExportCurrentFindings(string logMessage)
    {
        var report = BuildFindingsReport();
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_findingsPath)!);
            File.WriteAllText(_findingsPath, report, Encoding.UTF8);
            _lastExportPath = _findingsPath;
            OutputPathText.Text = _lastExportPath;
            _stopExported = _stopRequested;
            LogConsole(logMessage + " " + _lastExportPath);
            if (_scanCompleted)
            {
                DetailStatusText.Text = "Scan complete. Webhook report saved to " + System.IO.Path.GetFileName(_lastExportPath) + ".";
            }
            return true;
        }
        catch (Exception ex)
        {
            var primaryError = ex.Message;
            var fallbackPath = NextFallbackFindingsPath();
            try
            {
                File.WriteAllText(fallbackPath, report, Encoding.UTF8);
                _lastExportPath = fallbackPath;
                OutputPathText.Text = _lastExportPath;
                _stopExported = _stopRequested;
                LogConsole("findings.txt is locked, so exported to " + fallbackPath + ". Lock error: " + primaryError);
                if (_scanCompleted)
                {
                    DetailStatusText.Text = "Scan complete. Webhook report saved to " + System.IO.Path.GetFileName(_lastExportPath) + ".";
                }
                return true;
            }
            catch (Exception fallbackEx)
            {
                LogConsole("Could not export findings.txt: " + primaryError);
                LogConsole("Could not export fallback findings file: " + fallbackEx.Message);
                return false;
            }
        }
    }

    private string NextFallbackFindingsPath()
    {
        Directory.CreateDirectory(_workspaceRoot);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var path = System.IO.Path.Combine(_workspaceRoot, "findings-" + stamp + ".txt");
        for (var index = 2; File.Exists(path); index++)
        {
            path = System.IO.Path.Combine(_workspaceRoot, "findings-" + stamp + "-" + index + ".txt");
        }

        return path;
    }

    private string BuildFindingsReport()
    {
        var builder = new StringBuilder();
        builder.AppendLine("Weehok findings.txt");
        builder.AppendLine("Secrets are redacted unless --unsafe-reveal-secrets is used.");
        builder.AppendLine("Exported: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        builder.AppendLine();

        builder.AppendLine("== Webhooks ==");
        if (_webhookGroups.Count == 0)
        {
            builder.AppendLine("No Discord webhooks found.");
        }
        else
        {
            foreach (var group in _webhookGroups)
            {
                builder.Append(FormatWebhookGroup(group));
                builder.AppendLine();
            }
        }

        builder.AppendLine("== Raw Webhook Hits ==");
        if (_findings.Count == 0)
        {
            builder.AppendLine("No raw webhook findings found.");
        }
        else
        {
            foreach (var finding in _findings)
            {
                builder.AppendLine(FormatFinding(finding));
                builder.AppendLine();
            }
        }

        return builder.ToString();
    }

    private static string FormatWebhookGroup(WebhookGroupItem group)
    {
        var builder = new StringBuilder();
        builder.AppendLine("[Webhook] " + group.DisplayName);
        builder.AppendLine("  webhook: " + group.RedactedWebhook);
        builder.AppendLine("  sha256: " + group.Sha256);
        builder.AppendLine("  locations: " + group.Count);
        builder.AppendLine("  context: " + group.ThreatLabel + " (" + group.ThreatScore + ")");
        foreach (var location in group.Locations)
        {
            builder.AppendLine("  - " + location.Display);
        }

        return builder.ToString().TrimEnd();
    }

    private static string FormatThreat(ThreatItem item)
    {
        return "[" + item.Label + "] " + item.Path + Environment.NewLine +
               "  source: " + item.Source + Environment.NewLine +
               "  score: " + item.Score + Environment.NewLine +
               "  reasons: " + item.Reasons;
    }

    private static string FormatFinding(FindingItem item)
    {
        var builder = new StringBuilder();
        builder.AppendLine("[" + item.Confidence + "] " + item.Path);
        builder.AppendLine("  source: " + item.Source);
        builder.AppendLine("  method: " + item.Method);
        builder.AppendLine("  evidence: " + item.Evidence);
        if (!string.IsNullOrWhiteSpace(item.ThreatLabel))
        {
            builder.AppendLine("  context: " + item.ThreatLabel + " (" + item.ThreatScore + ")");
            builder.AppendLine("  reasons: " + item.ThreatReasons);
        }
        builder.AppendLine("  sha256: " + item.Sha256);
        return builder.ToString().TrimEnd();
    }

    private static string FormatHistoryItem(HistoryItem item)
    {
        var builder = new StringBuilder();
        builder.AppendLine("[" + item.Label + "] " + item.PrimaryPath);
        builder.AppendLine("  score: " + item.Score);
        if (!string.IsNullOrWhiteSpace(item.Evidence))
        {
            builder.AppendLine("  evidence: " + item.Evidence);
        }

        builder.AppendLine("  display: " + item.Location);
        return builder.ToString().TrimEnd();
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if ((Keyboard.Modifiers & ModifierKeys.Control) != ModifierKeys.Control || IsTextInputFocused())
        {
            return;
        }

        if (e.Key == Key.A)
        {
            SelectAllActiveResults();
            e.Handled = true;
        }
        else if (e.Key == Key.C)
        {
            CopyActiveSelection();
            e.Handled = true;
        }
    }

    private static bool IsTextInputFocused()
    {
        return Keyboard.FocusedElement is TextBox or PasswordBox or RichTextBox;
    }

    private void CopySelected_Click(object sender, RoutedEventArgs e)
    {
        CopyActiveSelection();
    }

    private void CopyAll_Click(object sender, RoutedEventArgs e)
    {
        CopyAllActiveResults();
    }

    private void OpenFileLocation_Click(object sender, RoutedEventArgs e)
    {
        OpenActiveSelectionLocation();
    }

    private void CopyLocation_Click(object sender, RoutedEventArgs e)
    {
        if (GetContextMenuDataContext(sender) is WebhookLocationItem location)
        {
            CopyText(location.Display);
        }
    }

    private void OpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (GetContextMenuDataContext(sender) is WebhookLocationItem location)
        {
            OpenFileLocation(location.Path);
        }
    }

    private static object? GetContextMenuDataContext(object sender)
    {
        return sender is MenuItem { Parent: ContextMenu { PlacementTarget: FrameworkElement target } }
            ? target.DataContext
            : null;
    }

    private void SelectAllActiveResults()
    {
        switch (ResultsTabs.SelectedIndex)
        {
            case 0:
                WebhookGroupsList.SelectAll();
                WebhookGroupsList.Focus();
                break;
            case 1:
                ThreatsList.SelectAll();
                ThreatsList.Focus();
                break;
            case 2:
                FindingsList.SelectAll();
                FindingsList.Focus();
                break;
            case 4:
                AiHistoryList.SelectAll();
                AiHistoryList.Focus();
                break;
        }
    }

    private void CopyAllActiveResults()
    {
        var text = ResultsTabs.SelectedIndex switch
        {
            0 => string.Join(Environment.NewLine + Environment.NewLine, _webhookGroups.Select(FormatWebhookGroup)),
            1 => string.Join(Environment.NewLine + Environment.NewLine, _threats.Select(FormatThreat)),
            2 => string.Join(Environment.NewLine + Environment.NewLine, _findings.Select(FormatFinding)),
            4 => string.IsNullOrWhiteSpace(_lastAiReportMarkdown)
                ? string.Join(Environment.NewLine + Environment.NewLine, _history.Select(FormatHistoryItem))
                : _lastAiReportMarkdown,
            _ => ""
        };

        CopyText(text);
    }

    private void CopyActiveSelection()
    {
        var text = ResultsTabs.SelectedIndex switch
        {
            0 => FormatSelectedItems<WebhookGroupItem>(WebhookGroupsList.SelectedItems, _webhookGroups, FormatWebhookGroup),
            1 => FormatSelectedItems<ThreatItem>(ThreatsList.SelectedItems, _threats, FormatThreat),
            2 => FormatSelectedItems<FindingItem>(FindingsList.SelectedItems, _findings, FormatFinding),
            4 => AiHistoryList.SelectedItems.Count > 0
                ? FormatSelectedItems<HistoryItem>(AiHistoryList.SelectedItems, _history, FormatHistoryItem)
                : _lastAiReportMarkdown,
            _ => ""
        };

        CopyText(text);
    }

    private static string FormatSelectedItems<T>(
        System.Collections.IList selectedItems,
        IEnumerable<T> fallbackItems,
        Func<T, string> formatter)
    {
        var selected = selectedItems.Cast<T>().ToList();
        var items = selected.Count > 0 ? selected : fallbackItems.ToList();
        return string.Join(Environment.NewLine + Environment.NewLine, items.Select(formatter));
    }

    private void CopyText(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        try
        {
            Clipboard.SetText(text);
            LogConsole("Copied result text to clipboard.");
        }
        catch (Exception ex)
        {
            LogConsole("Could not copy to clipboard: " + ex.Message);
        }
    }

    private void OpenActiveSelectionLocation()
    {
        switch (ResultsTabs.SelectedIndex)
        {
            case 0:
                if (WebhookGroupsList.SelectedItem is WebhookGroupItem group)
                {
                    OpenFileLocation(group.Locations.FirstOrDefault()?.Path ?? "");
                }
                break;
            case 1:
                if (ThreatsList.SelectedItem is ThreatItem threat)
                {
                    OpenFileLocation(threat.Path);
                }
                break;
            case 2:
                if (FindingsList.SelectedItem is FindingItem finding)
                {
                    OpenFileLocation(finding.Path);
                }
                break;
            case 4:
                if (AiHistoryList.SelectedItem is HistoryItem history)
                {
                    OpenFileLocation(history.PrimaryPath);
                }
                break;
        }
    }

    private void OpenFileLocation(string location)
    {
        if (string.IsNullOrWhiteSpace(location))
        {
            return;
        }

        if (location.Contains("://", StringComparison.Ordinal))
        {
            LogConsole("No file location exists for " + location + ".");
            return;
        }

        try
        {
            if (File.Exists(location))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + location.Replace("\"", "\\\"") + "\"")
                {
                    UseShellExecute = true
                });
                return;
            }

            if (Directory.Exists(location))
            {
                Process.Start(new ProcessStartInfo(location) { UseShellExecute = true });
                return;
            }

            var parent = System.IO.Path.GetDirectoryName(location);
            if (!string.IsNullOrWhiteSpace(parent) && Directory.Exists(parent))
            {
                Process.Start(new ProcessStartInfo(parent) { UseShellExecute = true });
                return;
            }

            LogConsole("Location no longer exists: " + location);
        }
        catch (Exception ex)
        {
            LogConsole("Could not open file location: " + ex.Message);
        }
    }

    private void ResultsList_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (FindAncestor<ListBoxItem>(e.OriginalSource as DependencyObject) is { } listBoxItem)
        {
            listBoxItem.IsSelected = true;
            listBoxItem.Focus();
            return;
        }

        if (FindAncestor<ListViewItem>(e.OriginalSource as DependencyObject) is { } listViewItem)
        {
            listViewItem.IsSelected = true;
            listViewItem.Focus();
        }
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private void HandleScannerLine(string line)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var type = root.GetProperty("type").GetString();

            switch (type)
            {
                case "started":
                    HandleStarted(root);
                    break;
                case "progress":
                    HandleProgress(root);
                    break;
                case "finding":
                    HandleFinding(root.GetProperty("finding"));
                    break;
                case "threat":
                    HandleThreat(root.GetProperty("finding"));
                    break;
                case "log":
                    LogConsole("[" + root.GetProperty("level").GetString() + "] " + root.GetProperty("message").GetString());
                    break;
                case "finished":
                    HandleFinished(root);
                    break;
                case "fatal":
                    _scanCompleted = true;
                    SetStatus("Error", "#F87171");
                    LogConsole("[fatal] " + root.GetProperty("message").GetString());
                    break;
            }
        }
        catch (Exception ex)
        {
            LogConsole("Could not parse scanner output: " + ex.Message);
        }
    }

    private void HandleStarted(JsonElement root)
    {
        var roots = root.GetProperty("roots").EnumerateArray().Select(item => item.GetString()).Where(item => item is not null);
        var maxFileText = root.GetProperty("max_file_mb").ValueKind == JsonValueKind.Null
            ? "no per-file size cap"
            : root.GetProperty("max_file_mb").GetUInt64() + " MB file cap";

        DetailStatusText.Text = "Enumerating drives with " + root.GetProperty("threads").GetInt32() + " workers.";
        LogConsole("Started scan. Roots: " + string.Join(", ", roots) + ". " + maxFileText + ".");
    }

    private void HandleProgress(JsonElement root)
    {
        var queued = root.GetProperty("queued").GetUInt64();
        var scanned = root.GetProperty("scanned").GetUInt64();
        var bytes = root.GetProperty("bytes").GetUInt64();
        var findings = root.GetProperty("findings").GetUInt64();
        var skipped = root.GetProperty("skipped").GetUInt64();
        var errors = root.GetProperty("errors").GetUInt64();
        var enumerating = root.GetProperty("enumerating").GetBoolean();

        QueuedText.Text = queued.ToString("N0");
        ScannedText.Text = scanned.ToString("N0");
        FindingsText.Text = findings.ToString("N0");
        BytesText.Text = FormatBytes(bytes);
        ErrorsText.Text = errors.ToString("N0") + " errors, " + skipped.ToString("N0") + " skipped";
        DetailStatusText.Text = enumerating
            ? "Enumerating files and scanning as they are discovered."
            : "Finishing queued files.";

        ScanProgress.IsIndeterminate = enumerating;
        if (!enumerating)
        {
            ScanProgress.Maximum = Math.Max(1, queued);
            ScanProgress.Value = Math.Min(scanned, queued);
        }
    }

    private void HandleFinding(JsonElement finding)
    {
        var item = new FindingItem
        {
            Confidence = finding.GetProperty("confidence").GetString() ?? "",
            Method = finding.GetProperty("method").GetString() ?? "",
            Evidence = finding.GetProperty("evidence").GetString() ?? "",
            Path = finding.GetProperty("path").GetString() ?? "",
            Sha256 = finding.GetProperty("sha256").GetString() ?? ""
            ,
            Secret = finding.TryGetProperty("secret", out var secret) && secret.ValueKind == JsonValueKind.String
                ? secret.GetString() ?? ""
                : "",
            Source = finding.TryGetProperty("source", out var source)
                ? source.GetString() ?? ""
                : "",
            ThreatLabel = finding.TryGetProperty("threat_label", out var threatLabel) && threatLabel.ValueKind == JsonValueKind.String
                ? threatLabel.GetString() ?? ""
                : "",
            ThreatScore = finding.TryGetProperty("threat_score", out var threatScore)
                ? threatScore.GetUInt32()
                : 0,
            ThreatReasons = finding.TryGetProperty("threat_reasons", out var threatReasons) && threatReasons.ValueKind == JsonValueKind.Array
                ? string.Join("; ", threatReasons.EnumerateArray().Select(value => value.GetString()).Where(value => !string.IsNullOrWhiteSpace(value)))
                : ""
        };

        _findings.Add(item);
        AddWebhookGroupHit(item);
        UpdateResultsSummary();
        UpdateAiHistorySummary();
        FindingsList.ScrollIntoView(item);
        LogConsole("Finding [" + item.Confidence + "] " + item.Evidence + " in " + item.Path);
    }

    private void HandleThreat(JsonElement threat)
    {
        // New scanner builds are webhook-only. Ignore legacy standalone threat events
        // so stealer context only appears when it is attached to a webhook hit.
    }

    private void AddWebhookGroupHit(FindingItem item)
    {
        if (string.IsNullOrWhiteSpace(item.Sha256) || string.IsNullOrWhiteSpace(item.Secret))
        {
            return;
        }

        if (!_webhookGroupsByHash.TryGetValue(item.Sha256, out var group))
        {
            group = new WebhookGroupItem
            {
                Sha256 = item.Sha256,
                Secret = item.Secret,
                RedactedWebhook = item.Evidence,
                DisplayName = "Resolving webhook",
                ThreatLabel = string.IsNullOrWhiteSpace(item.ThreatLabel) ? "Webhook only" : item.ThreatLabel,
                ThreatScore = item.ThreatScore
            };
            _webhookGroupsByHash[item.Sha256] = group;
            _webhookGroups.Add(group);
            AddHistoryItem("webhook:" + item.Sha256, "Discord webhook", item.ThreatScore, item.Path, item.ThreatReasons);
            _ = HydrateWebhookMetadataAsync(group, item.Secret);
        }

        if (item.ThreatScore > group.ThreatScore)
        {
            group.ThreatScore = item.ThreatScore;
            group.ThreatLabel = string.IsNullOrWhiteSpace(item.ThreatLabel) ? group.ThreatLabel : item.ThreatLabel;
        }

        group.Locations.Add(new WebhookLocationItem
        {
            Path = item.Path,
            Source = item.Source,
            Method = item.Method,
            ThreatReasons = item.ThreatReasons,
            Display = item.Source + " | " + item.Method + " | " + item.Path +
                      (string.IsNullOrWhiteSpace(item.ThreatReasons) ? "" : " | " + item.ThreatReasons)
        });
        group.Count = group.Locations.Count;
        UpdateWebhookHistory("webhook:" + item.Sha256, group, item.Path, item.ThreatReasons);
    }

    private void AddHistoryItem(string key, string label, uint score, string location, string evidence)
    {
        if (_historyByKey.TryGetValue(key, out var existing))
        {
            existing.Score = Math.Max(existing.Score, score);
            if (string.IsNullOrWhiteSpace(existing.PrimaryPath))
            {
                existing.PrimaryPath = location;
            }
            if (!string.IsNullOrWhiteSpace(evidence))
            {
                existing.Evidence = evidence;
            }
            return;
        }

        var item = new HistoryItem
        {
            Label = label,
            Score = score,
            Location = location,
            PrimaryPath = location,
            Evidence = evidence
        };
        _historyByKey[key] = item;
        _history.Add(item);
    }

    private void UpdateWebhookHistory(string key, WebhookGroupItem group, string latestPath, string evidence)
    {
        if (!_historyByKey.TryGetValue(key, out var history))
        {
            return;
        }

        history.Score = Math.Max(history.Score, group.ThreatScore);
        history.Label = string.IsNullOrWhiteSpace(group.ThreatLabel) || group.ThreatLabel == "Webhook only"
            ? "Discord webhook"
            : "Webhook + " + group.ThreatLabel;
        history.Location = group.Count == 1
            ? latestPath
            : group.Count.ToString("N0") + " locations, latest: " + latestPath;
        if (string.IsNullOrWhiteSpace(history.PrimaryPath))
        {
            history.PrimaryPath = latestPath;
        }
        if (!string.IsNullOrWhiteSpace(evidence))
        {
            history.Evidence = evidence;
        }
    }

    private async Task HydrateWebhookMetadataAsync(WebhookGroupItem group, string webhook)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, webhook);
            using var response = await Http.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                Dispatcher.Invoke(() => group.DisplayName = "Webhook metadata unavailable");
                return;
            }

            using var stream = await response.Content.ReadAsStreamAsync();
            using var document = await JsonDocument.ParseAsync(stream);
            var root = document.RootElement;
            var id = root.TryGetProperty("id", out var idElement) ? idElement.GetString() : "";
            var name = root.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : "";
            var avatar = root.TryGetProperty("avatar", out var avatarElement) && avatarElement.ValueKind == JsonValueKind.String
                ? avatarElement.GetString()
                : "";

            Dispatcher.Invoke(() =>
            {
                group.DisplayName = string.IsNullOrWhiteSpace(name) ? "Unnamed Discord webhook" : name!;
                if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(avatar))
                {
                    group.AvatarUri = "https://cdn.discordapp.com/avatars/" + id + "/" + avatar + ".png?size=64";
                }
            });
        }
        catch (Exception ex)
        {
            Dispatcher.Invoke(() =>
            {
                group.DisplayName = "Webhook metadata failed";
                LogConsole("Webhook metadata lookup failed: " + ex.Message);
            });
        }
    }

    private void HandleFinished(JsonElement root)
    {
        _scanCompleted = true;
        SetStatus("Complete", "#2F6BFF");
        ScanProgress.IsIndeterminate = false;
        ScanProgress.Maximum = Math.Max(1, root.GetProperty("queued").GetUInt64());
        ScanProgress.Value = ScanProgress.Maximum;
        DetailStatusText.Text = "Scan complete. Webhook report saved to findings.txt.";
        LogConsole("Complete. Scanned " + root.GetProperty("scanned").GetUInt64().ToString("N0") +
                   " files, found " + root.GetProperty("findings").GetUInt64().ToString("N0") +
                   ", skipped " + root.GetProperty("skipped").GetUInt64().ToString("N0") +
                   ", errors " + root.GetProperty("errors").GetUInt64().ToString("N0") + ".");
        DetailStatusText.Text = "Scan complete. Exporting report after scanner closes.";
    }

    private void SetRunning(bool running)
    {
        StartButton.IsEnabled = !running;
        StopButton.IsEnabled = running;
        OpenFindingsButton.IsEnabled = !running;
        CustomScanButton.IsEnabled = !running;
        ChooseCustomFileButton.IsEnabled = !running;
        ChooseCustomFolderButton.IsEnabled = !running;

        if (running)
        {
            StartPulse();
            ScanProgress.IsIndeterminate = true;
        }
        else
        {
            StopPulse();
            ScanProgress.IsIndeterminate = false;
        }
    }

    private void SetStatus(string text, string color)
    {
        StatusText.Text = text;
        StatusDot.Fill = BrushFromHex(color);
    }

    private void ResetCounters()
    {
        QueuedText.Text = "0";
        ScannedText.Text = "0";
        FindingsText.Text = "0";
        BytesText.Text = "0 B";
        ErrorsText.Text = "0 errors, 0 skipped";
        ScanProgress.Value = 0;
        DetailStatusText.Text = "Starting scanner.";
    }

    private void LogConsole(string message)
    {
        ConsoleBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);
        ConsoleBox.ScrollToEnd();
    }

    private void StartPulse()
    {
        _pulseStoryboard ??= (Storyboard)FindResource("ScanPulseStoryboard");
        _pulseStoryboard.Begin(this, true);
    }

    private void StopPulse()
    {
        _pulseStoryboard?.Stop(this);
        ActivityGlow.Opacity = 0.30;
    }

    private string? ResolveScannerPath()
    {
        var candidates = new[]
        {
            System.IO.Path.Combine(AppContext.BaseDirectory, "weehok-scanner.exe"),
            System.IO.Path.Combine(_workspaceRoot, "src", "weehok-scanner", "target", "release", "weehok-scanner.exe"),
            System.IO.Path.Combine(_workspaceRoot, "src", "weehok-scanner", "target", "debug", "weehok-scanner.exe")
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static string ResolveWorkspaceRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(System.IO.Path.Combine(directory.FullName, "Weehok.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return AppContext.BaseDirectory;
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return value.ToString(unit == 0 ? "N0" : "N1") + " " + units[unit];
    }

    private static Brush BrushFromHex(string color)
    {
        return (Brush)new BrushConverter().ConvertFromString(color)!;
    }

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(6)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Weehok/1.0");
        return client;
    }

    private static HttpClient CreateGeminiHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(90)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Weehok/1.0");
        return client;
    }

    private static void RenderMarkdown(RichTextBox box, string markdown)
    {
        var document = new FlowDocument
        {
            Background = Brushes.Transparent,
            Foreground = BrushFromHex("#D6DCE2"),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 13,
            PagePadding = new Thickness(0)
        };

        var normalized = (markdown ?? "").Replace("\r\n", "\n").Replace('\r', '\n');
        var inCodeBlock = false;
        var codeBuilder = new StringBuilder();

        foreach (var line in normalized.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("```", StringComparison.Ordinal))
            {
                if (inCodeBlock)
                {
                    AddCodeParagraph(document, codeBuilder.ToString().TrimEnd());
                    codeBuilder.Clear();
                    inCodeBlock = false;
                }
                else
                {
                    inCodeBlock = true;
                }

                continue;
            }

            if (inCodeBlock)
            {
                codeBuilder.AppendLine(line);
                continue;
            }

            AddMarkdownLine(document, line);
        }

        if (inCodeBlock && codeBuilder.Length > 0)
        {
            AddCodeParagraph(document, codeBuilder.ToString().TrimEnd());
        }

        box.Document = document;
    }

    private static void AddMarkdownLine(FlowDocument document, string line)
    {
        var trimmed = line.Trim();
        if (trimmed.Length == 0)
        {
            document.Blocks.Add(new Paragraph { Margin = new Thickness(0, 0, 0, 6) });
            return;
        }

        var paragraph = new Paragraph
        {
            Margin = new Thickness(0, 0, 0, 8),
            LineHeight = 20
        };

        if (trimmed.StartsWith("### ", StringComparison.Ordinal))
        {
            paragraph.FontSize = 15;
            paragraph.FontWeight = FontWeights.SemiBold;
            paragraph.Foreground = BrushFromHex("#F1F4F7");
            paragraph.Inlines.Add(new Run(trimmed[4..]));
        }
        else if (trimmed.StartsWith("## ", StringComparison.Ordinal))
        {
            paragraph.FontSize = 17;
            paragraph.FontWeight = FontWeights.SemiBold;
            paragraph.Foreground = BrushFromHex("#F1F4F7");
            paragraph.Margin = new Thickness(0, 2, 0, 10);
            paragraph.Inlines.Add(new Run(trimmed[3..]));
        }
        else if (trimmed.StartsWith("# ", StringComparison.Ordinal))
        {
            paragraph.FontSize = 19;
            paragraph.FontWeight = FontWeights.SemiBold;
            paragraph.Foreground = BrushFromHex("#F1F4F7");
            paragraph.Margin = new Thickness(0, 2, 0, 12);
            paragraph.Inlines.Add(new Run(trimmed[2..]));
        }
        else if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed.StartsWith("* ", StringComparison.Ordinal))
        {
            paragraph.Inlines.Add(new Run("• ") { Foreground = BrushFromHex("#2F6BFF"), FontWeight = FontWeights.SemiBold });
            AddInlineMarkdown(paragraph, trimmed[2..]);
        }
        else if (TrySplitNumberedLine(trimmed, out var number, out var text))
        {
            paragraph.Inlines.Add(new Run(number + " ") { Foreground = BrushFromHex("#2F6BFF"), FontWeight = FontWeights.SemiBold });
            AddInlineMarkdown(paragraph, text);
        }
        else
        {
            AddInlineMarkdown(paragraph, trimmed);
        }

        document.Blocks.Add(paragraph);
    }

    private static void AddCodeParagraph(FlowDocument document, string code)
    {
        document.Blocks.Add(new Paragraph(new Run(code))
        {
            Background = BrushFromHex("#0A0D10"),
            Foreground = BrushFromHex("#C9D0D8"),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 10),
            Padding = new Thickness(10),
            LineHeight = 18
        });
    }

    private static void AddInlineMarkdown(Paragraph paragraph, string text)
    {
        var buffer = new StringBuilder();
        var bold = false;
        var code = false;

        void Flush()
        {
            if (buffer.Length == 0)
            {
                return;
            }

            var run = new Run(buffer.ToString());
            if (bold)
            {
                run.FontWeight = FontWeights.SemiBold;
                run.Foreground = BrushFromHex("#F1F4F7");
            }

            if (code)
            {
                run.FontFamily = new FontFamily("Consolas");
                run.Background = BrushFromHex("#10151A");
                run.Foreground = BrushFromHex("#C9D0D8");
            }

            paragraph.Inlines.Add(run);
            buffer.Clear();
        }

        for (var i = 0; i < text.Length; i++)
        {
            if (i + 1 < text.Length && text[i] == '*' && text[i + 1] == '*')
            {
                Flush();
                bold = !bold;
                i++;
                continue;
            }

            if (text[i] == '`')
            {
                Flush();
                code = !code;
                continue;
            }

            buffer.Append(text[i]);
        }

        Flush();
    }

    private static bool TrySplitNumberedLine(string line, out string number, out string text)
    {
        number = "";
        text = "";
        var dot = line.IndexOf(". ", StringComparison.Ordinal);
        if (dot <= 0 || dot > 3)
        {
            return false;
        }

        var prefix = line[..dot];
        if (!prefix.All(char.IsDigit))
        {
            return false;
        }

        number = prefix + ".";
        text = line[(dot + 2)..];
        return true;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            DragMove();
        }
    }

    private IntPtr WindowProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg != WmNcHitTest)
        {
            return IntPtr.Zero;
        }

        var screenPoint = GetPointFromLParam(lParam);
        var point = PointFromScreen(screenPoint);
        var hit = HitTestWindow(point);
        if (hit == HtClient)
        {
            return IntPtr.Zero;
        }

        handled = true;
        return new IntPtr(hit);
    }

    private int HitTestWindow(Point point)
    {
        if (point.X < 0 || point.Y < 0 || point.X > ActualWidth || point.Y > ActualHeight)
        {
            return HtClient;
        }

        var left = point.X <= ResizeBorder;
        var right = point.X >= ActualWidth - ResizeBorder;
        var top = point.Y <= ResizeBorder;
        var bottom = point.Y >= ActualHeight - ResizeBorder;

        if (top && left) return HtTopLeft;
        if (top && right) return HtTopRight;
        if (bottom && left) return HtBottomLeft;
        if (bottom && right) return HtBottomRight;
        if (left) return HtLeft;
        if (right) return HtRight;
        if (top) return HtTop;
        if (bottom) return HtBottom;

        var overWindowButtons = point.Y <= 44 && point.X >= ActualWidth - 92;
        if (point.Y <= CaptionHeight && !overWindowButtons)
        {
            return HtCaption;
        }

        return HtClient;
    }

    private static Point GetPointFromLParam(IntPtr lParam)
    {
        var value = lParam.ToInt64();
        var x = unchecked((short)(value & 0xFFFF));
        var y = unchecked((short)((value >> 16) & 0xFFFF));
        return new Point(x, y);
    }

    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}

public sealed class FindingItem
{
    public string Confidence { get; init; } = "";
    public string Method { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Path { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public string Secret { get; init; } = "";
    public string Source { get; init; } = "";
    public string ThreatLabel { get; init; } = "";
    public uint ThreatScore { get; init; }
    public string ThreatReasons { get; init; } = "";
}

public sealed class ThreatItem
{
    public string Label { get; init; } = "";
    public uint Score { get; init; }
    public string Source { get; init; } = "";
    public string Reasons { get; init; } = "";
    public string Path { get; init; } = "";
}

public sealed class HistoryItem : INotifyPropertyChanged
{
    private string _label = "";
    private uint _score;
    private string _location = "";
    private string _primaryPath = "";
    private string _evidence = "";

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Label
    {
        get => _label;
        set => SetField(ref _label, value);
    }

    public uint Score
    {
        get => _score;
        set => SetField(ref _score, value);
    }

    public string Location
    {
        get => _location;
        set => SetField(ref _location, value);
    }

    public string PrimaryPath
    {
        get => _primaryPath;
        set => SetField(ref _primaryPath, value);
    }

    public string Evidence
    {
        get => _evidence;
        set => SetField(ref _evidence, value);
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }
}

public sealed class WebhookLocationItem
{
    public string Display { get; init; } = "";
    public string Path { get; init; } = "";
    public string Source { get; init; } = "";
    public string Method { get; init; } = "";
    public string ThreatReasons { get; init; } = "";
}

public sealed class WebhookGroupItem : INotifyPropertyChanged
{
    private string _displayName = "Unknown webhook";
    private string _avatarUri = "";
    private string _threatLabel = "Webhook only";
    private uint _threatScore;
    private int _count;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<WebhookLocationItem> Locations { get; } = new();
    public string Sha256 { get; init; } = "";
    public string Secret { get; init; } = "";
    public string RedactedWebhook { get; init; } = "";

    public string DisplayName
    {
        get => _displayName;
        set => SetField(ref _displayName, value);
    }

    public string AvatarUri
    {
        get => _avatarUri;
        set => SetField(ref _avatarUri, value);
    }

    public string ThreatLabel
    {
        get => _threatLabel;
        set
        {
            if (SetField(ref _threatLabel, value))
            {
                OnPropertyChanged(nameof(ThreatBrush));
            }
        }
    }

    public uint ThreatScore
    {
        get => _threatScore;
        set
        {
            if (SetField(ref _threatScore, value))
            {
                OnPropertyChanged(nameof(ThreatBrush));
            }
        }
    }

    public int Count
    {
        get => _count;
        set
        {
            if (SetField(ref _count, value))
            {
                OnPropertyChanged(nameof(CountLabel));
            }
        }
    }

    public string CountLabel => Count == 1 ? "1 location" : Count + " locations";
    public string ThreatBrush => ThreatLabel.Contains("likely", StringComparison.OrdinalIgnoreCase)
        ? "#EF4444"
        : ThreatLabel.Contains("suspicious", StringComparison.OrdinalIgnoreCase) || ThreatScore >= 58
            ? "#FBBF24"
            : "#7F8790";

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
