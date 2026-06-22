using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Forensics;

[SupportedOSPlatform("windows")]
public sealed partial class MemoryForensicsService(IMemoryDumpResultRepository repo) : IMemoryForensicsService
{
    private const uint MiniDumpWithFullMemory = 0x00000002;
    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

    private static readonly HashSet<string> SuspiciousApiNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "RtlCreateUserThread", "SetWindowsHookEx", "GetAsyncKeyState", "keybd_event",
        "mouse_event", "CreateToolhelp32Snapshot", "OpenProcess", "ReadProcessMemory",
        "QueueUserAPC", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "ShellExecuteA", "ShellExecuteW",
        "WinExec", "CreateProcessA", "CreateProcessW", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
    };

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        SafeFileHandle hFile,
        uint dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    public async Task<MemoryDumpResult> DumpAndAnalyzeAsync(int processId, string outputDirectory, CancellationToken ct = default)
    {
        return await Task.Run<MemoryDumpResult>(() =>
        {
            SysProcess? targetProcess = null;
            try { targetProcess = SysProcess.GetProcessById(processId); }
            catch { }

            var processName = targetProcess?.ProcessName ?? $"pid_{processId}";
            Directory.CreateDirectory(outputDirectory);
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var dumpPath = Path.Combine(outputDirectory, $"dump_{processId}_{timestamp}.dmp");

            var dumpSuccess = false;
            var hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (hProcess != IntPtr.Zero)
            {
                try
                {
                    using var fs = new FileStream(dumpPath, FileMode.Create, FileAccess.Write, FileShare.None);
                    dumpSuccess = MiniDumpWriteDump(
                        hProcess,
                        (uint)processId,
                        fs.SafeFileHandle,
                        MiniDumpWithFullMemory,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero);
                }
                catch { }
                finally
                {
                    CloseHandle(hProcess);
                }
            }

            targetProcess?.Dispose();

            var extractedStrings = new List<string>();
            if (dumpSuccess && File.Exists(dumpPath))
            {
                try
                {
                    var bytes = File.ReadAllBytes(dumpPath);
                    extractedStrings.AddRange(ExtractAsciiStrings(bytes, 6));
                    extractedStrings.AddRange(ExtractUnicodeStrings(bytes, 6));
                }
                catch { }
            }

            var extractedIps = extractedStrings
                .Where(s => IpRegex().IsMatch(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(100)
                .ToList();

            var extractedUrls = extractedStrings
                .Where(s => UrlRegex().IsMatch(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(100)
                .ToList();

            var suspiciousImports = extractedStrings
                .Where(s => SuspiciousApiNames.Contains(s.Trim()))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var severity = 0;
            if (suspiciousImports.Count >= 5) severity = 9;
            else if (suspiciousImports.Count >= 2) severity = 6;
            else if (suspiciousImports.Count >= 1) severity = 3;
            if (extractedUrls.Count > 0) severity = Math.Max(severity, 4);

            var result = new MemoryDumpResult
            {
                Id = Guid.NewGuid(),
                ProcessName = processName,
                ProcessId = processId,
                DumpFilePath = dumpSuccess ? dumpPath : string.Empty,
                ExtractedStrings = string.Join("|", extractedStrings.Take(500)),
                ExtractedIps = string.Join("|", extractedIps),
                ExtractedUrls = string.Join("|", extractedUrls),
                SuspiciousImports = string.Join("|", suspiciousImports),
                Severity = severity,
                CreatedAtUtc = DateTime.UtcNow
            };

            return result;
        }, ct);
    }

    public async Task SaveResultAsync(MemoryDumpResult result, CancellationToken ct = default)
        => await repo.AddAsync(result, ct);

    private static IEnumerable<string> ExtractAsciiStrings(byte[] bytes, int minLength)
    {
        var sb = new StringBuilder();
        foreach (var b in bytes)
        {
            if (b >= 0x20 && b < 0x7F)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLength)
                    yield return sb.ToString();
                sb.Clear();
            }
        }
        if (sb.Length >= minLength)
            yield return sb.ToString();
    }

    private static IEnumerable<string> ExtractUnicodeStrings(byte[] bytes, int minLength)
    {
        var sb = new StringBuilder();
        for (var i = 0; i + 1 < bytes.Length; i += 2)
        {
            var ch = (char)(bytes[i] | (bytes[i + 1] << 8));
            if (ch >= 0x20 && ch < 0x7F)
            {
                sb.Append(ch);
            }
            else
            {
                if (sb.Length >= minLength)
                    yield return sb.ToString();
                sb.Clear();
            }
        }
        if (sb.Length >= minLength)
            yield return sb.ToString();
    }

    [GeneratedRegex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
    private static partial Regex IpRegex();

    [GeneratedRegex(@"https?://[^\s""'<>]{8,}")]
    private static partial Regex UrlRegex();
}
