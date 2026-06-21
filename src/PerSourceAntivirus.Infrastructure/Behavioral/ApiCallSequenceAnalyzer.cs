using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;
using ProcessModule = System.Diagnostics.ProcessModule;

namespace PerSourceAntivirus.Infrastructure.Behavioral;

[SupportedOSPlatform("windows")]
public sealed class ApiCallSequenceAnalyzer : IApiCallSequenceAnalyzer
{
    private static readonly Dictionary<string, string[]> SuspiciousPatterns = new()
    {
        ["ProcessInjection"] = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ["DllInjection"]     = ["LoadLibrary", "CreateRemoteThread"],
        ["ProcessHollowing"] = ["NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"],
        ["AtomBombing"]      = ["GlobalAddAtom", "NtQueueApcThread"],
        ["ShellcodeLoader"]  = ["VirtualAlloc", "RtlMoveMemory", "CreateThread"],
    };

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ConcurrentDictionary<int, HashSet<string>> _processApis = new();
    private readonly ConcurrentDictionary<int, HashSet<string>> _alertedPatterns = new();
    private CancellationTokenSource? _cts;

    public event EventHandler<ApiCallSequenceAlertEventArgs>? AlertDetected;

    public ApiCallSequenceAnalyzer(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    public async Task StartMonitoringAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        await Task.Run(() => PollLoopAsync(_cts.Token), _cts.Token).ConfigureAwait(false);
    }

    public void StopMonitoring() => _cts?.Cancel();

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                foreach (var proc in SysProcess.GetProcesses())
                {
                    if (ct.IsCancellationRequested)
                        break;
                    try
                    {
                        AnalyzeProcess(proc);
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }

            await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        }
    }

    private void AnalyzeProcess(SysProcess proc)
    {
        if (proc.Id <= 4)
            return;

        var imports = CollectImports(proc);
        if (imports.Count == 0)
            return;

        _processApis[proc.Id] = imports;

        var alerted = _alertedPatterns.GetOrAdd(proc.Id, _ => new HashSet<string>());

        foreach (var (patternName, apis) in SuspiciousPatterns)
        {
            lock (alerted)
            {
                if (alerted.Contains(patternName))
                    continue;
            }

            var matched = apis.Where(a => imports.Contains(a)).ToList();
            if (matched.Count < 2)
                continue;

            lock (alerted)
            {
                if (!alerted.Add(patternName))
                    continue;
            }

            string imagePath;
            try { imagePath = proc.MainModule?.FileName ?? string.Empty; }
            catch { imagePath = string.Empty; }

            var alert = new ApiCallSequenceAlert
            {
                Id = Guid.NewGuid(),
                ProcessName = proc.ProcessName,
                ProcessId = proc.Id,
                ImagePath = imagePath,
                ApiSequence = string.Join(", ", matched),
                PatternName = patternName,
                DetectionReason = $"Process imports match {patternName} pattern: {string.Join(", ", matched)}",
                Severity = patternName is "ProcessInjection" or "ProcessHollowing" ? 9 : 7,
                DetectedAtUtc = DateTime.UtcNow
            };

            try
            {
                using var scope = _scopeFactory.CreateScope();
                var repo = scope.ServiceProvider.GetRequiredService<IApiCallSequenceAlertRepository>();
                repo.AddAsync(alert, CancellationToken.None).GetAwaiter().GetResult();
            }
            catch { }

            AlertDetected?.Invoke(this, new ApiCallSequenceAlertEventArgs(alert));
        }
    }

    private static HashSet<string> CollectImports(SysProcess proc)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var mainModule = proc.MainModule;
            if (mainModule?.FileName is string exePath && File.Exists(exePath))
            {
                var fromExe = ParsePeImports(exePath);
                foreach (var fn in fromExe) result.Add(fn);
            }
        }
        catch { }

        try
        {
            var modules = proc.Modules;
            foreach (ProcessModule mod in modules)
            {
                try
                {
                    var modName = mod.ModuleName ?? string.Empty;
                    if (modName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase) ||
                        modName.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase) ||
                        modName.Equals("kernelbase.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        if (mod.FileName is string path && File.Exists(path))
                        {
                            var fns = ParsePeImports(path);
                            foreach (var fn in fns) result.Add(fn);
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

        return result;
    }

    private static IReadOnlyList<string> ParsePeImports(string filePath)
    {
        var result = new List<string>();
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var br = new BinaryReader(fs);

            if (fs.Length < 64)
                return result;

            fs.Seek(0x3C, SeekOrigin.Begin);
            var peOffset = br.ReadInt32();

            if (peOffset <= 0 || peOffset + 24 > fs.Length)
                return result;

            fs.Seek(peOffset, SeekOrigin.Begin);
            var signature = br.ReadUInt32();
            if (signature != 0x00004550)
                return result;

            fs.Seek(peOffset + 20, SeekOrigin.Begin);
            var optHeaderSize = br.ReadUInt16();

            if (optHeaderSize == 0)
                return result;

            fs.Seek(peOffset + 24, SeekOrigin.Begin);
            var magic = br.ReadUInt16();
            bool is64 = magic == 0x20B;

            if (is64)
                fs.Seek(peOffset + 24 + 104, SeekOrigin.Begin);
            else
                fs.Seek(peOffset + 24 + 88, SeekOrigin.Begin);

            if (fs.Position + 8 > fs.Length)
                return result;

            var importDirRva = br.ReadUInt32();
            var importDirSize = br.ReadUInt32();

            if (importDirRva == 0 || importDirSize == 0)
                return result;

            var sections = ReadSections(br, peOffset, optHeaderSize);

            var importOffset = RvaToOffset(sections, importDirRva);
            if (importOffset < 0)
                return result;

            fs.Seek(importOffset, SeekOrigin.Begin);

            while (true)
            {
                if (fs.Position + 20 > fs.Length)
                    break;

                var iltRva  = br.ReadUInt32();
                br.ReadUInt32();
                br.ReadUInt32();
                var nameRva = br.ReadUInt32();
                br.ReadUInt32();

                if (nameRva == 0)
                    break;

                var iltOffset = RvaToOffset(sections, iltRva != 0 ? iltRva : 0);
                if (iltOffset < 0)
                    continue;

                var savedPos = fs.Position;
                fs.Seek(iltOffset, SeekOrigin.Begin);

                while (true)
                {
                    if (fs.Position + (is64 ? 8 : 4) > fs.Length)
                        break;

                    ulong entry = is64 ? br.ReadUInt64() : br.ReadUInt32();
                    if (entry == 0)
                        break;

                    bool isOrdinal = is64 ? (entry & 0x8000000000000000UL) != 0 : (entry & 0x80000000U) != 0;
                    if (isOrdinal)
                        continue;

                    uint hintNameRva = (uint)(entry & 0x7FFFFFFF);
                    var hintOffset = RvaToOffset(sections, hintNameRva);
                    if (hintOffset < 0)
                        continue;

                    var namePos = fs.Position;
                    fs.Seek(hintOffset + 2, SeekOrigin.Begin);
                    var fnName = ReadAsciiString(br, 256);
                    fs.Seek(namePos, SeekOrigin.Begin);

                    if (!string.IsNullOrEmpty(fnName))
                        result.Add(fnName);
                }

                fs.Seek(savedPos, SeekOrigin.Begin);
            }
        }
        catch { }

        return result;
    }

    private static (uint VirtualAddress, uint RawOffset, uint VirtualSize)[] ReadSections(
        BinaryReader br, int peOffset, ushort optHeaderSize)
    {
        var fs = br.BaseStream;
        fs.Seek(peOffset + 6, SeekOrigin.Begin);
        var numSections = br.ReadUInt16();

        fs.Seek(peOffset + 24 + optHeaderSize, SeekOrigin.Begin);

        var sections = new (uint VirtualAddress, uint RawOffset, uint VirtualSize)[numSections];
        for (int i = 0; i < numSections; i++)
        {
            if (fs.Position + 40 > fs.Length)
                break;
            fs.Seek(8, SeekOrigin.Current);
            var va   = br.ReadUInt32();
            var vsz  = br.ReadUInt32();
            var raw  = br.ReadUInt32();
            fs.Seek(16, SeekOrigin.Current);
            sections[i] = (va, raw, vsz);
        }
        return sections;
    }

    private static long RvaToOffset((uint VA, uint Raw, uint VSize)[] sections, uint rva)
    {
        foreach (var (va, raw, vsz) in sections)
        {
            if (rva >= va && rva < va + vsz)
                return raw + (rva - va);
        }
        return -1;
    }

    private static string ReadAsciiString(BinaryReader br, int maxLen)
    {
        var chars = new List<char>(maxLen);
        for (int i = 0; i < maxLen; i++)
        {
            if (br.BaseStream.Position >= br.BaseStream.Length)
                break;
            var b = br.ReadByte();
            if (b == 0) break;
            chars.Add((char)b);
        }
        return new string([.. chars]);
    }
}
