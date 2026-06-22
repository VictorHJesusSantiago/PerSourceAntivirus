using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Forensics;

[SupportedOSPlatform("windows")]
public sealed class FirmwareVariableMonitor(IFirmwareVariableSnapshotRepository repo) : IFirmwareVariableMonitor
{
    private static readonly (string Name, string Guid)[] UefiVariables =
    [
        ("BootOrder",  "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"),
        ("Boot0000",   "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"),
        ("Boot0001",   "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"),
        ("ConOut",     "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"),
        ("SecureBoot", "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"),
    ];

    private bool _baselineEstablished;

    public bool IsBaselineEstablished => _baselineEstablished;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFirmwareEnvironmentVariableEx(
        string lpName,
        string lpGuid,
        byte[] pBuffer,
        uint nSize,
        out uint pdwAttributes);

    public async Task<IReadOnlyList<FirmwareVariableSnapshot>> ScanAsync(CancellationToken ct = default)
    {
        var baseline = await repo.GetBaselineAsync(ct);
        var baselineMap = baseline.ToDictionary(
            s => s.VariableName,
            s => s.CurrentValueHash,
            StringComparer.OrdinalIgnoreCase);

        var snapshots = new List<FirmwareVariableSnapshot>();
        var now = DateTime.UtcNow;

        foreach (var (name, guid) in UefiVariables)
        {
            ct.ThrowIfCancellationRequested();
            var currentHash = ReadVariableHash(name, guid);
            var baselineHash = baselineMap.TryGetValue(name, out var bh) ? bh : string.Empty;
            var isSuspicious = !string.IsNullOrEmpty(baselineHash)
                && !string.Equals(currentHash, baselineHash, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrEmpty(currentHash);

            var changeDescription = isSuspicious
                ? $"Value changed from baseline. Previous: {baselineHash[..Math.Min(16, baselineHash.Length)]}..., Current: {currentHash[..Math.Min(16, currentHash.Length)]}..."
                : string.IsNullOrEmpty(baselineHash) ? "No baseline established" : "No change detected";

            snapshots.Add(new FirmwareVariableSnapshot
            {
                Id = Guid.NewGuid(),
                VariableName = name,
                VariableNamespace = guid,
                CurrentValueHash = currentHash,
                BaselineValueHash = baselineHash,
                IsSuspicious = isSuspicious,
                ChangeDescription = changeDescription,
                SnapshotAtUtc = now
            });
        }

        return snapshots;
    }

    public async Task SaveBaselineAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var snapshots = new List<FirmwareVariableSnapshot>();

        foreach (var (name, guid) in UefiVariables)
        {
            ct.ThrowIfCancellationRequested();
            var hash = ReadVariableHash(name, guid);
            snapshots.Add(new FirmwareVariableSnapshot
            {
                Id = Guid.NewGuid(),
                VariableName = name,
                VariableNamespace = guid,
                CurrentValueHash = hash,
                BaselineValueHash = hash,
                IsSuspicious = false,
                ChangeDescription = "Baseline snapshot",
                SnapshotAtUtc = now
            });
        }

        await repo.AddRangeAsync(snapshots, ct);
        _baselineEstablished = true;
    }

    private static string ReadVariableHash(string name, string guid)
    {
        try
        {
            var buffer = new byte[4096];
            var size = GetFirmwareEnvironmentVariableEx(name, guid, buffer, (uint)buffer.Length, out _);
            if (size == 0)
                return string.Empty;

            var data = buffer[..(int)size];
            var hash = SHA256.HashData(data);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return string.Empty;
        }
    }
}
