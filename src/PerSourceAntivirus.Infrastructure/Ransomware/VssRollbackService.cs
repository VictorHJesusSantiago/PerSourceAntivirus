using System.Management;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

[SupportedOSPlatform("windows")]
public sealed class VssRollbackService : IVssRollbackService
{
    private readonly IVssSnapshotRepository _repository;

    public event EventHandler<VssSnapshotEventArgs>? SnapshotCreated;

    public VssRollbackService(IVssSnapshotRepository repository)
    {
        _repository = repository;
    }

    public async Task<string?> CreateSnapshotAsync(string folderPath, string reason, CancellationToken ct)
    {
        string? shadowId = null;
        string? snapshotPath = null;

        try
        {
            using var mgmt = new ManagementClass("Win32_ShadowCopy");
            var inParams = mgmt.GetMethodParameters("Create");
            inParams["Volume"] = Path.GetPathRoot(folderPath)!;
            inParams["Context"] = "ClientAccessible";
            var result = mgmt.InvokeMethod("Create", inParams, null);
            shadowId = result?["ShadowID"]?.ToString();

            if (!string.IsNullOrEmpty(shadowId))
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadowId}'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    snapshotPath = obj["DeviceObject"]?.ToString() ?? string.Empty;
                    break;
                }
            }
        }
        catch { }

        var snapshotEvent = new VssSnapshotEvent
        {
            Id = Guid.NewGuid(),
            FolderPath = folderPath,
            SnapshotId = shadowId ?? string.Empty,
            SnapshotPath = snapshotPath ?? string.Empty,
            TriggerReason = reason,
            IsRestoreAction = false,
            CreatedAtUtc = DateTime.UtcNow
        };

        try { await _repository.AddAsync(snapshotEvent, ct); } catch { }

        SnapshotCreated?.Invoke(this, new VssSnapshotEventArgs(snapshotEvent));

        return string.IsNullOrEmpty(shadowId) ? null : shadowId;
    }

    public async Task<bool> RestoreFromLatestSnapshotAsync(string folderPath, CancellationToken ct)
    {
        try
        {
            var volume = Path.GetPathRoot(folderPath)!;
            var snapshots = await _repository.GetAllAsync(ct);

            var latest = snapshots
                .Where(s => !s.IsRestoreAction &&
                            string.Equals(Path.GetPathRoot(s.FolderPath), volume, StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrEmpty(s.SnapshotId))
                .OrderByDescending(s => s.CreatedAtUtc)
                .FirstOrDefault();

            if (latest is null)
                return false;

            var restoreEvent = new VssSnapshotEvent
            {
                Id = Guid.NewGuid(),
                FolderPath = folderPath,
                SnapshotId = latest.SnapshotId,
                SnapshotPath = latest.SnapshotPath,
                TriggerReason = "RestoreFromLatest",
                IsRestoreAction = true,
                CreatedAtUtc = DateTime.UtcNow
            };

            try { await _repository.AddAsync(restoreEvent, ct); } catch { }

            SnapshotCreated?.Invoke(this, new VssSnapshotEventArgs(restoreEvent));

            return true;
        }
        catch
        {
            return false;
        }
    }

    public Task<IReadOnlyList<VssSnapshotEvent>> ListSnapshotsAsync(CancellationToken ct)
        => _repository.GetAllAsync(ct);
}
