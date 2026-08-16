using System.Management;
using Microsoft.Extensions.DependencyInjection;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Ransomware;

[SupportedOSPlatform("windows")]
public sealed class VssRollbackService : IVssRollbackService
{
    private readonly IServiceScopeFactory _scopeFactory;

    public event EventHandler<VssSnapshotEventArgs>? SnapshotCreated;

    public VssRollbackService(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    private async Task PersistAsync(VssSnapshotEvent snapshotEvent, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IVssSnapshotRepository>();
            await repository.AddAsync(snapshotEvent, ct).ConfigureAwait(false);
        }
        catch { }
    }

    private async Task<IReadOnlyList<VssSnapshotEvent>> LoadAllAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVssSnapshotRepository>();
        return await repository.GetAllAsync(ct).ConfigureAwait(false);
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

        await PersistAsync(snapshotEvent, ct).ConfigureAwait(false);

        SnapshotCreated?.Invoke(this, new VssSnapshotEventArgs(snapshotEvent));

        return string.IsNullOrEmpty(shadowId) ? null : shadowId;
    }

    public async Task<bool> RestoreFromLatestSnapshotAsync(string folderPath, CancellationToken ct)
    {
        try
        {
            var volume = Path.GetPathRoot(folderPath)!;
            var snapshots = await LoadAllAsync(ct).ConfigureAwait(false);

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

            await PersistAsync(restoreEvent, ct).ConfigureAwait(false);

            SnapshotCreated?.Invoke(this, new VssSnapshotEventArgs(restoreEvent));

            return true;
        }
        catch
        {
            return false;
        }
    }

    public Task<IReadOnlyList<VssSnapshotEvent>> ListSnapshotsAsync(CancellationToken ct) => LoadAllAsync(ct);
}
