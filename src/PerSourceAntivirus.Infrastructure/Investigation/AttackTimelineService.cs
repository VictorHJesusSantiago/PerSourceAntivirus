using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Investigation;

public sealed class AttackTimelineService : IAttackTimelineService
{
    private readonly IProcessCreationEventRepository  _processRepo;
    private readonly IFileActivityEventRepository     _fileRepo;
    private readonly IRegistryActivityEventRepository _registryRepo;
    private readonly AppDbContext                     _db;

    public AttackTimelineService(
        IProcessCreationEventRepository processRepo,
        IFileActivityEventRepository fileRepo,
        IRegistryActivityEventRepository registryRepo,
        AppDbContext db)
    {
        _processRepo  = processRepo;
        _fileRepo     = fileRepo;
        _registryRepo = registryRepo;
        _db           = db;
    }

    public async Task<AttackTimeline> GetTimelineAsync(int processId, DateTime? from, DateTime? to, CancellationToken ct = default)
    {
        var effectiveFrom = from ?? DateTime.UtcNow.AddHours(-24);
        var effectiveTo   = to   ?? DateTime.UtcNow;

        var childProcesses = await _db.Set<ProcessCreationEvent>()
            .Where(e => e.ParentProcessId == processId && e.CreatedAtUtc >= effectiveFrom && e.CreatedAtUtc <= effectiveTo)
            .OrderBy(e => e.CreatedAtUtc)
            .ToListAsync(ct);

        var ownProcess = await _db.Set<ProcessCreationEvent>()
            .Where(e => e.ProcessId == processId)
            .OrderByDescending(e => e.CreatedAtUtc)
            .FirstOrDefaultAsync(ct);

        var processName = ownProcess?.FileName ?? string.Empty;
        var imagePath   = ownProcess?.ImagePath ?? string.Empty;

        var fileActivities = await _db.Set<FileActivityEvent>()
            .Where(e => e.ProcessId == processId && e.OccurredAtUtc >= effectiveFrom && e.OccurredAtUtc <= effectiveTo)
            .OrderBy(e => e.OccurredAtUtc)
            .ToListAsync(ct);

        var networkConnections = await _db.Set<NetworkConnectionEvent>()
            .Where(e => e.CapturedAtUtc >= effectiveFrom && e.CapturedAtUtc <= effectiveTo)
            .OrderBy(e => e.CapturedAtUtc)
            .ToListAsync(ct);

        var registryActivities = await _db.Set<RegistryActivityEvent>()
            .Where(e => e.ProcessId == processId && e.OccurredAtUtc >= effectiveFrom && e.OccurredAtUtc <= effectiveTo)
            .OrderBy(e => e.OccurredAtUtc)
            .ToListAsync(ct);

        return new AttackTimeline(
            processId,
            processName,
            imagePath,
            childProcesses,
            fileActivities,
            networkConnections,
            registryActivities,
            effectiveFrom,
            effectiveTo);
    }

    public Task<AttackTimeline> GetTimelineByAlertIdAsync(Guid alertId, string alertType, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        return Task.FromResult(new AttackTimeline(
            0,
            alertType,
            string.Empty,
            Array.Empty<ProcessCreationEvent>(),
            Array.Empty<FileActivityEvent>(),
            Array.Empty<NetworkConnectionEvent>(),
            Array.Empty<RegistryActivityEvent>(),
            now.AddHours(-1),
            now));
    }
}
