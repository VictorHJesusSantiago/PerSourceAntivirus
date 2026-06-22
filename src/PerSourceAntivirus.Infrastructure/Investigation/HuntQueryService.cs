using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Investigation;

public sealed class HuntQueryService(AppDbContext db) : IHuntQueryService
{
    public async Task<HuntQueryResults> QueryAsync(HuntQueryFilters filters, CancellationToken ct = default)
    {
        var processQuery = db.Set<ProcessCreationEvent>().AsQueryable();
        var fileQuery    = db.Set<FileActivityEvent>().AsQueryable();
        var registryQuery = db.Set<RegistryActivityEvent>().AsQueryable();
        var networkQuery = db.Set<NetworkConnectionEvent>().AsQueryable();

        if (filters.ProcessId.HasValue)
        {
            processQuery  = processQuery.Where(e => e.ProcessId == filters.ProcessId.Value);
            fileQuery     = fileQuery.Where(e => e.ProcessId == filters.ProcessId.Value);
            registryQuery = registryQuery.Where(e => e.ProcessId == filters.ProcessId.Value);
        }

        if (!string.IsNullOrEmpty(filters.ProcessName))
        {
            processQuery  = processQuery.Where(e => e.FileName.Contains(filters.ProcessName));
            fileQuery     = fileQuery.Where(e => e.ProcessName.Contains(filters.ProcessName));
            registryQuery = registryQuery.Where(e => e.ProcessName.Contains(filters.ProcessName));
        }

        if (!string.IsNullOrEmpty(filters.FilePath))
        {
            fileQuery = fileQuery.Where(e => e.FilePath.Contains(filters.FilePath));
        }

        if (!string.IsNullOrEmpty(filters.RegistryKey))
        {
            registryQuery = registryQuery.Where(e => e.KeyPath.Contains(filters.RegistryKey));
        }

        if (!string.IsNullOrEmpty(filters.IpAddress))
        {
            networkQuery = networkQuery.Where(e =>
                e.SourceAddress.Contains(filters.IpAddress) ||
                e.DestinationAddress.Contains(filters.IpAddress));
        }

        if (filters.Port.HasValue)
        {
            networkQuery = networkQuery.Where(e =>
                e.SourcePort == filters.Port.Value ||
                e.DestinationPort == filters.Port.Value);
        }

        if (!string.IsNullOrEmpty(filters.Hash))
        {
            processQuery = processQuery.Where(e => e.Sha256Hash == filters.Hash);
            fileQuery    = fileQuery.Where(e => e.Sha256Hash == filters.Hash);
        }

        if (filters.From.HasValue)
        {
            processQuery  = processQuery.Where(e => e.CreatedAtUtc >= filters.From.Value);
            fileQuery     = fileQuery.Where(e => e.OccurredAtUtc >= filters.From.Value);
            registryQuery = registryQuery.Where(e => e.OccurredAtUtc >= filters.From.Value);
            networkQuery  = networkQuery.Where(e => e.CapturedAtUtc >= filters.From.Value);
        }

        if (filters.To.HasValue)
        {
            processQuery  = processQuery.Where(e => e.CreatedAtUtc <= filters.To.Value);
            fileQuery     = fileQuery.Where(e => e.OccurredAtUtc <= filters.To.Value);
            registryQuery = registryQuery.Where(e => e.OccurredAtUtc <= filters.To.Value);
            networkQuery  = networkQuery.Where(e => e.CapturedAtUtc <= filters.To.Value);
        }

        var maxPerType = Math.Max(1, filters.MaxResults / 4);

        var processes  = await processQuery.Take(maxPerType).ToListAsync(ct);
        var files      = await fileQuery.Take(maxPerType).ToListAsync(ct);
        var registry   = await registryQuery.Take(maxPerType).ToListAsync(ct);
        var network    = await networkQuery.Take(maxPerType).ToListAsync(ct);

        var total = processes.Count + files.Count + registry.Count + network.Count;

        return new HuntQueryResults(processes, files, registry, network, total);
    }
}
