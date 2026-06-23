using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.ThreatIntel;

public sealed class CustomIocService(ICustomIocRepository repo) : ICustomIocService
{
    public Task<IReadOnlyList<CustomIoc>> GetAllAsync(CancellationToken ct = default)
        => repo.GetAllAsync(ct);

    public async Task AddAsync(CustomIoc ioc, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ioc.Value))
            throw new ArgumentException("IOC value must not be empty.", nameof(ioc));
        if (string.IsNullOrWhiteSpace(ioc.IocType))
            throw new ArgumentException("IOC type must not be empty.", nameof(ioc));

        ioc.Id           = ioc.Id == Guid.Empty ? Guid.NewGuid() : ioc.Id;
        ioc.IsActive     = true;
        ioc.CreatedAtUtc = DateTime.UtcNow;

        await repo.AddAsync(ioc, ct);
    }

    public Task RemoveAsync(Guid id, CancellationToken ct = default)
        => repo.RemoveAsync(id, ct);

    public async Task<bool> IsKnownMaliciousAsync(string value, string iocType, CancellationToken ct = default)
    {
        var iocs = await repo.GetByTypeAsync(iocType, ct);
        return iocs.Any(i => string.Equals(i.Value, value, StringComparison.OrdinalIgnoreCase));
    }
}
