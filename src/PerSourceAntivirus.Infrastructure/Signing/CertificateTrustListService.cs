using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Signing;

// Facade over ICertificateTrustEntryRepository — creates its own scope per call so it is
// safe to inject into singleton detectors (AppDbContext is not thread-safe).
public sealed class CertificateTrustListService(IServiceScopeFactory scopeFactory) : ICertificateTrustListService
{
    public async Task<CertificateTrustEntry?> FindByThumbprintAsync(string thumbprint, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ICertificateTrustEntryRepository>();
        return await repository.FindByThumbprintAsync(thumbprint, ct).ConfigureAwait(false);
    }

    public async Task AddOrUpdateAsync(string thumbprint, string subjectName, string trustLevel, string? note, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ICertificateTrustEntryRepository>();
        await repository.AddOrUpdateAsync(new CertificateTrustEntry
        {
            Id = Guid.NewGuid(),
            Thumbprint = thumbprint,
            SubjectName = subjectName,
            TrustLevel = trustLevel,
            Note = note,
            AddedAtUtc = DateTime.UtcNow
        }, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<CertificateTrustEntry>> GetAllAsync(CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ICertificateTrustEntryRepository>();
        return await repository.GetAllAsync(ct).ConfigureAwait(false);
    }
}
