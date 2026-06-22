using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Notifications;

public sealed class NotificationCenter(IServiceScopeFactory scopeFactory) : INotificationCenter
{
    public event EventHandler<NotificationRecord>? NotificationAdded;

    public async Task AddNotificationAsync(NotificationRecord record, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<INotificationRecordRepository>();
        await repo.AddAsync(record, ct);
        NotificationAdded?.Invoke(this, record);
    }

    public async Task AcknowledgeAsync(Guid id, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<INotificationRecordRepository>();
        var records = await repo.GetAllAsync(ct);
        var record = records.FirstOrDefault(r => r.Id == id);
        if (record is null) return;
        record.Status = "Acknowledged";
        record.AcknowledgedAtUtc = DateTime.UtcNow;
        await repo.UpdateAsync(record, ct);
    }

    public async Task ResolveAsync(Guid id, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<INotificationRecordRepository>();
        var records = await repo.GetAllAsync(ct);
        var record = records.FirstOrDefault(r => r.Id == id);
        if (record is null) return;
        record.Status = "Resolved";
        await repo.UpdateAsync(record, ct);
    }

    public async Task<IReadOnlyList<NotificationRecord>> GetRecentAsync(int count = 50, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<INotificationRecordRepository>();
        return await repo.GetRecentAsync(count, ct);
    }

    public async Task<int> GetUnreadCountAsync(CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<INotificationRecordRepository>();
        return await repo.GetUnreadCountAsync(ct);
    }
}
