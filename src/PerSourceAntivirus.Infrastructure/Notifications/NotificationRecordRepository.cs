using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.Notifications;

public sealed class NotificationRecordRepository(AppDbContext db) : INotificationRecordRepository
{
    public async Task AddAsync(NotificationRecord record, CancellationToken ct)
    {
        db.NotificationRecords.Add(record);
        await db.SaveChangesAsync(ct);
    }

    public async Task UpdateAsync(NotificationRecord record, CancellationToken ct)
    {
        db.NotificationRecords.Update(record);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<NotificationRecord>> GetRecentAsync(int count, CancellationToken ct)
        => await db.NotificationRecords
            .OrderByDescending(n => n.CreatedAtUtc)
            .Take(count)
            .ToListAsync(ct);

    public async Task<int> GetUnreadCountAsync(CancellationToken ct)
        => await db.NotificationRecords
            .CountAsync(n => n.Status == "New", ct);

    public async Task<IReadOnlyList<NotificationRecord>> GetAllAsync(CancellationToken ct)
        => await db.NotificationRecords
            .OrderByDescending(n => n.CreatedAtUtc)
            .ToListAsync(ct);
}
