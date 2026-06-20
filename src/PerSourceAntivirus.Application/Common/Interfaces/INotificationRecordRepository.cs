using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INotificationRecordRepository
{
    Task AddAsync(NotificationRecord record, CancellationToken ct);
    Task UpdateAsync(NotificationRecord record, CancellationToken ct);
    Task<IReadOnlyList<NotificationRecord>> GetRecentAsync(int count, CancellationToken ct);
    Task<int> GetUnreadCountAsync(CancellationToken ct);
    Task<IReadOnlyList<NotificationRecord>> GetAllAsync(CancellationToken ct);
}
