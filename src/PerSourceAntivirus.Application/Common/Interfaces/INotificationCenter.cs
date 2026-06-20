using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INotificationCenter
{
    Task AddNotificationAsync(NotificationRecord record, CancellationToken ct = default);
    Task AcknowledgeAsync(Guid id, CancellationToken ct = default);
    Task ResolveAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<NotificationRecord>> GetRecentAsync(int count = 50, CancellationToken ct = default);
    Task<int> GetUnreadCountAsync(CancellationToken ct = default);
    event EventHandler<NotificationRecord> NotificationAdded;
}
