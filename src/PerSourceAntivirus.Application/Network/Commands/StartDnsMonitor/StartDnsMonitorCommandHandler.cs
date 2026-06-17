using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Network.Commands.StartDnsMonitor;

public class StartDnsMonitorCommandHandler(IDnsMonitor dnsMonitor, IDnsEventRepository repository)
    : IRequestHandler<StartDnsMonitorCommand, StartDnsMonitorResult>
{
    public async Task<StartDnsMonitorResult> Handle(StartDnsMonitorCommand request, CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(request.DurationSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        var events = new List<DnsQueryEvent>();

        try
        {
            await foreach (var query in dnsMonitor.WatchAsync(request.DeviceName, linkedCts.Token))
            {
                events.Add(new DnsQueryEvent
                {
                    Id = Guid.NewGuid(),
                    CapturedAtUtc = DateTime.UtcNow,
                    QueryName = query.QueryName,
                    QueryType = query.QueryType,
                    SourceAddress = query.SourceAddress,
                    IsSuspicious = query.IsSuspicious,
                    SuspicionReason = query.SuspicionReason
                });
            }
        }
        catch (OperationCanceledException) { }

        if (events.Count > 0)
        {
            await repository.AddRangeAsync(events, cancellationToken);
        }

        return new StartDnsMonitorResult(events.Count, events.Count(e => e.IsSuspicious), DateTime.UtcNow - startedAt);
    }
}
