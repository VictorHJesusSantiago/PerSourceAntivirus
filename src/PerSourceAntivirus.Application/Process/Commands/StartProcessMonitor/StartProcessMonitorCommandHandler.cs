using MediatR;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Process.Commands.StartProcessMonitor;

public class StartProcessMonitorCommandHandler(IProcessMonitor processMonitor, IProcessEventRepository repository)
    : IRequestHandler<StartProcessMonitorCommand, StartProcessMonitorResult>
{
    public async Task<StartProcessMonitorResult> Handle(StartProcessMonitorCommand request, CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(request.DurationSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        var events = new List<ProcessEvent>();

        try
        {
            await foreach (var ev in processMonitor.WatchAsync(linkedCts.Token))
            {
                events.Add(new ProcessEvent
                {
                    Id = Guid.NewGuid(),
                    DetectedAtUtc = DateTime.UtcNow,
                    ProcessId = ev.ProcessId,
                    ProcessName = ev.ProcessName,
                    ParentProcessId = ev.ParentProcessId,
                    ParentProcessName = ev.ParentProcessName,
                    CommandLine = ev.CommandLine,
                    IsSuspicious = ev.IsSuspicious,
                    SuspicionReason = ev.SuspicionReason
                });
            }
        }
        catch (OperationCanceledException) { }

        if (events.Count > 0)
        {
            await repository.AddRangeAsync(events, cancellationToken);
        }

        return new StartProcessMonitorResult(events.Count, events.Count(e => e.IsSuspicious), DateTime.UtcNow - startedAt);
    }
}
