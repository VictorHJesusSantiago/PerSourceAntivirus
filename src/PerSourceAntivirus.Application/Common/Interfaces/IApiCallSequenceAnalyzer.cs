using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public record ApiCallSequenceAlertEventArgs(ApiCallSequenceAlert Alert);

public interface IApiCallSequenceAnalyzer
{
    Task StartMonitoringAsync(CancellationToken ct);
    void StopMonitoring();
    event EventHandler<ApiCallSequenceAlertEventArgs> AlertDetected;
}
