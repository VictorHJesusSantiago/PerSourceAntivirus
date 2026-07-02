namespace PerSourceAntivirus.Application.Common.Interfaces;

// Configurable "if detected X with severity >= N then: kill process + isolate network +
// quarantine + notify" rule engine. Detectors call EvaluateAsync with the context of an alert
// they just raised; matching enabled rules run their action list and are logged.
public interface IResponsePlaybookEngine
{
    Task EvaluateAsync(PlaybookTriggerContext context, CancellationToken ct = default);
}

public record PlaybookTriggerContext(
    string AlertType,
    int Severity,
    int? ProcessId = null,
    string? FilePath = null);
