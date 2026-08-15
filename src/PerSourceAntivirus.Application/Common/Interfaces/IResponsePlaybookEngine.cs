namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IResponsePlaybookEngine
{
    Task EvaluateAsync(PlaybookTriggerContext context, CancellationToken ct = default);
}

public record PlaybookTriggerContext(
    string AlertType,
    int Severity,
    int? ProcessId = null,
    string? FilePath = null);
