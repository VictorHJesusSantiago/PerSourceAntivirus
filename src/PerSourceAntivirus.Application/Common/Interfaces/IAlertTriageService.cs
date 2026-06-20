using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAlertTriageService
{
    Task<AlertTriage> CreateTriageAsync(string alertType, Guid alertId, int autoScore, CancellationToken ct = default);
    Task UpdateStatusAsync(Guid triageId, string status, string notes, CancellationToken ct = default);
    Task<Incident> CreateIncidentAsync(string title, string description, int severity, CancellationToken ct = default);
    Task AssignToIncidentAsync(Guid triageId, Guid incidentId, CancellationToken ct = default);
    Task<IReadOnlyList<AlertTriage>> GetOpenTriagesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<Incident>> GetActiveIncidentsAsync(CancellationToken ct = default);
    int ComputeSeverityScore(string alertType, string processName, DateTime detectedAt, int baseScore);
}
