using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Investigation;

public sealed class AlertTriageService : IAlertTriageService
{
    private static readonly HashSet<string> SystemWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer",
        "svchost",
        "lsass",
        "csrss",
        "wininit",
        "winlogon",
        "services",
        "smss",
        "spoolsv",
        "taskhostw",
        "dwm",
        "sihost",
        "ctfmon",
        "runtimebroker",
    };

    private readonly IAlertTriageRepository _triageRepo;
    private readonly IIncidentRepository    _incidentRepo;

    public AlertTriageService(IAlertTriageRepository triageRepo, IIncidentRepository incidentRepo)
    {
        _triageRepo   = triageRepo;
        _incidentRepo = incidentRepo;
    }

    public int ComputeSeverityScore(string alertType, string processName, DateTime detectedAt, int baseScore)
    {
        var score = baseScore;

        if (alertType.Contains("Ransomware", StringComparison.OrdinalIgnoreCase) ||
            alertType.Contains("Mbr",        StringComparison.OrdinalIgnoreCase))
        {
            score += 2;
        }

        if (alertType.Contains("Injection", StringComparison.OrdinalIgnoreCase) ||
            alertType.Contains("Hollowing", StringComparison.OrdinalIgnoreCase))
        {
            score += 1;
        }

        var hour = detectedAt.ToLocalTime().Hour;
        if (hour < 8 || hour >= 18)
            score += 1;

        var procName = Path.GetFileNameWithoutExtension(processName);
        if (SystemWhitelist.Contains(procName))
            score -= 1;

        return Math.Clamp(score, 1, 10);
    }

    public async Task<AlertTriage> CreateTriageAsync(string alertType, Guid alertId, int autoScore, CancellationToken ct = default)
    {
        var triage = new AlertTriage
        {
            Id               = Guid.NewGuid(),
            AlertType        = alertType,
            AlertId          = alertId,
            Status           = "Open",
            AutoSeverityScore = autoScore,
            Notes            = string.Empty,
            TriagedBy        = string.Empty,
            IncidentId       = null,
            CreatedAtUtc     = DateTime.UtcNow,
            TriagedAtUtc     = null,
        };

        await _triageRepo.AddAsync(triage, ct);
        return triage;
    }

    public async Task UpdateStatusAsync(Guid triageId, string status, string notes, CancellationToken ct = default)
    {
        var all = await _triageRepo.GetAllAsync(ct);
        var triage = all.FirstOrDefault(t => t.Id == triageId);
        if (triage == null)
            return;

        triage.Status      = status;
        triage.Notes       = notes;
        triage.TriagedAtUtc = DateTime.UtcNow;

        await _triageRepo.UpdateAsync(triage, ct);
    }

    public async Task<Incident> CreateIncidentAsync(string title, string description, int severity, CancellationToken ct = default)
    {
        var incident = new Incident
        {
            Id           = Guid.NewGuid(),
            Title        = title,
            Description  = description,
            Severity     = severity,
            Status       = "Open",
            AlertCount   = 0,
            CreatedAtUtc = DateTime.UtcNow,
            ResolvedAtUtc = null,
        };

        await _incidentRepo.AddAsync(incident, ct);
        return incident;
    }

    public async Task AssignToIncidentAsync(Guid triageId, Guid incidentId, CancellationToken ct = default)
    {
        var all = await _triageRepo.GetAllAsync(ct);
        var triage = all.FirstOrDefault(t => t.Id == triageId);
        if (triage == null)
            return;

        triage.IncidentId = incidentId;
        await _triageRepo.UpdateAsync(triage, ct);

        var incidents = await _incidentRepo.GetAllAsync(ct);
        var incident  = incidents.FirstOrDefault(i => i.Id == incidentId);
        if (incident != null)
        {
            incident.AlertCount += 1;
            await _incidentRepo.UpdateAsync(incident, ct);
        }
    }

    public async Task<IReadOnlyList<AlertTriage>> GetOpenTriagesAsync(CancellationToken ct = default)
    {
        var open         = await _triageRepo.GetByStatusAsync("Open",          ct);
        var investigating = await _triageRepo.GetByStatusAsync("Investigating", ct);
        return open.Concat(investigating).OrderByDescending(t => t.CreatedAtUtc).ToList();
    }

    public Task<IReadOnlyList<Incident>> GetActiveIncidentsAsync(CancellationToken ct = default)
        => _incidentRepo.GetActiveAsync(ct);
}
