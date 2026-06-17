namespace PerSourceAntivirus.Application.Process.Commands.StartProcessMonitor;

public record StartProcessMonitorResult(int EventsRecorded, int SuspiciousCount, TimeSpan Duration);
