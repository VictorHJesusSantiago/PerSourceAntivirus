namespace PerSourceAntivirus.Application.Network.Commands.StartDnsMonitor;

public record StartDnsMonitorResult(int QueriesCaptured, int SuspiciousCount, TimeSpan Duration);
