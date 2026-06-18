namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface INdisInspectionService
{
    bool IsDriverLoaded { get; }
    Task<bool> CheckDriverStatusAsync(CancellationToken ct = default);
    string DriverServiceName { get; }
}
