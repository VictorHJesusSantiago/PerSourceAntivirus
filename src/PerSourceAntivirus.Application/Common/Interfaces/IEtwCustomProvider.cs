namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IEtwCustomProvider
{
    void WriteEvent(string eventName, string payload);
    void WriteThreatEvent(string alertType, int severity, string details);
    Guid ProviderId { get; }
    string ProviderName { get; }
}
