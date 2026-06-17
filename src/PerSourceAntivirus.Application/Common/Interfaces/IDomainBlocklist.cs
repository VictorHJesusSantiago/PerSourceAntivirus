namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IDomainBlocklist
{
    bool IsSuspiciousDomain(string domain, out string? reason);
}
