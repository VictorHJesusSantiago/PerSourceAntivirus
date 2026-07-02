using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IProcessFirewallRuleRepository
{
    Task AddAsync(ProcessFirewallRule rule, CancellationToken ct = default);
    Task RemoveAsync(string processPath, CancellationToken ct = default);
    Task<IReadOnlyList<ProcessFirewallRule>> GetAllAsync(CancellationToken ct = default);
}
