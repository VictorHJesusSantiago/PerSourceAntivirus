using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IMitreAttackService
{
    MitreAttackMapping? GetMapping(string alertType);
    IReadOnlyList<MitreAttackMapping> GetAllMappings();
    string GetMitreUrl(string techniqueId);
}
