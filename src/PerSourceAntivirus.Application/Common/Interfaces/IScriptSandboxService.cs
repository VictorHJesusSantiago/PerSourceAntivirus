using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IScriptSandboxService
{
    Task<ScriptSandboxResult> AnalyzeAsync(string scriptContent, string scriptType, CancellationToken ct = default);
}
