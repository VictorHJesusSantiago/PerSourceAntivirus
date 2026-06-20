namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IPowerShellClmEnforcer
{
    bool IsClmEnabled();
    bool EnableClm();
    bool DisableClm();
}
