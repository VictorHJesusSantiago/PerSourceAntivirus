namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IExclusionList
{
    bool IsExcludedFile(string filePath);
    bool IsWhitelistedHash(string sha256Hash);
}
