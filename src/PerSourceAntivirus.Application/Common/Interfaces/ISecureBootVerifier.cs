namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ISecureBootVerifier
{
    Task<SecureBootCheckResult> VerifyAsync(CancellationToken ct = default);
}

public record SecureBootCheckResult(
    bool SecureBootEnabled,
    string BootloaderPath,
    bool BootloaderSigned,
    bool BootloaderTrusted,
    string BootloaderHashSha256,
    IReadOnlyList<string> Anomalies);
