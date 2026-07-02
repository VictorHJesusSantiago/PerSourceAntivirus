namespace PerSourceAntivirus.Application.Common.Interfaces;

// Verifies UEFI Secure Boot state and the integrity/Authenticode signature of the Windows
// bootloader (bootmgfw.efi), complementing the existing MBR-focused protection.
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
