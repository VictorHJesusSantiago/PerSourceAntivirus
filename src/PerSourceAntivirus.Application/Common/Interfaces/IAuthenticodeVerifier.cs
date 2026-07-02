namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IAuthenticodeVerifier
{
    Task<AuthenticodeResult> VerifyAsync(string filePath, CancellationToken ct = default);
}

public record AuthenticodeResult(bool IsSigned, bool IsTrusted, string? SignerSubject, string? Thumbprint);
