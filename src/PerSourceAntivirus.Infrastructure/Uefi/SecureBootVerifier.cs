using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Win32;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Uefi;

[SupportedOSPlatform("windows")]
public sealed class SecureBootVerifier : ISecureBootVerifier
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IAuthenticodeVerifier _authenticodeVerifier;

    private static readonly string BootloaderPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Boot", "EFI", "bootmgfw.efi");

    public SecureBootVerifier(IServiceScopeFactory scopeFactory, IAuthenticodeVerifier authenticodeVerifier)
    {
        _scopeFactory = scopeFactory;
        _authenticodeVerifier = authenticodeVerifier;
    }

    public async Task<SecureBootCheckResult> VerifyAsync(CancellationToken ct = default)
    {
        var anomalies = new List<string>();

        bool secureBootEnabled = ReadSecureBootState();
        if (!secureBootEnabled) anomalies.Add("SecureBootDisabled");

        bool signed = false, trusted = false;
        string hash = string.Empty;

        if (File.Exists(BootloaderPath))
        {
            var verification = await _authenticodeVerifier.VerifyAsync(BootloaderPath, ct).ConfigureAwait(false);
            signed = verification.IsSigned;
            trusted = verification.IsTrusted;
            if (!signed) anomalies.Add("BootloaderUnsigned");
            else if (!trusted) anomalies.Add("BootloaderUntrusted");

            hash = Convert.ToHexStringLower(SHA256.HashData(await File.ReadAllBytesAsync(BootloaderPath, ct).ConfigureAwait(false)));
        }
        else
        {
            anomalies.Add("BootloaderFileNotFound");
        }

        SecureBootStatusSnapshot? previous;
        using (var scope = _scopeFactory.CreateScope())
        {
            var repository = scope.ServiceProvider.GetRequiredService<ISecureBootSnapshotRepository>();
            previous = await repository.GetLatestAsync(ct).ConfigureAwait(false);

            if (previous is not null && hash.Length > 0 &&
                !previous.BootloaderHashSha256.Equals(hash, StringComparison.OrdinalIgnoreCase))
            {
                anomalies.Add("BootloaderHashChangedSinceLastCheck");
            }

            var snapshot = new SecureBootStatusSnapshot
            {
                Id = Guid.NewGuid(),
                SecureBootEnabled = secureBootEnabled,
                BootloaderPath = BootloaderPath,
                BootloaderSigned = signed,
                BootloaderTrusted = trusted,
                BootloaderHashSha256 = hash,
                Anomalies = anomalies.Count > 0 ? string.Join(",", anomalies) : null,
                CheckedAtUtc = DateTime.UtcNow
            };

            try { await repository.AddAsync(snapshot, ct).ConfigureAwait(false); }
            catch { }
        }

        return new SecureBootCheckResult(secureBootEnabled, BootloaderPath, signed, trusted, hash, anomalies);
    }

    private static bool ReadSecureBootState()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            var value = key?.GetValue("UEFISecureBootEnabled");
            return value is int i && i == 1;
        }
        catch
        {
            return false;
        }
    }
}
