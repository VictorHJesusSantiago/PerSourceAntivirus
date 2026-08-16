using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace PerSourceAntivirus.Infrastructure.Persistence;

[SupportedOSPlatform("windows")]
public static class DatabaseEncryptionKeyProvider
{
    public static string GetOrCreatePassphrase(string keyFilePath)
    {
        var dir = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        if (File.Exists(keyFilePath))
        {
            try
            {
                var protectedBytes = File.ReadAllBytes(keyFilePath);
                var unprotectedBytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
                return Convert.ToHexStringLower(unprotectedBytes);
            }
            catch
            {
            }
        }

        var keyBytes = RandomNumberGenerator.GetBytes(32);
        var protectedForDisk = ProtectedData.Protect(keyBytes, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(keyFilePath, protectedForDisk);
        return Convert.ToHexStringLower(keyBytes);
    }
}
