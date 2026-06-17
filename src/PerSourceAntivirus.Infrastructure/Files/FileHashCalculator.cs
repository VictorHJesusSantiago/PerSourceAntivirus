using System.Security.Cryptography;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Infrastructure.Common;

namespace PerSourceAntivirus.Infrastructure.Files;

public class FileHashCalculator : IFileHashCalculator
{
    private const int BufferSize = 81920;

    public async Task<FileHashResult> ComputeAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var byteCounts = new long[256];
        long totalBytes = 0;

        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, useAsync: true);
        using var sha256 = SHA256.Create();

        var buffer = new byte[BufferSize];
        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(buffer, cancellationToken)) > 0)
        {
            sha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);

            for (var i = 0; i < bytesRead; i++)
            {
                byteCounts[buffer[i]]++;
            }

            totalBytes += bytesRead;
        }

        sha256.TransformFinalBlock([], 0, 0);
        var hash = Convert.ToHexString(sha256.Hash!).ToLowerInvariant();
        var entropy = ShannonEntropy.Calculate(byteCounts, totalBytes);

        return new FileHashResult(hash, entropy, totalBytes);
    }
}
