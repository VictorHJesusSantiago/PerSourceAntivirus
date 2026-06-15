using System.Security.Cryptography;
using PerSourceAntivirus.Application.Common.Interfaces;

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
        var entropy = CalculateShannonEntropy(byteCounts, totalBytes);

        return new FileHashResult(hash, entropy, totalBytes);
    }

    private static double CalculateShannonEntropy(long[] byteCounts, long totalBytes)
    {
        if (totalBytes == 0)
        {
            return 0;
        }

        var entropy = 0.0;
        foreach (var count in byteCounts)
        {
            if (count == 0)
            {
                continue;
            }

            var probability = (double)count / totalBytes;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }
}
