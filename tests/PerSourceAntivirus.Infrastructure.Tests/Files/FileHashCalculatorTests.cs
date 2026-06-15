using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Files;

namespace PerSourceAntivirus.Infrastructure.Tests.Files;

public class FileHashCalculatorTests
{
    [Fact]
    public async Task ComputeAsync_ReturnsKnownSha256Hash()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(filePath, "hello world");
            var calculator = new FileHashCalculator();

            var result = await calculator.ComputeAsync(filePath);

            result.Sha256Hash.Should().Be("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
            result.SizeBytes.Should().Be(11);
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public async Task ComputeAsync_ReturnsZeroEntropy_ForSingleByteValueFile()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(filePath, new byte[1024]);
            var calculator = new FileHashCalculator();

            var result = await calculator.ComputeAsync(filePath);

            result.Entropy.Should().Be(0);
        }
        finally
        {
            File.Delete(filePath);
        }
    }

    [Fact]
    public async Task ComputeAsync_ReturnsMaxEntropy_ForUniformlyDistributedBytes()
    {
        var filePath = Path.GetTempFileName();
        try
        {
            var bytes = new byte[256];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)i;
            }

            await File.WriteAllBytesAsync(filePath, bytes);
            var calculator = new FileHashCalculator();

            var result = await calculator.ComputeAsync(filePath);

            result.Entropy.Should().BeApproximately(8.0, 0.0001);
        }
        finally
        {
            File.Delete(filePath);
        }
    }
}
