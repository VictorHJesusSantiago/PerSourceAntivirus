using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Reputation;

namespace PerSourceAntivirus.Infrastructure.Tests.Reputation;

public class LocalHashReputationServiceTests
{
    [Fact]
    public async Task CheckAsync_ReturnsMalicious_WhenHashIsInBlocklist()
    {
        var file = Path.GetTempFileName();
        try
        {
            const string hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
            await File.WriteAllTextAsync(file, hash);

            var service = new LocalHashReputationService(file);
            var result = await service.CheckAsync(hash);

            result.Should().NotBeNull();
            result!.IsMalicious.Should().BeTrue();
            result.Source.Should().Be("LocalList");
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task CheckAsync_ReturnsNull_WhenHashIsNotInBlocklist()
    {
        var file = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(file, "# empty");
            var service = new LocalHashReputationService(file);
            var result = await service.CheckAsync("unknownhash");
            result.Should().BeNull();
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task CheckAsync_ReturnsNull_WhenFileDoesNotExist()
    {
        var service = new LocalHashReputationService(Path.Combine(Path.GetTempPath(), "nonexistent_hashes.txt"));
        var result = await service.CheckAsync("anyhash");
        result.Should().BeNull();
    }

    [Fact]
    public async Task CheckAsync_IsCaseInsensitive()
    {
        var file = Path.GetTempFileName();
        try
        {
            const string hash = "AABBCCDD";
            await File.WriteAllTextAsync(file, hash);
            var service = new LocalHashReputationService(file);
            var result = await service.CheckAsync("aabbccdd");
            result.Should().NotBeNull();
        }
        finally { File.Delete(file); }
    }
}
