using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Common;

namespace PerSourceAntivirus.Infrastructure.Tests.Common;

public class ShannonEntropyTests
{
    [Fact]
    public void Calculate_ReturnsZero_ForEmptyArray()
    {
        ShannonEntropy.Calculate([]).Should().Be(0);
    }

    [Fact]
    public void Calculate_ReturnsZero_ForSingleByteValue()
    {
        var data = new byte[256];
        ShannonEntropy.Calculate(data).Should().Be(0);
    }

    [Fact]
    public void Calculate_ReturnsMaxEntropy_ForUniformDistribution()
    {
        var data = new byte[256];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = (byte)i;
        }

        ShannonEntropy.Calculate(data).Should().BeApproximately(8.0, 0.0001);
    }
}
