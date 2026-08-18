using FluentAssertions;
using PerSourceAntivirus.Domain.Alerts;

namespace PerSourceAntivirus.Domain.Tests.Alerts;

public class AlertSeverityTests
{
    [Theory]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(10)]
    public void IsCritical_IsTrue_AtAndAboveTheThreshold(int severity)
    {
        AlertSeverity.IsCritical(severity).Should().BeTrue();
    }

    [Theory]
    [InlineData(7)]
    [InlineData(5)]
    [InlineData(1)]
    public void IsCritical_IsFalse_BelowTheThreshold(int severity)
    {
        AlertSeverity.IsCritical(severity).Should().BeFalse();
    }

    [Fact]
    public void NamedLevels_SitInsideTheDocumentedRange()
    {
        foreach (var level in new[] { AlertSeverity.Low, AlertSeverity.Medium, AlertSeverity.High, AlertSeverity.CriticalThreshold })
            AlertSeverity.IsInRange(level).Should().BeTrue();
    }

    [Fact]
    public void NamedLevels_AreOrdered()
    {
        AlertSeverity.Low.Should().BeLessThan(AlertSeverity.Medium);
        AlertSeverity.Medium.Should().BeLessThan(AlertSeverity.High);
        AlertSeverity.High.Should().BeLessThan(AlertSeverity.CriticalThreshold);
        AlertSeverity.CriticalThreshold.Should().BeLessThanOrEqualTo(AlertSeverity.Maximum);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(10, true)]
    [InlineData(11, false)]
    [InlineData(-1, false)]
    public void IsInRange_BoundsAreInclusive(int severity, bool expected)
    {
        AlertSeverity.IsInRange(severity).Should().Be(expected);
    }

    [Theory]
    [InlineData(-5, 1)]
    [InlineData(0, 1)]
    [InlineData(5, 5)]
    [InlineData(99, 10)]
    public void Clamp_KeepsExternallySuppliedValuesInRange(int input, int expected)
    {
        AlertSeverity.Clamp(input).Should().Be(expected);
    }

    [Theory]
    [InlineData(10, "CRITICAL")]
    [InlineData(8, "CRITICAL")]
    [InlineData(7, "HIGH")]
    [InlineData(5, "HIGH")]
    [InlineData(4, "LOW")]
    [InlineData(1, "LOW")]
    public void ToLabel_MatchesTheThresholds(int severity, string expected)
    {
        AlertSeverity.ToLabel(severity).Should().Be(expected);
    }
}
