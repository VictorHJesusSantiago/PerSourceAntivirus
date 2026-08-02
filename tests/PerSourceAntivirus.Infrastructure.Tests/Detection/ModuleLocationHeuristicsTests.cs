using FluentAssertions;
using PerSourceAntivirus.Infrastructure.Detection.Heuristics;

namespace PerSourceAntivirus.Infrastructure.Tests.Detection;

public class ModuleLocationHeuristicsTests
{
    private static readonly string[] TrustedDirectories =
    [
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\WinSxS"
    ];

    [Theory]
    [InlineData("kernel32.dll")]
    [InlineData("KERNEL32.DLL")]
    [InlineData("ntdll.dll")]
    [InlineData("version.dll")]   // classic sideloading target
    public void IsKnownSystemDll_MatchesCaseInsensitively(string name)
    {
        ModuleLocationHeuristics.IsKnownSystemDll(name).Should().BeTrue();
    }

    [Theory]
    [InlineData("mycompany.dll")]
    [InlineData("")]
    public void IsKnownSystemDll_IsFalse_ForNonSystemNames(string name)
    {
        ModuleLocationHeuristics.IsKnownSystemDll(name).Should().BeFalse();
    }

    [Fact]
    public void IsSearchOrderHijack_Flags_SystemDllLoadedFromApplicationDirectory()
    {
        // The actual attack: a version.dll dropped next to a legitimate executable, which Windows
        // loads in preference to the System32 copy.
        ModuleLocationHeuristics.IsSearchOrderHijack(
            "version.dll", @"C:\Program Files\SomeApp", TrustedDirectories)
            .Should().BeTrue();
    }

    [Fact]
    public void IsSearchOrderHijack_DoesNotFlag_SystemDllFromSystem32()
    {
        ModuleLocationHeuristics.IsSearchOrderHijack(
            "kernel32.dll", @"C:\Windows\System32", TrustedDirectories)
            .Should().BeFalse();
    }

    [Fact]
    public void IsSearchOrderHijack_DoesNotFlag_SystemDllFromWinSxs()
    {
        ModuleLocationHeuristics.IsSearchOrderHijack(
            "comctl32.dll", @"C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_xyz",
            TrustedDirectories)
            .Should().BeFalse();
    }

    [Fact]
    public void IsSearchOrderHijack_DoesNotFlag_ApplicationDllOutsideSystem32()
    {
        // Only system DLL *names* matter — an app's own DLL living in its own folder is normal.
        ModuleLocationHeuristics.IsSearchOrderHijack(
            "myapp.dll", @"C:\Program Files\SomeApp", TrustedDirectories)
            .Should().BeFalse();
    }

    [Fact]
    public void IsTrustedSystemDirectory_IsCaseInsensitive()
    {
        ModuleLocationHeuristics.IsTrustedSystemDirectory(@"c:\windows\system32", TrustedDirectories)
            .Should().BeTrue();
    }

    [Fact]
    public void IsTrustedSystemDirectory_IsFalse_ForEmptyPath()
    {
        ModuleLocationHeuristics.IsTrustedSystemDirectory("", TrustedDirectories).Should().BeFalse();
    }

    [Fact]
    public void IsSuspiciousExecutableLocation_Flags_TempAndAppData()
    {
        string[] suspicious = [@"C:\Users\me\AppData\Local\Temp", @"C:\Users\me\Downloads"];

        ModuleLocationHeuristics.IsSuspiciousExecutableLocation(
            @"C:\Users\me\AppData\Local\Temp\dropper.exe", suspicious).Should().BeTrue();
        ModuleLocationHeuristics.IsSuspiciousExecutableLocation(
            @"C:\Users\me\Downloads\installer.exe", suspicious).Should().BeTrue();
    }

    [Fact]
    public void IsSuspiciousExecutableLocation_DoesNotFlag_ProgramFiles()
    {
        // Unsigned software under Program Files is common and must not generate noise.
        string[] suspicious = [@"C:\Users\me\AppData\Local\Temp"];

        ModuleLocationHeuristics.IsSuspiciousExecutableLocation(
            @"C:\Program Files\SomeApp\app.exe", suspicious).Should().BeFalse();
    }

    [Fact]
    public void IsSuspiciousExecutableLocation_IsFalse_ForEmptyPathOrNoDirectories()
    {
        ModuleLocationHeuristics.IsSuspiciousExecutableLocation("", [@"C:\Temp"]).Should().BeFalse();
        ModuleLocationHeuristics.IsSuspiciousExecutableLocation(@"C:\Temp\x.exe", []).Should().BeFalse();
    }
}
