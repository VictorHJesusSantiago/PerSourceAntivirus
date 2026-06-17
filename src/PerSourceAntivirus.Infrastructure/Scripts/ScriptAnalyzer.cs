using System.Management.Automation.Language;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Enums;

namespace PerSourceAntivirus.Infrastructure.Scripts;

public class ScriptAnalyzer : IScriptAnalyzer
{
    private static readonly HashSet<string> ScriptExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".ps1", ".vbs", ".bat", ".cmd", ".js" };

    public ScriptAnalysisData? Analyze(string filePath)
    {
        var extension = Path.GetExtension(filePath);
        if (!ScriptExtensions.Contains(extension)) return null;

        string content;
        try { content = File.ReadAllText(filePath); }
        catch { return null; }

        var scriptType = extension.ToLowerInvariant() switch
        {
            ".ps1"            => ScriptType.PowerShell,
            ".vbs"            => ScriptType.VBScript,
            ".bat" or ".cmd"  => ScriptType.Batch,
            ".js"             => ScriptType.JavaScript,
            _                 => ScriptType.Unknown
        };

        return scriptType == ScriptType.PowerShell
            ? AnalyzePowerShellAst(content)
            : AnalyzeByRegex(scriptType, content);
    }

    // ------------------------------------------------------------------ PowerShell AST

    private static ScriptAnalysisData AnalyzePowerShellAst(string content)
    {
        var patterns           = new List<string>();
        bool hasObfuscation    = false;
        bool hasNetworkAccess  = false;
        bool hasProcessExec    = false;
        bool hasFileSystem     = false;

        ScriptBlockAst ast;
        try
        {
            ast = Parser.ParseInput(content, out _, out _);
        }
        catch
        {
            // Parser failure: fall back to regex for this file.
            return AnalyzeByRegex(ScriptType.PowerShell, content);
        }

        // --- Pass 1: command names ---
        foreach (var cmd in ast.FindAll(a => a is CommandAst, true).OfType<CommandAst>())
        {
            var name = cmd.GetCommandName()?.ToLowerInvariant();
            switch (name)
            {
                case "iex":
                case "invoke-expression":
                    hasObfuscation = true;
                    AddPattern(patterns, "IEX/Invoke-Expression");
                    break;

                case "invoke-webrequest":
                case "invoke-restmethod":
                case "start-bitstransfer":
                case "wget":
                case "curl":
                    hasNetworkAccess = true;
                    AddPattern(patterns, $"Network access via {name}");
                    break;

                case "new-object":
                    // e.g. New-Object Net.WebClient
                    var firstArg = cmd.CommandElements.Count > 1
                        ? cmd.CommandElements[1].ToString().ToLowerInvariant()
                        : string.Empty;
                    if (firstArg.Contains("webclient") || firstArg.Contains("httpclient") ||
                        firstArg.Contains("net.http"))
                    {
                        hasNetworkAccess = true;
                        AddPattern(patterns, "Network access via New-Object WebClient");
                    }
                    break;

                case "start-process":
                case "invoke-item":
                    hasProcessExec = true;
                    AddPattern(patterns, $"Process execution via {name}");
                    break;

                case "get-content":
                case "set-content":
                case "out-file":
                case "add-content":
                case "copy-item":
                case "move-item":
                case "remove-item":
                    hasFileSystem = true;
                    AddPattern(patterns, "File system access");
                    break;
            }

            // Check ALL command parameters regardless of command name
            foreach (var element in cmd.CommandElements)
            {
                if (element is not CommandParameterAst param) continue;
                var pname = param.ParameterName.ToLowerInvariant();
                switch (pname)
                {
                    case "encodedcommand":
                    case "enc":
                    case "en":
                    case "e":
                        hasObfuscation = true;
                        AddPattern(patterns, "EncodedCommand argument");
                        break;
                    case "executionpolicy":
                    case "ep":
                        AddPattern(patterns, "Bypass execution policy");
                        break;
                    case "windowstyle":
                    case "w":
                        AddPattern(patterns, "Hidden window style");
                        break;
                    case "noprofile":
                    case "nop":
                        AddPattern(patterns, "NoProfile flag");
                        break;
                }
            }
        }

        // --- Pass 2: member expressions (.DownloadString, ::FromBase64String, etc.) ---
        foreach (var member in ast.FindAll(a => a is MemberExpressionAst, true).OfType<MemberExpressionAst>())
        {
            var mname = member.Member.ToString().ToLowerInvariant();
            switch (mname)
            {
                case "frombase64string":
                    hasObfuscation = true;
                    AddPattern(patterns, "Base64 decode via [Convert]::FromBase64String");
                    break;
                case "downloadstring":
                case "downloadfile":
                case "downloaddata":
                case "getstringasync":
                case "getasync":
                case "postasync":
                    hasNetworkAccess = true;
                    AddPattern(patterns, $"Network access via .{member.Member}");
                    break;
                case "invoke":
                case "invokeasync":
                    // [System.Reflection.Assembly]::Load + Invoke = reflective execution
                    AddPattern(patterns, "Reflection-based invocation");
                    break;
            }
        }

        // --- Pass 3: AMSI bypass + long base64 strings in string literals ---
        foreach (var str in ast.FindAll(a => a is StringConstantExpressionAst, true).OfType<StringConstantExpressionAst>())
        {
            var v = str.Value;
            if (v.Contains("amsi", StringComparison.OrdinalIgnoreCase))
                AddPattern(patterns, "AMSI reference");

            if (v.Length >= 100 && IsBase64Like(v))
            {
                hasObfuscation = true;
                AddPattern(patterns, "Embedded base64 payload string");
            }
        }

        // --- Pass 4: nested script-block count (> 2 is unusual in benign scripts) ---
        var sbCount = ast.FindAll(a => a is ScriptBlockExpressionAst, true).OfType<ScriptBlockExpressionAst>().Count();
        if (sbCount > 2)
        {
            hasObfuscation = true;
            AddPattern(patterns, $"Nested script blocks ({sbCount})");
        }

        return new ScriptAnalysisData(
            ScriptType.PowerShell, hasObfuscation, hasNetworkAccess,
            hasProcessExec, hasFileSystem, patterns);
    }

    // ------------------------------------------------------------------ regex fallback for non-PS types

    private static ScriptAnalysisData AnalyzeByRegex(ScriptType scriptType, string content)
    {
        var lower = content.ToLowerInvariant();
        var patterns = new List<string>();
        bool hasObfuscation = false, hasNetworkAccess = false;
        bool hasProcessExecution = false, hasFileSystemAccess = false;

        switch (scriptType)
        {
            case ScriptType.PowerShell:
                AnalyzePowerShellRegex(lower, patterns, ref hasObfuscation, ref hasNetworkAccess,
                    ref hasProcessExecution, ref hasFileSystemAccess);
                break;
            case ScriptType.VBScript:
                AnalyzeVBScript(lower, patterns, ref hasObfuscation, ref hasNetworkAccess,
                    ref hasProcessExecution, ref hasFileSystemAccess);
                break;
            case ScriptType.Batch:
                AnalyzeBatch(lower, patterns, ref hasObfuscation, ref hasNetworkAccess,
                    ref hasProcessExecution, ref hasFileSystemAccess);
                break;
            case ScriptType.JavaScript:
                AnalyzeJavaScript(lower, patterns, ref hasObfuscation, ref hasNetworkAccess,
                    ref hasProcessExecution, ref hasFileSystemAccess);
                break;
        }

        return new ScriptAnalysisData(scriptType, hasObfuscation, hasNetworkAccess,
            hasProcessExecution, hasFileSystemAccess, patterns);
    }

    private static void AnalyzePowerShellRegex(string lower, List<string> patterns,
        ref bool hasObfuscation, ref bool hasNetworkAccess,
        ref bool hasProcessExecution, ref bool hasFileSystemAccess)
    {
        if (Has(lower, "iex ", "invoke-expression", "[convert]::frombase64string", "-encodedcommand"))
        {
            hasObfuscation = true;
            Flag(lower, patterns, "IEX/Invoke-Expression", "iex ", "invoke-expression");
            Flag(lower, patterns, "Base64 decode", "[convert]::frombase64string", "-encodedcommand");
        }
        if (Has(lower, "downloadstring", "invoke-webrequest", "net.webclient", "bitstransfer"))
        {
            hasNetworkAccess = true;
            patterns.Add("Network download");
        }
        if (Has(lower, "start-process", "invoke-item", "shellexecute", "[diagnostics.process]"))
        {
            hasProcessExecution = true;
            patterns.Add("Process execution");
        }
        if (Has(lower, "get-content", "set-content", "out-file", "[io.file]"))
        {
            hasFileSystemAccess = true;
            patterns.Add("File system access");
        }
        Flag(lower, patterns, "AMSI bypass", "amsiutils", "amsi.dll");
        Flag(lower, patterns, "Bypass execution policy", "-executionpolicy bypass", "set-executionpolicy bypass");
        Flag(lower, patterns, "Hidden window", "-windowstyle hidden");
        Flag(lower, patterns, "Credential theft", "convertfrom-securestring", "sekurlsa");
    }

    private static void AnalyzeVBScript(string lower, List<string> patterns,
        ref bool hasObfuscation, ref bool hasNetworkAccess,
        ref bool hasProcessExecution, ref bool hasFileSystemAccess)
    {
        if (Has(lower, "chr(", "chrw(", "execute(", "executeglobal"))
        {
            hasObfuscation = true;
            Flag(lower, patterns, "Chr() obfuscation", "chr(", "chrw(");
            Flag(lower, patterns, "Execute obfuscation", "execute(", "executeglobal");
        }
        if (Has(lower, "xmlhttp", "winhttprequest", "microsoft.xmlhttp", "msxml2.xmlhttp"))
        {
            hasNetworkAccess = true;
            patterns.Add("Network request via XMLHTTP");
        }
        if (Has(lower, "wscript.shell", "shell.application", "createobject"))
        {
            hasProcessExecution = true;
            Flag(lower, patterns, "WScript.Shell execution", "wscript.shell");
            Flag(lower, patterns, "Shell.Application execution", "shell.application");
        }
        if (Has(lower, "filesystemobject", "scripting.filesystemobject", "adodb.stream"))
        {
            hasFileSystemAccess = true;
            patterns.Add("FileSystemObject access");
        }
        Flag(lower, patterns, "Registry access", "regread", "regwrite");
    }

    private static void AnalyzeBatch(string lower, List<string> patterns,
        ref bool hasObfuscation, ref bool hasNetworkAccess,
        ref bool hasProcessExecution, ref bool hasFileSystemAccess)
    {
        if (Has(lower, "set /a", "cmd /v", "%%"))
        {
            hasObfuscation = true;
            Flag(lower, patterns, "Variable obfuscation", "set /a", "cmd /v");
        }
        if (Has(lower, "powershell", "certutil -urlcache", "bitsadmin /transfer"))
        {
            hasNetworkAccess = true;
            Flag(lower, patterns, "PowerShell invocation", "powershell");
            Flag(lower, patterns, "CertUtil download", "certutil -urlcache");
            Flag(lower, patterns, "BITSAdmin download", "bitsadmin /transfer");
        }
        if (Has(lower, "net user", "net localgroup administrators", "schtasks /create"))
        {
            hasProcessExecution = true;
            Flag(lower, patterns, "Privilege escalation (net user/group)", "net user", "net localgroup administrators");
            Flag(lower, patterns, "Scheduled task creation", "schtasks /create");
        }
        if (Has(lower, "reg add", "reg delete", "reg export"))
        {
            hasFileSystemAccess = true;
            patterns.Add("Registry modification");
        }
        Flag(lower, patterns, "Service creation", "sc create");
        Flag(lower, patterns, "UAC bypass attempt", "eventvwr.exe", "fodhelper.exe");
    }

    private static void AnalyzeJavaScript(string lower, List<string> patterns,
        ref bool hasObfuscation, ref bool hasNetworkAccess,
        ref bool hasProcessExecution, ref bool hasFileSystemAccess)
    {
        if (Has(lower, "eval(", "string.fromcharcode", "unescape(", "atob("))
        {
            hasObfuscation = true;
            Flag(lower, patterns, "eval() execution", "eval(");
            Flag(lower, patterns, "fromCharCode obfuscation", "string.fromcharcode");
            Flag(lower, patterns, "Base64 decode (atob)", "atob(");
        }
        if (Has(lower, "xmlhttprequest", "activexobject", "winhttprequest"))
        {
            hasNetworkAccess = true;
            Flag(lower, patterns, "XMLHttpRequest/ActiveX network", "xmlhttprequest", "activexobject");
        }
        if (Has(lower, "wscript.shell", "shell.application", "wscript.createobject"))
        {
            hasProcessExecution = true;
            patterns.Add("WScript.Shell execution");
        }
        if (Has(lower, "filesystemobject", "scripting.filesystemobject", "adodb.stream"))
        {
            hasFileSystemAccess = true;
            patterns.Add("FileSystemObject access");
        }
        Flag(lower, patterns, "document.write injection", "document.write(");
        Flag(lower, patterns, "innerHTML injection", ".innerhtml");
    }

    // ------------------------------------------------------------------ shared helpers

    private static bool IsBase64Like(string s)
        => s.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=');

    private static void AddPattern(List<string> list, string label)
    { if (!list.Contains(label)) list.Add(label); }

    private static bool Has(string content, params string[] values)
        => values.Any(content.Contains);

    private static void Flag(string content, List<string> patterns, string label, params string[] triggers)
    {
        if (triggers.Any(content.Contains) && !patterns.Contains(label))
            patterns.Add(label);
    }
}
