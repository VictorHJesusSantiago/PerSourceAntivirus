using System.IO.Compression;
using System.Text;
using OpenMcdf;
using PerSourceAntivirus.Application.Common.Interfaces;

namespace PerSourceAntivirus.Infrastructure.Office;

public class OfficeMacroAnalyzer : IOfficeMacroAnalyzer
{
    private static readonly HashSet<string> OleExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot" };

    private static readonly HashSet<string> OoxmlMacroExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".ppsm", ".potm" };

    private static readonly HashSet<string> SkippedStreams =
        new(StringComparer.OrdinalIgnoreCase) { "_VBA_PROJECT", "dir", "PROJECTwm", "PROJECT" };

    public OfficeMacroData? Analyze(string filePath)
    {
        var ext = Path.GetExtension(filePath);
        bool isOle   = OleExtensions.Contains(ext);
        bool isOoxml = OoxmlMacroExtensions.Contains(ext);
        if (!isOle && !isOoxml) return null;

        string olePath    = filePath;
        string? tempFile  = null;

        try
        {
            if (isOoxml)
            {
                var vbaBytes = ExtractVbaProjectFromOoxml(filePath);
                if (vbaBytes == null) return null;
                tempFile = Path.GetTempFileName();
                File.WriteAllBytes(tempFile, vbaBytes);
                olePath = tempFile;
            }

            var modules = ExtractModuleTextsFromFile(olePath);

            if (modules.Count == 0 && isOle)
                return new OfficeMacroData(false, false, false, false, false, []);

            if (modules.Count == 0)
                return null;

            return AnalyzeMacroText(modules);
        }
        catch
        {
            return null;
        }
        finally
        {
            if (tempFile is not null && File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    // ------------------------------------------------------------------ extraction

    private static byte[]? ExtractVbaProjectFromOoxml(string filePath)
    {
        try
        {
            using var zip = ZipFile.OpenRead(filePath);
            var entry = zip.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
            if (entry == null) return null;
            using var entryStream = entry.Open();
            using var ms = new MemoryStream();
            entryStream.CopyTo(ms);
            return ms.ToArray();
        }
        catch { return null; }
    }

    private static List<string> ExtractModuleTextsFromFile(string olePath)
    {
        var results = new List<string>();
        try
        {
            using var root = RootStorage.OpenRead(olePath);

            // VBA storage may be at the root level or one level deep (e.g. "Macros/VBA")
            var vbaEntry = FindEntryByName(root.EnumerateEntries(), "VBA", EntryType.Storage);

            if (vbaEntry is null)
            {
                // Search one level deeper
                foreach (var entry in root.EnumerateEntries()
                    .Where(e => e.Type == EntryType.Storage))
                {
                    var child = root.OpenStorage(entry.Name);
                    var inner = FindEntryByName(child.EnumerateEntries(), "VBA", EntryType.Storage);
                    if (inner is not null)
                    {
                        var vbaSub = child.OpenStorage("VBA");
                        ReadModulesFromStorage(vbaSub, results);
                        return results;
                    }
                }
                return results;
            }

            var vbaStorage = root.OpenStorage("VBA");
            ReadModulesFromStorage(vbaStorage, results);
        }
        catch { /* malformed OLE2 */ }

        return results;
    }

    private static EntryInfo? FindEntryByName(
        IEnumerable<EntryInfo> entries, string name, EntryType type)
        => entries.FirstOrDefault(e =>
            e.Type == type &&
            e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static void ReadModulesFromStorage(Storage vbaStorage, List<string> results)
    {
        foreach (var entry in vbaStorage.EnumerateEntries())
        {
            if (entry.Type != EntryType.Stream) continue;
            if (SkippedStreams.Contains(entry.Name)) continue;
            if (entry.Name.StartsWith("__SRP_", StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                using var moduleStream = vbaStorage.OpenStream(entry.Name);
                using var ms = new MemoryStream();
                moduleStream.CopyTo(ms);
                var rawBytes = ms.ToArray();

                if (rawBytes.Length < 4) continue;

                var decompressed = VbaDecompressor.Decompress(rawBytes);
                var text = decompressed.Length > 10
                    ? Encoding.Default.GetString(decompressed)
                    : VbaDecompressor.ExtractPrintableText(rawBytes);

                if (text.Length > 10) results.Add(text);
            }
            catch { /* malformed stream */ }
        }
    }

    // ------------------------------------------------------------------ analysis

    private static OfficeMacroData AnalyzeMacroText(List<string> modules)
    {
        var code     = string.Join("\n", modules).ToLowerInvariant();
        var patterns = new List<string>();

        bool hasAutoExec = Contains(code,
            "autoopen", "auto_open", "document_open", "workbook_open",
            "documentopen", "workbookopen", "auto_exec",
            "auto_close", "document_close", "workbook_close");
        if (hasAutoExec) Flag(code, patterns, "AutoExec trigger", "autoopen", "document_open", "workbook_open");

        bool hasProcess = Contains(code,
            "shell(", "shell ", "wscript.shell", "shellexecute", "winexec",
            "createobject(\"wscript.shell", "createobject(\"shell.application",
            "environ(", "powershell");
        if (hasProcess) Flag(code, patterns, "Process execution via Shell", "shell(", "wscript.shell", "powershell");

        bool hasNetwork = Contains(code,
            "xmlhttp", "msxml2.xmlhttp", "microsoft.xmlhttp", "winhttp",
            "winhttprequest", "urldownloadtofile", "serverxmlhttp");
        if (hasNetwork) patterns.Add("Network access");

        int chrCount = CountOccurrences(code, "chr(");
        bool hasObfuscation = chrCount >= 5;
        if (hasObfuscation) patterns.Add($"Chr() obfuscation ({chrCount} calls)");

        Flag(code, patterns, "Registry access", "regread", "regwrite", "hkey_");
        Flag(code, patterns, "File system access", "filesystemobject", "scripting.filesystemobject");
        Flag(code, patterns, "Base64 decode", "frombase64string", "base64decode");
        Flag(code, patterns, "CreateObject usage", "createobject(");

        return new OfficeMacroData(
            HasMacros: true,
            HasAutoExec: hasAutoExec,
            HasNetworkAccess: hasNetwork,
            HasProcessExecution: hasProcess,
            HasObfuscation: hasObfuscation,
            SuspiciousPatterns: patterns);
    }

    // ------------------------------------------------------------------ helpers

    private static bool Contains(string text, params string[] values)
        => values.Any(text.Contains);

    private static void Flag(string text, List<string> list, string label, params string[] triggers)
    {
        if (!list.Contains(label) && triggers.Any(text.Contains))
            list.Add(label);
    }

    private static int CountOccurrences(string text, string pattern)
    {
        int count = 0, idx = 0;
        while ((idx = text.IndexOf(pattern, idx, StringComparison.Ordinal)) >= 0) { count++; idx++; }
        return count;
    }
}
