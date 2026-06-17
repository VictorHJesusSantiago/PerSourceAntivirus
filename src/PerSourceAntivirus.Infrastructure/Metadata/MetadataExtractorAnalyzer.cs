using MetadataExtractor;
using PerSourceAntivirus.Application.Common.Interfaces;
using MetaDir = MetadataExtractor.Directory;

namespace PerSourceAntivirus.Infrastructure.Metadata;

public class MetadataExtractorAnalyzer : IFileMetadataAnalyzer
{
    // Extensions where MetadataExtractor provides useful results.
    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp",
        ".heic", ".heif", ".cr2", ".nef", ".arw", ".dng",
        ".pdf", ".svg", ".mp3", ".mp4", ".mov", ".avi", ".mkv"
    };

    // Expected first-bytes keyed by extension. Value is the magic byte array.
    private static readonly Dictionary<string, byte[]> ExtensionMagic = new(StringComparer.OrdinalIgnoreCase)
    {
        [".pdf"]  = [0x25, 0x50, 0x44, 0x46],       // %PDF
        [".jpg"]  = [0xFF, 0xD8, 0xFF],
        [".jpeg"] = [0xFF, 0xD8, 0xFF],
        [".png"]  = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        [".gif"]  = [0x47, 0x49, 0x46, 0x38],        // GIF8
        [".bmp"]  = [0x42, 0x4D],                    // BM
        [".zip"]  = [0x50, 0x4B, 0x03, 0x04],
        [".docx"] = [0x50, 0x4B, 0x03, 0x04],
        [".xlsx"] = [0x50, 0x4B, 0x03, 0x04],
        [".pptx"] = [0x50, 0x4B, 0x03, 0x04],
        [".doc"]  = [0xD0, 0xCF, 0x11, 0xE0],        // OLE2 Compound
        [".xls"]  = [0xD0, 0xCF, 0x11, 0xE0],
        [".ppt"]  = [0xD0, 0xCF, 0x11, 0xE0],
    };

    // Magic byte signatures that are suspicious to find inside another file type.
    private static readonly (byte[] Magic, string Label)[] SuspiciousMagic =
    [
        ([0x50, 0x4B, 0x03, 0x04], "ZIP"),
        ([0x4D, 0x5A],             "WindowsPE"),
        ([0xD0, 0xCF, 0x11, 0xE0], "OLE2Document"),
        ([0x7F, 0x45, 0x4C, 0x46], "ELF"),
    ];

    // PDF markers that indicate risky content.
    private static readonly string[] PdfJsMarkers     = ["/JavaScript", "/JS\x20", "/JS\x0D", "/JS\x0A"];
    private static readonly string[] PdfEmbedMarkers  = ["/EmbeddedFile", "/EmbeddedFiles"];
    private static readonly string[] PdfActionMarkers = ["/OpenAction", "/AA\x20", "/AA\x0D", "/AA<<", "/Launch"];

    public FileMetadataData? Analyze(string filePath)
    {
        if (!File.Exists(filePath)) return null;

        var ext = Path.GetExtension(filePath);
        bool inSupportedSet = SupportedExtensions.Contains(ext);

        // Read raw bytes for magic byte and PDF content analysis (up to 64 KB).
        byte[] header;
        try
        {
            using var fs = File.OpenRead(filePath);
            var len = (int)Math.Min(fs.Length, 65536);
            header = new byte[len];
            _ = fs.Read(header, 0, len);
        }
        catch { return null; }

        var anomalies = new List<string>();

        // --- Polyglot detection ---
        bool isPolyglot = false;
        if (ExtensionMagic.TryGetValue(ext, out var expectedMagic))
        {
            if (!StartsWith(header, expectedMagic))
            {
                isPolyglot = true;
                anomalies.Add("MagicBytesMismatch");
            }
        }

        // Scan for suspicious secondary magic bytes within the body (skip first 8 bytes).
        if (header.Length > 8 && !isPolyglot)
        {
            foreach (var (magic, label) in SuspiciousMagic)
            {
                if (ContainsMagicAt(header, magic, offset: 8))
                {
                    isPolyglot = true;
                    anomalies.Add($"EmbeddedSignature:{label}");
                    break;
                }
            }
        }

        // --- PDF-specific content scan ---
        bool hasPdfJs = false, hasPdfEmbedded = false, hasPdfAutoAction = false;
        if (string.Equals(ext, ".pdf", StringComparison.OrdinalIgnoreCase) ||
            (header.Length >= 4 && StartsWith(header, PdfMagic)))
        {
            var text = System.Text.Encoding.Latin1.GetString(header);
            hasPdfJs        = PdfJsMarkers.Any(text.Contains);
            hasPdfEmbedded  = PdfEmbedMarkers.Any(text.Contains);
            hasPdfAutoAction = PdfActionMarkers.Any(text.Contains);

            if (hasPdfJs)         anomalies.Add("PdfJavaScript");
            if (hasPdfEmbedded)   anomalies.Add("PdfEmbeddedFiles");
            if (hasPdfAutoAction) anomalies.Add("PdfAutoAction");
        }

        // --- Library metadata extraction ---
        string? author = null, creator = null;
        DateTime? docCreated = null, docModified = null;

        if (inSupportedSet)
        {
            try
            {
                var dirs = ImageMetadataReader.ReadMetadata(filePath);

                author      = FindTagValue(dirs, "Author", "Artist", "By-line");
                creator     = FindTagValue(dirs, "Creator", "CreatorTool", "Software", "Make", "Camera Make");
                docCreated  = FindDate(dirs, "Date/Time Original", "Creation Date", "Date Created", "Created", "Date/Time Digitized");
                docModified = FindDate(dirs, "Date/Time", "Modify Date", "Modified", "Last Modified", "Date Modified");

                // Date anomaly: modification timestamp precedes creation timestamp.
                if (docCreated.HasValue && docModified.HasValue && docModified.Value < docCreated.Value)
                    anomalies.Add("ModifiedBeforeCreated");
            }
            catch { /* unsupported or corrupt file */ }
        }

        // Return null when nothing interesting was found and there are no anomalies.
        bool hasMetadata = author != null || creator != null || docCreated.HasValue;
        if (!hasMetadata && anomalies.Count == 0)
            return null;

        return new FileMetadataData(
            author, creator, docCreated, docModified,
            hasPdfEmbedded, hasPdfJs, isPolyglot, anomalies);
    }

    // ------------------------------------------------------------------ helpers

    private static readonly byte[] PdfMagic = [0x25, 0x50, 0x44, 0x46]; // %PDF

    private static bool StartsWith(byte[] data, byte[] magic)
    {
        if (data.Length < magic.Length) return false;
        for (int i = 0; i < magic.Length; i++)
            if (data[i] != magic[i]) return false;
        return true;
    }

    private static bool ContainsMagicAt(byte[] data, byte[] magic, int offset)
    {
        for (int i = offset; i <= data.Length - magic.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < magic.Length; j++)
                if (data[i + j] != magic[j]) { found = false; break; }
            if (found) return true;
        }
        return false;
    }

    private static string? FindTagValue(IReadOnlyList<MetaDir> dirs, params string[] tagNames)
        => dirs
            .SelectMany(d => d.Tags)
            .FirstOrDefault(t => tagNames.Contains(t.Name, StringComparer.OrdinalIgnoreCase))
            ?.Description;

    private static DateTime? FindDate(IReadOnlyList<MetaDir> dirs, params string[] tagNames)
    {
        var desc = dirs
            .SelectMany(d => d.Tags)
            .Where(t => tagNames.Contains(t.Name, StringComparer.OrdinalIgnoreCase))
            .Select(t => t.Description)
            .FirstOrDefault(d => d != null);

        if (desc == null) return null;

        // MetadataExtractor returns dates in various formats; try common ones.
        string[] formats =
        [
            "yyyy:MM:dd HH:mm:ss",
            "yyyy-MM-ddTHH:mm:sszzz",
            "yyyy-MM-ddTHH:mm:ss",
            "ddd MMM dd HH:mm:ss yyyy",
            "yyyy-MM-dd HH:mm:ss"
        ];

        foreach (var fmt in formats)
            if (DateTime.TryParseExact(desc, fmt,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var dt))
                return dt;

        if (DateTime.TryParse(desc, out var fallback)) return fallback;
        return null;
    }
}
