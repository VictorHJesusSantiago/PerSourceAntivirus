using MimeKit;
using PerSourceAntivirus.Application.Common.Interfaces;
using System.Text.RegularExpressions;

namespace PerSourceAntivirus.Infrastructure.Email;

// TODO: Register in DependencyInjection.cs as: services.AddSingleton<IEmailScanner, MimeKitEmailScanner>();
public sealed class MimeKitEmailScanner : IEmailScanner
{
    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
        ".scr", ".com", ".pif", ".iso", ".img", ".lnk", ".jar", ".msi"
    };

    // Regex to find HTTP links to bare IP addresses
    private static readonly Regex IpLinkRegex = new(
        @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public bool CanScan(string filePath)
    {
        var ext = Path.GetExtension(filePath);
        return string.Equals(ext, ".eml", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ext, ".msg", StringComparison.OrdinalIgnoreCase);
    }

    public EmailScanData? Scan(string filePath)
    {
        try
        {
            MimeMessage message;
            try
            {
                message = MimeMessage.Load(filePath);
            }
            catch
            {
                return null;
            }

            // Enumerate attachments
            var suspiciousAttachmentNames = new List<string>();
            int attachmentCount = 0;
            int suspiciousAttachmentCount = 0;

            foreach (var attachment in message.Attachments)
            {
                attachmentCount++;
                if (attachment is MimePart part)
                {
                    var fileName = part.FileName ?? string.Empty;
                    var ext = Path.GetExtension(fileName);
                    if (SuspiciousExtensions.Contains(ext))
                    {
                        suspiciousAttachmentCount++;
                        suspiciousAttachmentNames.Add(fileName);
                    }
                }
            }

            // Extract body text for phishing analysis
            var bodyText = message.TextBody ?? message.HtmlBody ?? string.Empty;
            var phishingIndicators = new List<string>();
            int phishingLinkCount = 0;

            // Check for phishing patterns
            var lowerBody = bodyText.ToLowerInvariant();

            if (lowerBody.Contains("verify your account") && lowerBody.Contains("http"))
            {
                phishingIndicators.Add("VerifyAccountWithLink");
                phishingLinkCount++;
            }

            var ipMatches = IpLinkRegex.Matches(bodyText);
            if (ipMatches.Count > 0)
            {
                phishingIndicators.Add("ClickHereIpLink");
                phishingLinkCount += ipMatches.Count;
            }

            if (lowerBody.Contains("update your payment"))
            {
                phishingIndicators.Add("UpdatePayment");
                phishingLinkCount++;
            }

            // Subject phishing keywords
            var subject = message.Subject?.ToLowerInvariant() ?? string.Empty;
            if (subject.Contains("urgent") || subject.Contains("immediately") ||
                subject.Contains("suspended") || subject.Contains("verify"))
            {
                phishingIndicators.Add("SuspiciousSubject");
            }

            // Spoofed sender: From domain differs from Reply-To domain
            bool hasSpoofedSender = false;
            var fromDomain = ExtractDomain(message.From?.Mailboxes.FirstOrDefault()?.Address);
            var replyToDomain = ExtractDomain(message.ReplyTo?.Mailboxes.FirstOrDefault()?.Address);

            if (fromDomain is not null && replyToDomain is not null &&
                !string.Equals(fromDomain, replyToDomain, StringComparison.OrdinalIgnoreCase))
            {
                hasSpoofedSender = true;
                phishingIndicators.Add("SpoofedSender");
            }

            // Risk score: suspicious attachment × 3 + phishing link × 2 + spoofed sender × 2
            int riskScore = suspiciousAttachmentCount * 3
                          + phishingLinkCount * 2
                          + (hasSpoofedSender ? 2 : 0);

            return new EmailScanData(
                AttachmentCount: attachmentCount,
                SuspiciousAttachmentCount: suspiciousAttachmentCount,
                PhishingLinkCount: phishingLinkCount,
                SuspiciousAttachmentNames: suspiciousAttachmentNames,
                PhishingIndicators: phishingIndicators,
                HasSpoofedSender: hasSpoofedSender,
                RiskScore: riskScore);
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractDomain(string? emailAddress)
    {
        if (string.IsNullOrWhiteSpace(emailAddress)) return null;
        var atIndex = emailAddress.IndexOf('@');
        return atIndex >= 0 ? emailAddress[(atIndex + 1)..] : null;
    }
}
