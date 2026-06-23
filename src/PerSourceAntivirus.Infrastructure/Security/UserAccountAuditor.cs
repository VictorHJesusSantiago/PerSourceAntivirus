using System.DirectoryServices.AccountManagement;
using System.Runtime.Versioning;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Security;

[SupportedOSPlatform("windows")]
public sealed class UserAccountAuditor : IUserAccountAuditor
{
    private static readonly HashSet<string> KnownServiceAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DefaultAccount",
        "WDAGUtilityAccount", "Guest"
    };

    public async Task<IReadOnlyList<UserAccountAuditFinding>> AuditAsync(CancellationToken ct)
    {
        var results = new List<UserAccountAuditFinding>();
        var now = DateTime.UtcNow;

        await Task.Run(() =>
        {
            try
            {
                using var ctx = new PrincipalContext(ContextType.Machine);
                var adminMembers = GetAdminMemberNames(ctx);

                using var searcher = new PrincipalSearcher(new UserPrincipal(ctx));
                foreach (var principal in searcher.FindAll())
                {
                    if (ct.IsCancellationRequested) break;
                    if (principal is not UserPrincipal user) continue;
                    try
                    {
                        AuditUser(user, adminMembers, results, now);
                    }
                    catch { }
                    finally { user.Dispose(); }
                }
            }
            catch { }
        }, ct);

        return results;
    }

    private static HashSet<string> GetAdminMemberNames(PrincipalContext ctx)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var adminsGroup = GroupPrincipal.FindByIdentity(ctx, "Administrators");
            if (adminsGroup == null) return names;
            foreach (var member in adminsGroup.GetMembers(false))
            {
                try { names.Add(member.SamAccountName ?? member.Name ?? string.Empty); }
                finally { member.Dispose(); }
            }
        }
        catch { }
        return names;
    }

    private static void AuditUser(UserPrincipal user, HashSet<string> adminMembers,
        List<UserAccountAuditFinding> results, DateTime now)
    {
        var name = user.SamAccountName ?? user.Name ?? string.Empty;
        if (string.IsNullOrWhiteSpace(name)) return;

        var isAdmin = adminMembers.Contains(name);
        var isEnabled = user.Enabled ?? false;
        var lastLogon = user.LastLogon;
        var passwordNeverExpires = user.PasswordNeverExpires;
        var hasPassword = !(user.PasswordNotRequired == true);
        var isKnownService = KnownServiceAccounts.Contains(name);

        if (!hasPassword && isEnabled && !isKnownService)
        {
            results.Add(MakeFinding(name, "Account has no password requirement", isAdmin,
                hasPassword, isEnabled, passwordNeverExpires, lastLogon, "NoPassword", 8, now));
        }

        if (!isEnabled && lastLogon.HasValue && (now - lastLogon.Value.ToUniversalTime()).TotalDays < 30)
        {
            results.Add(MakeFinding(name, "Disabled account with login activity in last 30 days",
                isAdmin, hasPassword, isEnabled, passwordNeverExpires, lastLogon, "SuspiciousRecentActivity", 7, now));
        }

        if (isAdmin && !isKnownService && !string.Equals(name, "Administrator", StringComparison.OrdinalIgnoreCase))
        {
            results.Add(MakeFinding(name, "Non-standard account in Administrators group",
                isAdmin, hasPassword, isEnabled, passwordNeverExpires, lastLogon, "UnexpectedAdmin", 6, now));
        }

        if (passwordNeverExpires && isEnabled && !isKnownService)
        {
            results.Add(MakeFinding(name, "Password never expires on active non-service account",
                isAdmin, hasPassword, isEnabled, passwordNeverExpires, lastLogon, "PasswordNeverExpires", 5, now));
        }
    }

    private static UserAccountAuditFinding MakeFinding(string name, string issue,
        bool isAdmin, bool hasPassword, bool isEnabled, bool passwordNeverExpires,
        DateTime? lastLogon, string classification, int severity, DateTime now)
    {
        return new UserAccountAuditFinding
        {
            Id = Guid.NewGuid(),
            AccountName = name,
            Issue = issue,
            IsAdmin = isAdmin,
            HasPassword = hasPassword,
            IsEnabled = isEnabled,
            PasswordNeverExpires = passwordNeverExpires,
            LastLogon = lastLogon,
            Classification = classification,
            Severity = severity,
            AuditedAtUtc = now
        };
    }
}
