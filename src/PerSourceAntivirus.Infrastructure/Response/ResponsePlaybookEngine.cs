using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using SysProcess = System.Diagnostics.Process;

namespace PerSourceAntivirus.Infrastructure.Response;

public sealed class ResponsePlaybookEngine(IServiceScopeFactory scopeFactory, string quarantineDirectory)
    : IResponsePlaybookEngine
{
    public async Task EvaluateAsync(PlaybookTriggerContext context, CancellationToken ct = default)
    {
        using var scope = scopeFactory.CreateScope();
        var ruleRepository = scope.ServiceProvider.GetRequiredService<IResponsePlaybookRuleRepository>();
        var logRepository = scope.ServiceProvider.GetRequiredService<IPlaybookExecutionLogRepository>();

        var rules = await ruleRepository.GetEnabledAsync(ct).ConfigureAwait(false);
        var matching = rules.Where(r =>
            context.Severity >= r.MinSeverity &&
            (r.TriggerAlertType == "*" || r.TriggerAlertType.Equals(context.AlertType, StringComparison.OrdinalIgnoreCase)));

        foreach (var rule in matching)
        {
            var executed = new List<string>();
            bool success = true;
            string? error = null;

            foreach (var action in rule.Actions.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                try
                {
                    await ExecuteActionAsync(action, context, scope.ServiceProvider, ct).ConfigureAwait(false);
                    executed.Add(action);
                }
                catch (Exception ex)
                {
                    success = false;
                    error = $"{action}: {ex.Message}";
                }
            }

            try
            {
                await logRepository.AddAsync(new PlaybookExecutionLog
                {
                    Id = Guid.NewGuid(),
                    RuleId = rule.Id,
                    RuleName = rule.Name,
                    AlertType = context.AlertType,
                    Severity = context.Severity,
                    ProcessId = context.ProcessId,
                    FilePath = context.FilePath,
                    ActionsExecuted = string.Join(",", executed),
                    Success = success,
                    ErrorMessage = error,
                    ExecutedAtUtc = DateTime.UtcNow
                }, ct).ConfigureAwait(false);
            }
            catch { }
        }
    }

    private async Task ExecuteActionAsync(
        string action, PlaybookTriggerContext context, IServiceProvider services, CancellationToken ct)
    {
        switch (action)
        {
            case "KillProcess":
                if (context.ProcessId is int pid)
                {
                    try { SysProcess.GetProcessById(pid).Kill(entireProcessTree: true); }
                    catch (ArgumentException) { /* already exited */ }
                }
                break;

            case "IsolateNetwork":
                var isolation = services.GetRequiredService<IHostIsolationService>();
                await isolation.IsolateAsync($"Playbook response to {context.AlertType}", ct).ConfigureAwait(false);
                break;

            case "Quarantine":
                if (!string.IsNullOrEmpty(context.FilePath) && File.Exists(context.FilePath))
                {
                    Directory.CreateDirectory(quarantineDirectory);
                    var dest = Path.Combine(quarantineDirectory, $"{Guid.NewGuid()}_{Path.GetFileName(context.FilePath)}.quarantine");
                    File.Move(context.FilePath, dest);
                }
                break;

            case "Notify":
                var notificationCenter = services.GetRequiredService<INotificationCenter>();
                await notificationCenter.AddNotificationAsync(new NotificationRecord
                {
                    Id = Guid.NewGuid(),
                    NotificationType = "PlaybookResponse",
                    Title = $"Resposta automática: {context.AlertType}",
                    Message = context.FilePath is not null
                        ? $"Ação automática executada para {context.AlertType} em {context.FilePath}"
                        : $"Ação automática executada para {context.AlertType}",
                    Severity = context.Severity,
                    Status = "Unread",
                    RelatedEntityType = context.AlertType,
                    RelatedEntityId = null,
                    CreatedAtUtc = DateTime.UtcNow
                }, ct).ConfigureAwait(false);
                break;
        }
    }
}
