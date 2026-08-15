namespace PerSourceAntivirus.Cli.Commands;

public static class CommandArgs
{
    public static string? GetOption(string[] args, string name, int startIndex = 1)
    {
        for (var i = startIndex; i < args.Length - 1; i++)
            if (args[i] == name) return args[i + 1];
        return null;
    }

    public static int GetIntOption(string[] args, string name, int fallback, int startIndex = 1)
    {
        var raw = GetOption(args, name, startIndex);
        return raw is not null && int.TryParse(raw, out var value) ? value : fallback;
    }

    public static bool HasFlag(string[] args, string name) => args.Contains(name);

    public static async Task<int> RunCancellableAsync(
        string startMessage,
        string cancelMessage,
        Func<CancellationToken, Task> action,
        CancellationToken ct)
    {
        Console.WriteLine(startMessage);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cts.Cancel(); };
        Console.CancelKeyPress += handler;
        try
        {
            await action(cts.Token);
            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine(cancelMessage);
            return 0;
        }
        finally
        {
            Console.CancelKeyPress -= handler;
        }
    }
}
