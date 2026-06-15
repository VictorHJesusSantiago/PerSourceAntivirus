using MediatR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PerSourceAntivirus.Application;
using PerSourceAntivirus.Application.Scans.Commands.ScanDirectory;
using PerSourceAntivirus.Application.Scans.Queries.GetScannedFiles;
using PerSourceAntivirus.Infrastructure;
using PerSourceAntivirus.Infrastructure.Persistence;

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

builder.Services.AddApplicationServices();
builder.Services.AddInfrastructureServices(builder.Configuration);

using var host = builder.Build();

var dbContext = host.Services.GetRequiredService<AppDbContext>();
await dbContext.Database.EnsureCreatedAsync();

var mediator = host.Services.GetRequiredService<IMediator>();

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

switch (args[0])
{
    case "scan":
        if (args.Length < 2)
        {
            Console.Error.WriteLine("Usage: scan <path>");
            return 1;
        }

        var result = await mediator.Send(new ScanDirectoryCommand(args[1]));
        Console.WriteLine($"Scanned {result.FilesScanned} file(s) in {result.Duration.TotalSeconds:F2}s.");
        break;

    case "list":
        var files = await mediator.Send(new GetScannedFilesQuery());
        Console.WriteLine($"{"Hash",-66} {"Entropy",-8} {"Size",-10} Path");
        foreach (var file in files)
        {
            Console.WriteLine($"{file.Sha256Hash,-66} {file.Entropy,-8:F3} {file.SizeBytes,-10} {file.FilePath}");
        }
        break;

    default:
        PrintUsage();
        return 1;
}

return 0;

static void PrintUsage()
{
    Console.WriteLine("PerSourceAntivirus CLI");
    Console.WriteLine("Usage:");
    Console.WriteLine("  scan <path>   Scan all files under <path> and store hash/entropy results");
    Console.WriteLine("  list          List all previously scanned files");
}
