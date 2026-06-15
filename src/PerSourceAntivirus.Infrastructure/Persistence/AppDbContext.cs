using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Persistence;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<ScannedFile> ScannedFiles => Set<ScannedFile>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ScannedFile>(builder =>
        {
            builder.HasKey(f => f.Id);
            builder.Property(f => f.FilePath).IsRequired();
            builder.Property(f => f.FileName).IsRequired();
            builder.Property(f => f.Sha256Hash).IsRequired().HasMaxLength(64);
        });
    }
}
