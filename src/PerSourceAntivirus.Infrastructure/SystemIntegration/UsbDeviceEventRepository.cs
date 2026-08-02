using Microsoft.EntityFrameworkCore;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;
using PerSourceAntivirus.Infrastructure.Persistence;

namespace PerSourceAntivirus.Infrastructure.SystemIntegration;

public sealed class UsbDeviceEventRepository(AppDbContext db) : IUsbDeviceEventRepository
{
    public async Task AddAsync(UsbDeviceEvent evt, CancellationToken ct = default)
    {
        db.Set<UsbDeviceEvent>().Add(evt);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<UsbDeviceEvent>> GetAllAsync(CancellationToken ct = default)
        => await db.Set<UsbDeviceEvent>().ToListAsync(ct);
}
