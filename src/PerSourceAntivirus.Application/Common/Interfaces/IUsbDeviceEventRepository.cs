using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface IUsbDeviceEventRepository
{
    Task AddAsync(UsbDeviceEvent evt, CancellationToken ct = default);
    Task<IReadOnlyList<UsbDeviceEvent>> GetAllAsync(CancellationToken ct = default);
}
