using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Application.Common.Interfaces;

public interface ITlsCertValidator
{
    event EventHandler<TlsCertAlertEventArgs> AlertDetected;
    TlsCertAlert? ValidateCertificate(string hostname, int port, System.Security.Cryptography.X509Certificates.X509Certificate2? cert, System.Net.Security.SslPolicyErrors errors);
}

public record TlsCertAlertEventArgs(TlsCertAlert Alert);
