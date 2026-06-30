using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using PerSourceAntivirus.Application.Common.Interfaces;
using PerSourceAntivirus.Domain.Entities;

namespace PerSourceAntivirus.Infrastructure.Tls;

public sealed class LocalTlsProxy : ITlsInspector, IDisposable
{
    public event EventHandler<TlsCertAlertEventArgs>? CertAlertDetected;
    private static readonly string[] SuspiciousUserAgents =
    [
        "python-requests",
        "curl/7.19",
        "Go-http-client/1.1",
        "Wget/1.12",
        "masscan",
        "sqlmap",
        "nikto",
        "zgrab"
    ];

    private static readonly string[] SuspiciousTlds = [".xyz", ".tk", ".cc", ".pw", ".top", ".gq", ".ml", ".cf"];
    private static readonly byte[] PeMagic = [0x4D, 0x5A]; // MZ

    private readonly string _caPath;
    private readonly Channel<TlsInspectionEvent> _channel;
    private readonly Channel<TlsCertAlert> _certAlertChannel;
    private readonly ConcurrentDictionary<string, X509Certificate2> _certCache = new();
    private readonly ConcurrentDictionary<string, DateTime> _certAlertDedup = new(StringComparer.OrdinalIgnoreCase);
    private readonly IServiceScopeFactory? _scopeFactory;

    private X509Certificate2? _caCert;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private int _proxyPort;
    private bool _running;
    private bool _disposed;

    public LocalTlsProxy(string caPath = "data/psav-ca.cer", IServiceScopeFactory? scopeFactory = null)
    {
        _caPath = caPath;
        _scopeFactory = scopeFactory;
        _channel = Channel.CreateUnbounded<TlsInspectionEvent>(new UnboundedChannelOptions
        {
            SingleWriter = false,
            SingleReader = false
        });
        _certAlertChannel = Channel.CreateUnbounded<TlsCertAlert>(new UnboundedChannelOptions
        {
            SingleWriter = false,
            SingleReader = false
        });
    }

    public TlsProxyStatus GetStatus()
    {
        var thumbprint = _caCert?.Thumbprint ?? string.Empty;
        return new TlsProxyStatus(_running, _proxyPort, thumbprint);
    }

    public async Task StartAsync(int port = 8080, CancellationToken ct = default)
    {
        if (_running) return;

        _caCert = EnsureCaCert();
        _proxyPort = port;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        _running = true;

        _ = AcceptLoopAsync(_cts.Token);
    }

    public Task StopAsync()
    {
        if (!_running) return Task.CompletedTask;
        _running = false;
        _cts?.Cancel();
        _listener?.Stop();
        _channel.Writer.TryComplete();
        return Task.CompletedTask;
    }

    public async IAsyncEnumerable<TlsInspectionEvent> WatchAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var evt in _channel.Reader.ReadAllAsync(ct))
            yield return evt;
    }

    private X509Certificate2 EnsureCaCert()
    {
        var dir = Path.GetDirectoryName(_caPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        // Always regenerate so we have the private key in memory.
        // The public cert is saved to disk only for user/system trust installation.
        return GenerateAndSaveCaCert();
    }

    private X509Certificate2 GenerateAndSaveCaCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=PSAV Root CA, O=PerSourceAntivirus",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: false));

        var caCert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5));

        // Export public cert to disk
        var dir = Path.GetDirectoryName(_caPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        File.WriteAllBytes(_caPath, caCert.Export(X509ContentType.Cert));

        // Install to CurrentUser\Root
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(caCert);
            store.Close();
        }
        catch
        {
            // installation failure is non-fatal
        }

        return caCert;
    }

    private X509Certificate2 GetOrCreateLeafCert(string targetHost)
    {
        return _certCache.GetOrAdd(targetHost, host =>
        {
            if (_caCert == null)
                throw new InvalidOperationException("CA cert not initialized");

            using var leafRsa = RSA.Create(2048);
            var leafReq = new CertificateRequest(
                $"CN={host}",
                leafRsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var sanBuilder = new SubjectAlternativeNameBuilder();
            if (IPAddress.TryParse(host, out _))
                sanBuilder.AddIpAddress(IPAddress.Parse(host));
            else
                sanBuilder.AddDnsName(host);
            leafReq.CertificateExtensions.Add(sanBuilder.Build());

            var serialNumber = Guid.NewGuid().ToByteArray();
            var leafCert = leafReq.Create(
                _caCert,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(1),
                serialNumber);

            return leafCert.CopyWithPrivateKey(leafRsa);
        });
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(ct);
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // continue accepting
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using var _ = client;
            var stream = client.GetStream();

            // Read the CONNECT line
            var connectLine = await ReadLineAsync(stream, ct);
            if (string.IsNullOrEmpty(connectLine)) return;

            // Parse "CONNECT host:port HTTP/1.1"
            if (!connectLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                return;

            var parts = connectLine.Split(' ');
            if (parts.Length < 2) return;

            var hostPort = parts[1];
            var colonIdx = hostPort.LastIndexOf(':');
            string targetHost;
            int targetPort;

            if (colonIdx > 0 && int.TryParse(hostPort[(colonIdx + 1)..], out targetPort))
                targetHost = hostPort[..colonIdx];
            else
            {
                targetHost = hostPort;
                targetPort = 443;
            }

            // Drain remaining headers
            while (true)
            {
                var headerLine = await ReadLineAsync(stream, ct);
                if (string.IsNullOrEmpty(headerLine)) break;
            }

            // Send 200 Connection Established
            var established = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await stream.WriteAsync(established, ct);

            // Get leaf cert for this host
            var leafCert = GetOrCreateLeafCert(targetHost);

            // Wrap client side in SslStream
            using var clientSsl = new SslStream(stream, leaveInnerStreamOpen: false,
                (_, _, _, _) => true);

            await clientSsl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leafCert,
                ClientCertificateRequired = false,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            }, ct);

            // Connect to real target
            using var targetTcp = new TcpClient();
            await targetTcp.ConnectAsync(targetHost, targetPort, ct);

            X509Certificate2? serverCert = null;
            SslPolicyErrors policyErrors = SslPolicyErrors.None;

            using var targetSsl = new SslStream(targetTcp.GetStream(), leaveInnerStreamOpen: false,
                (_, _, _, _) => true);

            await targetSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    serverCert = cert != null ? new X509Certificate2(cert) : null;
                    policyErrors = errors;
                    return true;
                }
            }, ct);

            if (serverCert != null)
                ValidateAndFireCertAlert(targetHost, targetPort, serverCert, policyErrors);

            // Intercept and forward HTTP request
            await InterceptAndForwardAsync(clientSsl, targetSsl, targetHost, targetPort, ct);
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
            // ignore per-connection errors
        }
    }

    private async Task InterceptAndForwardAsync(
        SslStream clientStream,
        SslStream targetStream,
        string targetHost,
        int targetPort,
        CancellationToken ct)
    {
        // Read the HTTP request from client
        var requestBytes = await ReadHttpMessageAsync(clientStream, ct);
        if (requestBytes.Length == 0) return;

        var requestText = Encoding.UTF8.GetString(requestBytes);
        var (method, path, requestHeaders) = ParseHttpHeaders(requestText);
        var requestBodySize = GetBodySize(requestBytes, requestText);

        // Check for suspicious user-agent
        var userAgent = ExtractHeader(requestHeaders, "User-Agent");
        var isSuspiciousRequest = IsSuspiciousUserAgent(userAgent);
        var suspiciousReasons = new List<string>();
        if (isSuspiciousRequest) suspiciousReasons.Add($"Suspicious User-Agent: {userAgent}");

        // Check for suspicious TLD
        if (HasSuspiciousTld(targetHost)) suspiciousReasons.Add($"Suspicious TLD in host: {targetHost}");

        // Check for potential exfiltration (POST with binary/base64 body)
        if (method.Equals("POST", StringComparison.OrdinalIgnoreCase) && IsNonStandardPath(path))
        {
            if (requestBodySize > 0 && IsPotentialExfil(requestBytes))
                suspiciousReasons.Add("Potential data exfiltration: POST with encoded body to non-standard path");
        }

        // Forward request to target
        await targetStream.WriteAsync(requestBytes, ct);
        await targetStream.FlushAsync(ct);

        // Read response from target
        var responseBytes = await ReadHttpMessageAsync(targetStream, ct);
        var responseText = Encoding.UTF8.GetString(responseBytes);
        var (_, _, responseHeaders) = ParseHttpHeaders(responseText);
        var responseBodySize = GetBodySize(responseBytes, responseText);
        var statusCode = ParseStatusCode(responseText);

        // Check if response contains PE header (malware download)
        if (ContainsPeHeader(responseBytes)) suspiciousReasons.Add("Response contains PE executable header (MZ)");

        // Forward response to client
        await clientStream.WriteAsync(responseBytes, ct);
        await clientStream.FlushAsync(ct);

        var isSuspicious = suspiciousReasons.Count > 0;
        var evt = new TlsInspectionEvent
        {
            CapturedAtUtc = DateTime.UtcNow,
            TargetHost = targetHost,
            TargetPort = targetPort,
            Method = method,
            RequestPath = path,
            ResponseStatus = statusCode,
            IsSuspicious = isSuspicious,
            SuspiciousReason = isSuspicious ? string.Join("; ", suspiciousReasons) : null,
            RequestBodySize = requestBodySize,
            ResponseBodySize = responseBodySize
        };

        _channel.Writer.TryWrite(evt);
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buffer = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, ct);
            if (read == 0) break;
            var ch = (char)buffer[0];
            if (ch == '\n') break;
            if (ch != '\r') sb.Append(ch);
        }
        return sb.ToString();
    }

    private static async Task<byte[]> ReadHttpMessageAsync(Stream stream, CancellationToken ct)
    {
        var buf = new List<byte>(8192);
        var oneByte = new byte[1];

        // Read headers until double CRLF
        int crlfCount = 0;
        while (crlfCount < 4)
        {
            var read = await stream.ReadAsync(oneByte, ct);
            if (read == 0) break;
            buf.Add(oneByte[0]);

            if (oneByte[0] == '\r' || oneByte[0] == '\n')
                crlfCount++;
            else
                crlfCount = 0;

            if (buf.Count > 65536) break; // safety limit for headers
        }

        // Check Content-Length and read body
        var headerText = Encoding.UTF8.GetString(buf.ToArray());
        var contentLength = ExtractContentLength(headerText);
        if (contentLength > 0)
        {
            var bodyBuf = new byte[Math.Min(contentLength, 1024 * 1024)]; // cap at 1MB
            var totalRead = 0;
            while (totalRead < bodyBuf.Length)
            {
                var read = await stream.ReadAsync(bodyBuf.AsMemory(totalRead, bodyBuf.Length - totalRead), ct);
                if (read == 0) break;
                totalRead += read;
            }
            buf.AddRange(bodyBuf[..totalRead]);
        }

        return buf.ToArray();
    }

    private static int ExtractContentLength(string headers)
    {
        var match = Regex.Match(headers, @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);
        return match.Success && int.TryParse(match.Groups[1].Value, out var len) ? len : 0;
    }

    private static (string method, string path, string headers) ParseHttpHeaders(string text)
    {
        var lines = text.Split('\n');
        if (lines.Length == 0) return (string.Empty, string.Empty, string.Empty);

        var firstLine = lines[0].Trim();
        var parts = firstLine.Split(' ');
        var method = parts.Length > 0 ? parts[0] : string.Empty;
        var path = parts.Length > 1 ? parts[1] : string.Empty;

        return (method, path, text);
    }

    private static string ExtractHeader(string headers, string name)
    {
        var match = Regex.Match(headers, $@"{Regex.Escape(name)}:\s*(.+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
    }

    private static int GetBodySize(byte[] bytes, string headers)
    {
        var headerLen = headers.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (headerLen < 0) headerLen = headers.IndexOf("\n\n", StringComparison.Ordinal);
        if (headerLen < 0) return 0;
        return Math.Max(0, bytes.Length - headerLen - 4);
    }

    private static int ParseStatusCode(string responseText)
    {
        // "HTTP/1.1 200 OK"
        var match = Regex.Match(responseText, @"HTTP/\d\.\d\s+(\d{3})");
        return match.Success && int.TryParse(match.Groups[1].Value, out var code) ? code : 0;
    }

    private static bool IsSuspiciousUserAgent(string userAgent)
    {
        if (string.IsNullOrEmpty(userAgent)) return false;
        return SuspiciousUserAgents.Any(ua =>
            userAgent.Contains(ua, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasSuspiciousTld(string host)
    {
        return SuspiciousTlds.Any(tld =>
            host.EndsWith(tld, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsNonStandardPath(string path)
    {
        // Standard paths typically start with known prefixes
        if (string.IsNullOrEmpty(path) || path == "/") return false;
        // Paths with random-looking segments or no recognizable structure
        return !path.StartsWith("/api/") &&
               !path.StartsWith("/v1/") &&
               !path.StartsWith("/v2/") &&
               path.Length > 5;
    }

    private static bool IsPotentialExfil(byte[] requestBytes)
    {
        if (requestBytes.Length < 100) return false;
        var bodyStart = FindBodyStart(requestBytes);
        if (bodyStart < 0 || bodyStart >= requestBytes.Length) return false;

        var body = requestBytes[bodyStart..];
        if (body.Length < 50) return false;

        // Check if body is base64-like
        var bodyText = Encoding.ASCII.GetString(body[..Math.Min(256, body.Length)]);
        var base64Ratio = bodyText.Count(c =>
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=');

        return base64Ratio > body.Length * 0.8;
    }

    private static bool ContainsPeHeader(byte[] bytes)
    {
        var bodyStart = Math.Max(0, FindBodyStart(bytes));
        if (bodyStart >= bytes.Length - 2) return false;
        return bytes[bodyStart] == PeMagic[0] && bytes[bodyStart + 1] == PeMagic[1];
    }

    private static int FindBodyStart(byte[] bytes)
    {
        // Find \r\n\r\n
        for (var i = 0; i < bytes.Length - 3; i++)
        {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n' &&
                bytes[i + 2] == '\r' && bytes[i + 3] == '\n')
                return i + 4;
        }
        // Find \n\n
        for (var i = 0; i < bytes.Length - 1; i++)
        {
            if (bytes[i] == '\n' && bytes[i + 1] == '\n')
                return i + 2;
        }
        return -1;
    }

    private void ValidateAndFireCertAlert(string hostname, int port, X509Certificate2 cert, SslPolicyErrors policyErrors)
    {
        try
        {
            var now = DateTime.UtcNow;
            var isSelfSigned = cert.Subject == cert.Issuer;
            var isExpired = cert.NotAfter.ToUniversalTime() < now;

            var cnDns = cert.GetNameInfo(X509NameType.DnsName, false) ?? string.Empty;
            var isCnMismatch = !string.IsNullOrEmpty(hostname) &&
                               !cnDns.Equals(hostname, StringComparison.OrdinalIgnoreCase) &&
                               !cnDns.StartsWith("*.", StringComparison.OrdinalIgnoreCase) &&
                               !GetSanEntries(cert).Any(san => san.Equals(hostname, StringComparison.OrdinalIgnoreCase));

            var isUnknownCa = false;
            if (!isSelfSigned)
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.Build(cert);
                isUnknownCa = chain.ChainStatus.Any(s =>
                    s.Status == X509ChainStatusFlags.UntrustedRoot ||
                    s.Status == X509ChainStatusFlags.PartialChain);
            }

            var hasPolicyErrors = policyErrors != SslPolicyErrors.None;
            if (!isSelfSigned && !isExpired && !isCnMismatch && !isUnknownCa && !hasPolicyErrors) return;

            var dedupKey = $"{hostname}:{port}";
            if (_certAlertDedup.TryGetValue(dedupKey, out var last) && (now - last).TotalMinutes < 5) return;
            _certAlertDedup[dedupKey] = now;

            var errors = new List<string>();
            if (isSelfSigned) errors.Add("self-signed");
            if (isExpired) errors.Add("expired");
            if (isCnMismatch) errors.Add("CN mismatch");
            if (isUnknownCa) errors.Add("unknown CA");
            if (hasPolicyErrors) errors.Add(policyErrors.ToString());

            var alert = new TlsCertAlert
            {
                Id = Guid.NewGuid(),
                Hostname = hostname,
                Port = port,
                SubjectCn = cert.GetNameInfo(X509NameType.SimpleName, false) ?? string.Empty,
                IssuerCn = cert.GetNameInfo(X509NameType.SimpleName, true) ?? string.Empty,
                CertExpiresUtc = cert.NotAfter.ToUniversalTime(),
                IsSelfSigned = isSelfSigned,
                IsExpired = isExpired,
                IsCnMismatch = isCnMismatch,
                IsUnknownCa = isUnknownCa,
                ValidationError = string.Join("; ", errors),
                Severity = 7,
                DetectedAtUtc = now
            };

            _certAlertChannel.Writer.TryWrite(alert);
            _ = PersistAsync(alert);
            CertAlertDetected?.Invoke(this, new TlsCertAlertEventArgs(alert));
        }
        catch { }
    }

    // Per-write scope: AppDbContext is not thread-safe; alerts are raised from TLS proxy connection
    // threads. Persistence is optional (the repository may not be registered), so resolve it leniently.
    private async Task PersistAsync(TlsCertAlert alert)
    {
        if (_scopeFactory is null) return;
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var repository = scope.ServiceProvider.GetService<ITlsCertAlertRepository>();
            if (repository is not null)
                await repository.AddAsync(alert).ConfigureAwait(false);
        }
        catch { }
    }

    private static IEnumerable<string> GetSanEntries(X509Certificate2 cert)
    {
        try
        {
            var sanExt = cert.Extensions["2.5.29.17"];
            if (sanExt is null) return [];
            var text = sanExt.Format(false);
            return text.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(e => e.Trim())
                .Where(e => e.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                .Select(e => e["DNS Name=".Length..]);
        }
        catch { return []; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts?.Cancel();
        _cts?.Dispose();
        _listener?.Stop();
        _channel.Writer.TryComplete();
        _certAlertChannel.Writer.TryComplete();
        foreach (var cert in _certCache.Values)
            cert.Dispose();
        _certCache.Clear();
        _caCert?.Dispose();
    }
}
