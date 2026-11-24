using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace ClaudeGuard.Core;

public sealed class ProbeResult
{
    public bool Ok { get; set; }
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public int ElapsedMs { get; set; }
    public string Target { get; set; } = "";
    public string RemoteIp { get; set; } = "";

    public static ProbeResult Fail(string code, string msg, int ms = 0, string target = "", string ip = "")
        => new() { Ok = false, Code = code, Message = msg, ElapsedMs = ms, Target = target, RemoteIp = ip };
}

/// <summary>
/// Активная проверка туннеля: TCP + TLS-рукопожатие к внешнему хосту,
/// сокет принудительно привязан к IP-адресу TUN-интерфейса.
/// Это проверяет не «процесс запущен», а реальную передачу данных через туннель.
/// </summary>
public static class TunnelProbe
{
    public static ProbeResult Run(IPAddress bindAddress, ProbeTarget target, int timeoutMs, int forceIfIndex = 0)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var label = $"{target.Host}:{target.Port}";
        IPAddress[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(target.Host)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Distinct()
                .Take(4)
                .ToArray();
        }
        catch (Exception ex)
        {
            return ProbeResult.Fail(ReasonCodes.ProbeDnsFailed, "DNS: " + ex.Message, (int)sw.ElapsedMilliseconds, label);
        }

        if (addresses.Length == 0)
            return ProbeResult.Fail(ReasonCodes.ProbeDnsFailed, "нет IPv4-адресов", (int)sw.ElapsedMilliseconds, label);

        string lastCode = ReasonCodes.ProbeTimeout;
        string lastMsg = "нет попыток";
        string lastIp = "";

        foreach (var ip in addresses)
        {
            lastIp = ip.ToString();
            var remaining = timeoutMs - (int)sw.ElapsedMilliseconds;
            if (remaining < 500) break;

            Socket socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                socket.Bind(new IPEndPoint(bindAddress, 0));
                if (forceIfIndex > 0)
                {
                    // IP_UNICAST_IF: жёстко выбрать исходящий интерфейс (значение в network byte order),
                    // иначе маршрут по умолчанию через TUN перехватит и физическую пробу.
                    socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31,
                        IPAddress.HostToNetworkOrder(forceIfIndex));
                }

                var ar = socket.BeginConnect(new IPEndPoint(ip, target.Port), null, null);
                if (!ar.AsyncWaitHandle.WaitOne(remaining))
                {
                    lastCode = ReasonCodes.ProbeTimeout;
                    lastMsg = $"таймаут TCP {remaining} мс";
                    try { socket.Close(); } catch { }
                    continue;
                }
                socket.EndConnect(ar);

                var tlsRemaining = timeoutMs - (int)sw.ElapsedMilliseconds;
                if (tlsRemaining < 500) tlsRemaining = 500;

                using var ssl = new SslStream(new NetworkStream(socket, ownsSocket: true), leaveInnerStreamOpen: false);
                using var cts = new CancellationTokenSource(tlsRemaining);
                var opts = new SslClientAuthenticationOptions
                {
                    TargetHost = target.Host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                };
                ssl.AuthenticateAsClientAsync(opts, cts.Token).GetAwaiter().GetResult();

                sw.Stop();
                return new ProbeResult
                {
                    Ok = true,
                    Code = "PROBE_OK",
                    Message = $"TLS OK ({ssl.SslProtocol})",
                    ElapsedMs = (int)sw.ElapsedMilliseconds,
                    Target = label,
                    RemoteIp = ip.ToString()
                };
            }
            catch (OperationCanceledException)
            {
                lastCode = ReasonCodes.ProbeTimeout;
                lastMsg = "таймаут TLS";
            }
            catch (AuthenticationException ex)
            {
                lastCode = ReasonCodes.ProbeTlsFailed;
                lastMsg = "TLS: " + ex.Message;
            }
            catch (SocketException ex)
            {
                lastCode = MapSocketError(ex.SocketErrorCode);
                lastMsg = $"{ex.SocketErrorCode}: {ex.Message}";
                if (ex.SocketErrorCode == SocketError.AddressNotAvailable ||
                    ex.SocketErrorCode == SocketError.AddressFamilyNotSupported)
                {
                    // привязка к TUN невозможна — это критично, дальше пробовать бессмысленно
                    sw.Stop();
                    return ProbeResult.Fail(ReasonCodes.ProbeTunBlocked, lastMsg, (int)sw.ElapsedMilliseconds, label, lastIp);
                }
            }
            catch (Exception ex)
            {
                lastCode = ReasonCodes.ProbeTimeout;
                lastMsg = ex.Message;
            }
            finally
            {
                try { socket?.Dispose(); } catch { }
            }
        }

        sw.Stop();
        return ProbeResult.Fail(lastCode, lastMsg, (int)sw.ElapsedMilliseconds, label, lastIp);
    }

    private static string MapSocketError(SocketError e) => e switch
    {
        SocketError.TimedOut => ReasonCodes.ProbeTimeout,
        SocketError.ConnectionRefused => ReasonCodes.ProbeRefused,
        SocketError.HostUnreachable => ReasonCodes.ProbeTimeout,
        SocketError.NetworkUnreachable => ReasonCodes.ProbeTimeout,
        SocketError.NetworkDown => ReasonCodes.ProbeTimeout,
        _ => ReasonCodes.ProbeTimeout
    };
}
