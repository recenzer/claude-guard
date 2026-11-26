using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

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

    /// <summary>
    /// Proxy probe: SOCKS5 (user/password) to the local sing-box inbound, CONNECT by domain name
    /// (DNS is resolved on the proxy side), then a TLS handshake with the target.
    /// Success means the proxy outbound really carries traffic.
    /// </summary>
    public static ProbeResult RunViaSocks(IPEndPoint proxy, string user, string pass, ProbeTarget target, int timeoutMs)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var label = $"{target.Host}:{target.Port}";
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            var ar = socket.BeginConnect(proxy, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(Math.Min(timeoutMs, 2000)))
                return ProbeResult.Fail(ReasonCodes.ProbeTimeout, "локальный SOCKS sing-box не отвечает", (int)sw.ElapsedMilliseconds, label);
            socket.EndConnect(ar);

            int Remaining() => Math.Max(500, timeoutMs - (int)sw.ElapsedMilliseconds);
            socket.SendTimeout = Remaining();
            socket.ReceiveTimeout = Remaining();

            // greeting: version 5, one method: username/password (0x02)
            socket.Send(new byte[] { 5, 1, 2 });
            var resp = ReadExact(socket, 2);
            if (resp[0] != 5 || resp[1] != 2)
                return ProbeResult.Fail(ReasonCodes.ProbeTimeout, $"SOCKS: метод отклонён ({resp[1]})", (int)sw.ElapsedMilliseconds, label);

            var u = Encoding.UTF8.GetBytes(user);
            var p = Encoding.UTF8.GetBytes(pass);
            var auth = new byte[3 + u.Length + p.Length];
            auth[0] = 1; auth[1] = (byte)u.Length; u.CopyTo(auth, 2);
            auth[2 + u.Length] = (byte)p.Length; p.CopyTo(auth, 3 + u.Length);
            socket.Send(auth);
            resp = ReadExact(socket, 2);
            if (resp[1] != 0)
                return ProbeResult.Fail(ReasonCodes.ProbeTimeout, "SOCKS: авторизация отклонена", (int)sw.ElapsedMilliseconds, label);

            // CONNECT by domain name
            socket.ReceiveTimeout = Remaining();
            var host = Encoding.ASCII.GetBytes(target.Host);
            var req = new byte[7 + host.Length];
            req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = (byte)host.Length;
            host.CopyTo(req, 5);
            req[5 + host.Length] = (byte)(target.Port >> 8);
            req[6 + host.Length] = (byte)(target.Port & 0xFF);
            socket.Send(req);

            var head = ReadExact(socket, 4);
            if (head[1] != 0)
            {
                var code = head[1] == 5 ? ReasonCodes.ProbeRefused : ReasonCodes.ProbeTimeout;
                return ProbeResult.Fail(code, $"прокси не смог подключиться (SOCKS reply {head[1]})", (int)sw.ElapsedMilliseconds, label);
            }
            var skip = head[3] switch
            {
                1 => 4 + 2,
                4 => 16 + 2,
                3 => ReadExact(socket, 1)[0] + 2,
                _ => 0
            };
            if (skip > 0) ReadExact(socket, skip);

            socket.ReceiveTimeout = 0;
            socket.SendTimeout = 0;
            using var ssl = new SslStream(new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false);
            using var cts = new CancellationTokenSource(Remaining());
            ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            }, cts.Token).GetAwaiter().GetResult();

            return new ProbeResult
            {
                Ok = true,
                Code = "PROBE_OK",
                Message = $"TLS через прокси OK ({ssl.SslProtocol})",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                Target = label
            };
        }
        catch (OperationCanceledException)
        {
            return ProbeResult.Fail(ReasonCodes.ProbeTimeout, "таймаут TLS через прокси", (int)sw.ElapsedMilliseconds, label);
        }
        catch (AuthenticationException ex)
        {
            return ProbeResult.Fail(ReasonCodes.ProbeTlsFailed, "TLS: " + ex.Message, (int)sw.ElapsedMilliseconds, label);
        }
        catch (SocketException ex)
        {
            return ProbeResult.Fail(MapSocketError(ex.SocketErrorCode), $"{ex.SocketErrorCode}: {ex.Message}", (int)sw.ElapsedMilliseconds, label);
        }
        catch (Exception ex)
        {
            return ProbeResult.Fail(ReasonCodes.ProbeTimeout, ex.Message, (int)sw.ElapsedMilliseconds, label);
        }
    }

    private static byte[] ReadExact(Socket s, int n)
    {
        var buf = new byte[n];
        int got = 0;
        while (got < n)
        {
            var r = s.Receive(buf, got, n - got, SocketFlags.None);
            if (r <= 0) throw new IOException("SOCKS: соединение закрыто");
            got += r;
        }
        return buf;
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
