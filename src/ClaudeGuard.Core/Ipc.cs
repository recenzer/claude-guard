using System.ComponentModel;
using System.Runtime.InteropServices;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ClaudeGuard.Core;

public sealed class GuardRequest
{
    public string Cmd { get; set; } = "";
    public int Count { get; set; } = 200;
    /// <summary>Command argument, e.g. a profile link/JSON for "set-profile".</summary>
    public string Payload { get; set; } = "";
}

public sealed class GuardResponse
{
    public bool Ok { get; set; }
    public string Error { get; set; } = "";
    public GuardStatus Status { get; set; }
    public LogEvent[] Log { get; set; }
    public SelfTestResult SelfTest { get; set; }
    public ProfileResult Profile { get; set; }
    public string Version { get; set; } = ProgramInfo.Version;
}

/// <summary>Локальный IPC через именованный канал с SDDL-ACL (без прав администратора у UI).</summary>
public static class Ipc
{
    public const string PipeName = "ClaudeGuard.v1";
    internal const string Sddl = "D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGW;;;AU)";

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static GuardResponse Call(GuardRequest req, int timeoutMs = 60000)
    {
        using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Identification);
        client.Connect(timeoutMs);
        using var writer = new StreamWriter(client, new UTF8Encoding(false), 8192, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(client, new UTF8Encoding(false), false, 8192, leaveOpen: true);
        writer.WriteLine(JsonSerializer.Serialize(req, Json));
        var line = reader.ReadLine();
        if (line == null) throw new IOException("Служба закрыла канал без ответа");
        return JsonSerializer.Deserialize<GuardResponse>(line, Json) ?? throw new IOException("Пустой ответ службы");
    }

    public static bool IsServiceAvailable()
    {
        try
        {
            var r = Call(new GuardRequest { Cmd = "ping" }, 1500);
            return r.Ok;
        }
        catch { return false; }
    }
}

public sealed class PipeServer : IDisposable
{
    private readonly Func<GuardRequest, bool, GuardResponse> _dispatch;
    private readonly CancellationTokenSource _cts = new();
    private Thread _thread;

    public PipeServer(Func<GuardRequest, bool, GuardResponse> dispatch) => _dispatch = dispatch;

    public void Start()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "guard-ipc" };
        _thread.Start();
    }

    public void Dispose()
    {
        _cts.Cancel();
        // разбудить поток, заблокированный в WaitForConnection
        try
        {
            using var c = new NamedPipeClientStream(".", Ipc.PipeName, PipeDirection.InOut);
            c.Connect(300);
        }
        catch { }
        try { _thread?.Join(1000); } catch { }
    }

    private void Loop()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream server = null;
            try
            {
                server = CreateInstance();
                server.WaitForConnection();
                var s = server;
                server = null;
                _ = Task.Run(() => Handle(s));
            }
            catch (Exception ex)
            {
                if (!_cts.IsCancellationRequested)
                    Log.Error("IPC_ACCEPT", ex.Message);
                try { server?.Dispose(); } catch { }
                Thread.Sleep(300);
            }
        }
    }

    private void Handle(NamedPipeServerStream server)
    {
        try
        {
            using (server)
            {
                bool elevated = IsClientElevated(server.SafePipeHandle);
                using var reader = new StreamReader(server, new UTF8Encoding(false), false, 8192, leaveOpen: true);
                using var writer = new StreamWriter(server, new UTF8Encoding(false), 8192, leaveOpen: true) { AutoFlush = true };

                var readTask = reader.ReadLineAsync();
                if (!readTask.Wait(10000))
                {
                    WriteError(writer, "TIMEOUT", "нет запроса");
                    return;
                }
                var line = readTask.Result;
                if (line == null) return;

                GuardRequest req;
                try { req = JsonSerializer.Deserialize<GuardRequest>(line, Ipc.Json) ?? new GuardRequest(); }
                catch (Exception ex) { WriteError(writer, "BAD_REQUEST", ex.Message); return; }

                GuardResponse resp;
                try { resp = _dispatch(req, elevated) ?? new GuardResponse { Ok = false, Error = "no response" }; }
                catch (Exception ex) { resp = new GuardResponse { Ok = false, Error = ex.Message }; }

                writer.WriteLine(JsonSerializer.Serialize(resp, Ipc.Json));
                // не закрывать канал, пока клиент не прочитал ответ
                try { server.WaitForPipeDrain(); } catch { }
            }
        }
        catch (Exception ex)
        {
            Log.Error("IPC_HANDLE", ex.Message);
        }
    }

    private static void WriteError(StreamWriter w, string code, string msg)
    {
        try { w.WriteLine(JsonSerializer.Serialize(new GuardResponse { Ok = false, Error = $"{code}: {msg}" }, Ipc.Json)); } catch { }
    }

    // ---------- Win32 ----------

    private const uint PipeAccessDuplex = 0x00000003;
    private const uint PipeTypeByte = 0x00000000;
    private const uint PipeReadmodeByte = 0x00000000;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemote = 0x00000008;
    private const uint UnlimitedInstances = 255;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateNamedPipeW(string lpName, uint dwOpenMode, uint dwPipeMode,
        uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, ref SECURITY_ATTRIBUTES lpSecurityAttributes);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl,
        uint revision, out IntPtr sd, out uint sdSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, out int info, int len, out int retLen);

    private static NamedPipeServerStream CreateInstance()
    {
        IntPtr sd = IntPtr.Zero;
        try
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Ipc.Sddl, 1, out sd, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SDDL");

            var sa = new SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                lpSecurityDescriptor = sd,
                bInheritHandle = false
            };

            var name = $@"\\.\pipe\{Ipc.PipeName}";
            var handle = CreateNamedPipeW(name,
                PipeAccessDuplex, PipeTypeByte | PipeReadmodeByte | PipeWait | PipeRejectRemote,
                UnlimitedInstances, 65536, 65536, 0, ref sa);

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateNamedPipe");

            var safe = new SafePipeHandle(handle, ownsHandle: true);
            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: false, isConnected: false, safe);
        }
        finally
        {
            if (sd != IntPtr.Zero)
            {
                try { LocalFree(sd); } catch { }
            }
        }
    }

    private static bool IsClientElevated(SafePipeHandle pipe)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(pipe, out var pid)) return false;
            var h = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
            if (h == IntPtr.Zero) return false;
            try
            {
                if (!OpenProcessToken(h, 0x0008, out var token)) return false; // TOKEN_QUERY
                try
                {
                    if (!GetTokenInformation(token, 20 /*TokenElevation*/, out var elevated, sizeof(int), out _)) return false;
                    return elevated != 0;
                }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(h); }
        }
        catch { return false; }
    }
}
