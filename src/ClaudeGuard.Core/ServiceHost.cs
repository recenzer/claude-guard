using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ClaudeGuard.Core;

/// <summary>Минимальный хост Windows-службы без внешних зависимостей (P/Invoke advapi32).</summary>
public static class ServiceHost
{
    private const int ServiceWin32OwnProcess = 0x00000010;
    private const int ServiceAcceptStop = 0x00000001;
    private const int ServiceAcceptShutdown = 0x00000004;
    private const int ServiceRunning = 0x00000004;
    private const int ServiceStartPending = 0x00000002;
    private const int ServiceStopPending = 0x00000003;
    private const int ServiceStopped = 0x00000001;
    private const int ErrorFailedServiceControllerConnect = 1063;

    private const int ControlStop = 1;
    private const int ControlInterrogate = 4;
    private const int ControlShutdown = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public int dwServiceType;
        public int dwCurrentState;
        public int dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceTableEntry
    {
        public IntPtr lpServiceName;
        public IntPtr lpServiceProc;
    }

    private delegate int ServiceControlHandlerEx(int control, int eventType, IntPtr eventData, IntPtr context);
    private delegate void ServiceMainFunction(int numArgs, IntPtr argPtr);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] entries);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, ServiceControlHandlerEx handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus status);

    private static IntPtr _statusHandle = IntPtr.Zero;
    private static ManualResetEventSlim _stopEvent;
    private static ServiceStatus _status;

    /// <summary>Возвращает false, если процесс запущен не SCM (обычный консольный режим).</summary>
    public static bool TryRun(string serviceName, Action<ManualResetEventSlim> run)
    {
        _stopEvent = new ManualResetEventSlim(false);

        var mainDelegate = new ServiceMainFunction((argc, argv) => ServiceMain(serviceName, run));
        var namePtr = Marshal.StringToHGlobalUni(serviceName);
        var entries = new ServiceTableEntry[2];
        entries[0].lpServiceName = namePtr;
        entries[0].lpServiceProc = Marshal.GetFunctionPointerForDelegate(mainDelegate);
        entries[1].lpServiceName = IntPtr.Zero;
        entries[1].lpServiceProc = IntPtr.Zero;

        try
        {
            if (StartServiceCtrlDispatcher(entries)) return true;
            var err = Marshal.GetLastWin32Error();
            if (err == ErrorFailedServiceControllerConnect) return false;
            throw new Win32Exception(err, "StartServiceCtrlDispatcher");
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            GC.KeepAlive(mainDelegate);
        }
    }

    private static void ServiceMain(string serviceName, Action<ManualResetEventSlim> run)
    {
        var handlerDelegate = new ServiceControlHandlerEx((control, eventType, data, ctx) =>
        {
            switch (control)
            {
                case ControlStop:
                case ControlShutdown:
                    ReportStatus(ServiceStopPending, 0, 20000);
                    _stopEvent.Set();
                    return 0;
                case ControlInterrogate:
                    return 0;
                default:
                    return 0;
            }
        });

        _statusHandle = RegisterServiceCtrlHandlerEx(serviceName, handlerDelegate, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
        {
            Log.Critical("SERVICE_HANDLER", "RegisterServiceCtrlHandlerEx failed: " + Marshal.GetLastWin32Error());
            return;
        }

        ReportStatus(ServiceStartPending, 0, 10000);
        ReportStatus(ServiceRunning, 0, 0);

        try
        {
            run(_stopEvent);
        }
        catch (Exception ex)
        {
            Log.Critical("SERVICE_RUN", ex.ToString());
        }
        finally
        {
            ReportStatus(ServiceStopped, 0, 0);
            GC.KeepAlive(handlerDelegate);
        }
    }

    private static void ReportStatus(int state, int exitCode, int waitHint)
    {
        _status.dwServiceType = ServiceWin32OwnProcess;
        _status.dwCurrentState = state;
        _status.dwControlsAccepted = state == ServiceRunning ? (ServiceAcceptStop | ServiceAcceptShutdown) : 0;
        _status.dwWin32ExitCode = exitCode;
        _status.dwCheckPoint = 0;
        _status.dwWaitHint = waitHint;
        if (_statusHandle != IntPtr.Zero) SetServiceStatus(_statusHandle, ref _status);
    }
}
