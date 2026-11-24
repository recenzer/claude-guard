using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using ClaudeGuard.Core;

namespace ClaudeGuard.Service;

internal static class Program
{
    private const string ServiceName = "ClaudeGuard";

    private static int Main(string[] args)
    {
        var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "--service";
        try
        {
            Directory.SetCurrentDirectory(AppContext.BaseDirectory);
            switch (mode)
            {
                case "--version":
                    Console.WriteLine(ProgramInfo.Version);
                    return 0;
                case "--selftest":
                    return RunSelfTest();
                case "--remove-rules":
                    return RemoveRules();
                case "--status":
                    return PrintStatus();
                case "--watchdog":
                    return Watchdog();
                case "--console":
                    return RunConsole();
                case "--service":
                default:
                    return RunService();
            }
        }
        catch (Exception ex)
        {
            try { Log.Critical("FATAL", ex.ToString()); } catch { }
            Console.Error.WriteLine(ex);
            return 99;
        }
    }

    private static bool IsAdmin()
        => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    private static int RunService()
    {
        var cfg = Config.Load();
        Log.Init(cfg.LogDir, cfg.LogRetentionDays, console: false);
        Log.Info("SERVICE_BOOT", $"Запуск службы, admin={IsAdmin()}");

        if (!IsAdmin())
        {
            Log.Critical("NOT_ADMIN", "Служба запущена без прав администратора — управление firewall невозможно");
            return 5;
        }

        var started = ServiceHost.TryRun(ServiceName, stopEvent =>
        {
            RunCore(cfg, stopEvent);
        });

        if (!started)
        {
            // запущено вручную, не через SCM — работаем как консоль
            Log.Warn("NOT_SCM", "Процесс запущен не через SCM, перехожу в консольный режим");
            return RunConsole();
        }
        return 0;
    }

    private static int RunConsole()
    {
        var cfg = Config.Load();
        Log.Init(cfg.LogDir, cfg.LogRetentionDays, console: true);
        var stop = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Set(); };
        RunCore(cfg, stop);
        return 0;
    }

    private static void RunCore(Config cfg, ManualResetEventSlim stopEvent)
    {
        var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "ClaudeGuard.Service.exe");
        using var engine = new GuardEngine(cfg, exe);
        using var pipe = new PipeServer((req, elevated) => Dispatch(req, elevated, engine));

        engine.Start();
        pipe.Start();
        Log.Info("SERVICE_READY", "Служба готова, IPC запущен");

        stopEvent.Wait();

        Log.Info("SERVICE_STOP", "Остановка службы");
        try { pipe.Dispose(); } catch { }
        try { engine.Stop(); } catch { }
    }

    private static GuardResponse Dispatch(GuardRequest req, bool elevated, GuardEngine engine)
    {
        var cmd = (req.Cmd ?? "").Trim().ToLowerInvariant();
        switch (cmd)
        {
            case "ping":
                return new GuardResponse { Ok = true };
            case "status":
                return new GuardResponse { Ok = true, Status = engine.GetStatus() };
            case "log":
                return new GuardResponse { Ok = true, Log = Log.Tail(req.Count <= 0 ? 200 : req.Count) };
            case "pause":
                if (!elevated) return new GuardResponse { Ok = false, Error = "ELEVATION_REQUIRED" };
                engine.Pause("UI (elevated)");
                return new GuardResponse { Ok = true, Status = engine.GetStatus() };
            case "resume":
                engine.Resume("UI");
                return new GuardResponse { Ok = true, Status = engine.GetStatus() };
            case "check":
                engine.CheckNow();
                return new GuardResponse { Ok = true, Status = engine.GetStatus() };
            case "restart-claude":
                engine.RequestRestartClaude();
                return new GuardResponse { Ok = true, Status = engine.GetStatus() };
            case "ack-restart":
                engine.AcknowledgeRestart();
                return new GuardResponse { Ok = true, Status = engine.GetStatus() };
            case "selftest":
                if (!elevated) return new GuardResponse { Ok = false, Error = "ELEVATION_REQUIRED" };
                return new GuardResponse { Ok = true, SelfTest = engine.RunSelfTest() };
            default:
                return new GuardResponse { Ok = false, Error = "UNKNOWN_CMD: " + cmd };
        }
    }

    // ---------------- вспомогательные режимы ----------------

    private static int RunSelfTest()
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("Нужны права администратора");
            return 2;
        }
        var cfg = Config.Load();
        Log.Init(cfg.LogDir, cfg.LogRetentionDays, console: false);
        Log.Info("SELFTEST_START", "Самопроверка firewall/туннеля");

        var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "ClaudeGuard.Service.exe");
        using var engine = new GuardEngine(cfg, exe);
        engine.Start();

        // ждём сканирования Claude
        for (int i = 0; i < 50 && !engine.IsReady; i++) Thread.Sleep(100);

        var result = engine.RunSelfTest();
        Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        Log.Info("SELFTEST_RESULT", $"ok={result.Ok} error={result.Error}");
        engine.Stop();
        return result.Ok ? 0 : 1;
    }

    private static int RemoveRules()
    {
        if (!IsAdmin()) return 2;
        var cfg = Config.Load();
        Log.Init(cfg.LogDir, cfg.LogRetentionDays, console: true);
        using var fw = new Firewall();
        fw.RemoveAll();
        Log.Warn("RULES_REMOVED", "Все правила Claude Guard удалены");
        return 0;
    }

    private static int PrintStatus()
    {
        try
        {
            var r = Ipc.Call(new GuardRequest { Cmd = "status" }, 3000);
            Console.WriteLine(JsonSerializer.Serialize(r, Ipc.Json));
            return r.Ok ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Служба недоступна: " + ex.Message);
            return 3;
        }
    }

    private static int Watchdog()
    {
        var cfg = Config.Load();
        Log.Init(cfg.LogDir, cfg.LogRetentionDays, console: false);

        if (Ipc.IsServiceAvailable())
        {
            return 0;
        }

        Log.Warn("WATCHDOG_START", "Служба не отвечает — пробую запустить");
        try
        {
            var psi = new ProcessStartInfo("sc.exe", "start ClaudeGuard")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(15000);
        }
        catch (Exception ex)
        {
            Log.Error("WATCHDOG_SC", ex.Message);
        }

        for (int i = 0; i < 20; i++)
        {
            Thread.Sleep(500);
            if (Ipc.IsServiceAvailable()) return 0;
        }

        // служба не поднимается — переводим защиту в fail-closed вручную
        Log.Critical("WATCHDOG_FAILSAFE", "Служба недоступна — включаю аварийную блокировку всех интерфейсов");
        try
        {
            var dir = ClaudeApp.FindInstallDir(cfg);
            var exes = ClaudeApp.EnumerateExecutables(dir);
            if (exes.Count > 0)
            {
                using var fw = new Firewall();
                var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "ClaudeGuard.Service.exe");
                var specs = Firewall.BuildSpecs(exes, new[] { exe }, blockAll: true);
                if (fw.Apply(specs, out var err)) Log.Critical("WATCHDOG_BLOCKED", "Аварийная блокировка применена");
                else Log.Critical("WATCHDOG_BLOCK_FAILED", err);
            }
        }
        catch (Exception ex)
        {
            Log.Critical("WATCHDOG_BLOCK_EX", ex.ToString());
        }
        return 1;
    }
}
