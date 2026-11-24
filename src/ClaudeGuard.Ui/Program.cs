using ClaudeGuard.Core;

namespace ClaudeGuard.Ui;

internal static class Program
{
    // Local\ — отдельный экземпляр на сеанс пользователя (Global\ мешал бы другим учётным записям)
    private const string MutexName = @"Local\ClaudeGuardUi";
    private const string ShowEventName = @"Local\ClaudeGuardUi.Show";

    [STAThread]
    private static void Main(string[] args)
    {
        // служебный режим: запросить паузу/возобновление с повышением прав
        if (args.Any(a => a.Equals("--pause", StringComparison.OrdinalIgnoreCase)))
        {
            Environment.Exit(Elevated("pause"));
            return;
        }
        if (args.Any(a => a.Equals("--resume", StringComparison.OrdinalIgnoreCase)))
        {
            Environment.Exit(Elevated("resume"));
            return;
        }

        using var mutex = new Mutex(true, MutexName, out bool created);
        if (!created)
        {
            // вместо сообщения — поднять окно уже запущенного экземпляра
            try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { }
            return;
        }

        ApplicationConfiguration.Initialize();

        var form = new MainForm();
        using var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        var watcher = new Thread(() =>
        {
            while (showEvent.WaitOne())
            {
                try { form.BeginInvoke(new Action(form.RestoreWindow)); } catch { }
            }
        })
        { IsBackground = true, Name = "show-watcher" };
        watcher.Start();

        Application.Run(form);
        GC.KeepAlive(mutex);
    }

    private static int Elevated(string cmd)
    {
        try
        {
            var r = Ipc.Call(new GuardRequest { Cmd = cmd }, 5000);
            return r.Ok ? 0 : 1;
        }
        catch { return 2; }
    }
}
