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
        // elevated helper: the profile is typed/pasted here, inside the elevated process
        if (args.Any(a => a.Equals("--import-profile", StringComparison.OrdinalIgnoreCase)))
        {
            ApplicationConfiguration.Initialize();
            Environment.Exit(ImportProfileElevated());
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

    private static int ImportProfileElevated()
    {
        // no MainForm in this process: take the DPI scale from the screen
        try { using var g = System.Drawing.Graphics.FromHwnd(IntPtr.Zero); Theme.Scale = g.DpiX / 96f; } catch { }
        while (true)
        {
            string text;
            using (var dlg = new ProfileDialog())
            {
                if (dlg.ShowDialog() != DialogResult.OK) return 1;
                text = dlg.ProfileText;
            }
            if (string.IsNullOrWhiteSpace(text)) return 1;

            string error;
            try
            {
                ProfileParser.Parse(text); // quick local check
                var r = Ipc.Call(new GuardRequest { Cmd = "set-profile", Payload = text }, 90000);
                if (r.Ok)
                {
                    MessageBox.Show("Профиль применён:\n" + r.Profile?.Summary, "Claude Guard",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 0;
                }
                error = r.Error;
            }
            catch (Exception ex) { error = ex.Message; }

            if (MessageBox.Show("Профиль не применён:\n" + error + "\n\nПопробовать другой?", "Claude Guard",
                    MessageBoxButtons.RetryCancel, MessageBoxIcon.Error) != DialogResult.Retry)
                return 1;
        }
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
