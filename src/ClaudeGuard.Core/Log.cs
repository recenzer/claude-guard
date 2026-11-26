using System.Text;

namespace ClaudeGuard.Core;

public static class Log
{
    private static readonly object Sync = new();
    private static readonly Queue<LogEvent> Ring = new();
    private const int RingSize = 600;

    private static string _dir;
    private static string _file;
    private static DateTime _fileDate;
    private static bool _console;
    private static int _retentionDays = 14;

    public static void Init(string dir, int retentionDays = 14, bool console = false)
    {
        lock (Sync)
        {
            _dir = dir;
            _retentionDays = retentionDays <= 0 ? 14 : retentionDays;
            _console = console;
            try
            {
                Directory.CreateDirectory(_dir);
                RotateIfNeeded();
                CleanupOldFiles();
            }
            catch { /* журнал не должен ронять сервис */ }
        }
    }

    public static void Write(string level, string code, string message)
    {
        var ev = new LogEvent(DateTimeOffset.Now, level, code, message ?? "");
        lock (Sync)
        {
            Ring.Enqueue(ev);
            while (Ring.Count > RingSize) Ring.Dequeue();

            try
            {
                if (_dir == null) return;
                RotateIfNeeded();
                var line = $"{ev.Ts:yyyy-MM-ddTHH:mm:ss.fffzzz} | {level,-5} | {code} | {message}";
                File.AppendAllText(_file, line + Environment.NewLine, new UTF8Encoding(false));
            }
            catch { }
        }

        if (_console)
        {
            Console.WriteLine($"{ev.Ts:HH:mm:ss} [{level}] {code}: {message}");
        }
    }

    public static void Info(string code, string message) => Write("INFO", code, message);
    public static void Warn(string code, string message) => Write("WARN", code, message);
    public static void Error(string code, string message) => Write("ERROR", code, message);
    public static void Critical(string code, string message) => Write("CRIT", code, message);

    public static LogEvent[] Tail(int count)
    {
        lock (Sync)
        {
            count = Math.Clamp(count, 1, RingSize);
            return Ring.Reverse().Take(count).Reverse().ToArray();
        }
    }

    public static string CurrentFile
    {
        get { lock (Sync) return _file; }
    }

    private static void RotateIfNeeded()
    {
        var today = DateTime.Now.Date;
        if (_file != null && _fileDate == today) return;
        var dayChanged = _file != null;
        _fileDate = today;
        _file = Path.Combine(_dir, $"guard-{today:yyyyMMdd}.log");
        // the service runs for weeks: clean up on every day change, not only at startup
        if (dayChanged) CleanupOldFiles();
    }

    private static void CleanupOldFiles()
    {
        try
        {
            var cutoff = DateTime.Now.AddDays(-_retentionDays);
            foreach (var f in Directory.GetFiles(_dir, "guard-*.log"))
            {
                if (File.GetLastWriteTime(f) < cutoff) File.Delete(f);
            }
        }
        catch { }
    }
}
