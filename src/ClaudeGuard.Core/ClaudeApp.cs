using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ClaudeGuard.Core;

public static class ClaudeApp
{
    private const string WindowsApps = @"C:\Program Files\WindowsApps";

    public static string FindInstallDir(Config cfg)
    {
        if (!string.IsNullOrWhiteSpace(cfg.ClaudeInstallDirOverride) && Directory.Exists(cfg.ClaudeInstallDirOverride))
            return cfg.ClaudeInstallDirOverride;

        // 1) если Claude запущен — берём путь из живого процесса (самый достоверный источник)
        try
        {
            foreach (var p in Process.GetProcessesByName("claude"))
            {
                try
                {
                    var path = p.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path) && path.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase))
                    {
                        // нужен корень пакета (Claude_x.y_x64__id), а не подпапка app\ —
                        // иначе путь «плавает» между запущенным и остановленным Claude
                        var root = PackageRoot(path);
                        if (!string.IsNullOrEmpty(root)) return root;
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        // 2) реестр зарегистрированных пакетов (доступен службе SYSTEM через HKEY_USERS).
        //    Каталог WindowsApps перечислять нельзя (ACL), но PackageRootFolder читается.
        var regDir = FindInRegistry(cfg.ClaudePackageFamilyName);
        if (!string.IsNullOrEmpty(regDir) && Directory.Exists(regDir)) return regDir;

        // 3) иначе — самый новый каталог пакета (может не работать из-за ACL WindowsApps)
        try
        {
            var publisher = PublisherId(cfg.ClaudePackageFamilyName);
            var dirs = Directory.GetDirectories(WindowsApps, $"Claude_*__{publisher}");
            if (dirs.Length == 0) return "";
            return dirs
                .Select(d => (dir: d, ver: ParseVersion(Path.GetFileName(d))))
                .OrderByDescending(x => x.ver)
                .First().dir;
        }
        catch
        {
            return "";
        }
    }

    private static string PackageRoot(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        while (!string.IsNullOrEmpty(dir))
        {
            var name = Path.GetFileName(dir);
            if (name.StartsWith("Claude_", StringComparison.OrdinalIgnoreCase) && name.Contains("__"))
                return dir;
            dir = Path.GetDirectoryName(dir);
        }
        return "";
    }

    /// <summary>PackageFamilyName (Claude_pzs8sxrjxfjjc) → publisher id (pzs8sxrjxfjjc).</summary>
    private static string PublisherId(string packageFamilyName)
    {
        if (string.IsNullOrWhiteSpace(packageFamilyName)) return "";
        var i = packageFamilyName.IndexOf('_');
        return i >= 0 ? packageFamilyName[(i + 1)..] : packageFamilyName;
    }

    /// <summary>
    /// Ищет каталог пакета в репозитории AppModel: текущий профиль и все загруженные
    /// профили (HKEY_USERS). Так служба SYSTEM находит Claude, даже если он не запущен.
    /// </summary>
    private static string FindInRegistry(string packageFamilyName)
    {
        if (string.IsNullOrWhiteSpace(packageFamilyName)) return "";
        var publisher = PublisherId(packageFamilyName);
        var found = new List<string>();

        void Scan(RegistryKey root)
        {
            try
            {
                using var repo = root.OpenSubKey(
                    @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
                if (repo == null) return;
                foreach (var name in repo.GetSubKeyNames())
                {
                    if (!name.StartsWith("Claude_", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!string.IsNullOrEmpty(publisher) &&
                        !name.EndsWith("__" + publisher, StringComparison.OrdinalIgnoreCase)) continue;
                    using var pkg = repo.OpenSubKey(name);
                    if (pkg?.GetValue("PackageRootFolder") is string path && !string.IsNullOrWhiteSpace(path))
                        found.Add(path);
                }
            }
            catch { }
        }

        Scan(Registry.CurrentUser);

        try
        {
            foreach (var sid in Registry.Users.GetSubKeyNames())
            {
                if (sid is ".DEFAULT" or "S-1-5-18" or "S-1-5-19" or "S-1-5-20") continue;
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    using var profile = Registry.Users.OpenSubKey(sid);
                    if (profile != null) Scan(profile);
                }
                catch { }
            }
        }
        catch { }

        return found
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(d => (dir: d, ver: ParseVersion(Path.GetFileName(d))))
            .OrderByDescending(x => x.ver)
            .Select(x => x.dir)
            .FirstOrDefault() ?? "";
    }

    private static Version ParseVersion(string folder)
    {
        // Claude_6.28899.6.0_x64__pzs8sxrjxfjjc
        try
        {
            var m = Regex.Match(folder, @"^Claude_(\d+(?:\.\d+){1,3})_");
            if (m.Success) return Version.Parse(m.Groups[1].Value);
        }
        catch { }
        return new Version(0, 0);
    }

    public static List<string> EnumerateExecutables(string installDir)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(installDir) || !Directory.Exists(installDir)) return list;
        try
        {
            foreach (var f in Directory.EnumerateFiles(installDir, "*.exe", SearchOption.AllDirectories))
                list.Add(f);
        }
        catch { }
        list.Sort(StringComparer.OrdinalIgnoreCase);
        return list;
    }

    /// <summary>Процессы самого Claude Desktop (claude.exe и его дочерние), не службы вроде CoworkVMService.</summary>
    public static List<Process> GetDesktopProcesses(string installDir)
    {
        var result = new List<Process>();
        if (string.IsNullOrWhiteSpace(installDir)) return result;
        var prefix = installDir.TrimEnd('\\') + "\\";
        foreach (var p in Process.GetProcessesByName("claude"))
        {
            try
            {
                var path = p.MainModule?.FileName;
                if (path != null && path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    result.Add(p);
                else
                    p.Dispose();
            }
            catch
            {
                try { p.Dispose(); } catch { }
            }
        }
        return result;
    }

    public static int[] GetRunningPids(string installDir)
        => GetDesktopProcesses(installDir).Select(p => { var id = p.Id; p.Dispose(); return id; }).ToArray();

    public static bool IsRunning(string installDir)
    {
        var ps = GetDesktopProcesses(installDir);
        var any = ps.Count > 0;
        foreach (var p in ps) p.Dispose();
        return any;
    }

    /// <summary>Завершает только процессы самого приложения Claude Desktop (claude.exe), не службу CoworkVMService.</summary>
    public static int KillDesktopProcesses(string installDir)
    {
        int killed = 0;
        foreach (var p in GetDesktopProcesses(installDir))
        {
            try
            {
                var pid = p.Id;
                p.Kill(entireProcessTree: true);
                p.WaitForExit(3000);
                killed++;
                Log.Warn("CLAUDE_KILLED", $"Процесс Claude завершён: pid={pid}");
            }
            catch (Exception ex)
            {
                Log.Error("CLAUDE_KILL_FAILED", $"Не удалось завершить pid={TryPid(p)}: {ex.Message}");
            }
            finally
            {
                try { p.Dispose(); } catch { }
            }
        }
        return killed;
    }

    private static string TryPid(Process p)
    {
        try { return p.Id.ToString(); } catch { return "?"; }
    }

    public static bool Launch(Config cfg)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $@"shell:AppsFolder\{cfg.ClaudeAppUserModelId}",
                UseShellExecute = true
            };
            Process.Start(psi);
            Log.Info("CLAUDE_LAUNCH", $"Запрошен запуск Claude: {cfg.ClaudeAppUserModelId}");
            return true;
        }
        catch (Exception ex)
        {
            Log.Error("CLAUDE_LAUNCH_FAILED", ex.Message);
            return false;
        }
    }
}
