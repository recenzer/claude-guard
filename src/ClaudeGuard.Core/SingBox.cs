using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ClaudeGuard.Core;

/// <summary>Builds the sing-box config (schema 1.12+): TUN inbound, per-process routing
/// (only Claude goes to the proxy, everything else goes direct) and a local SOCKS inbound
/// with random credentials, used only by the health probe.</summary>
public static class SingBoxConfig
{
    public const string ProbeInboundTag = "probe-in";

    public static string Build(Config cfg, ProxyProfile profile, int socksPort, string socksUser, string socksPass)
    {
        var outbound = JsonNode.Parse(profile.Outbound) as JsonObject
                       ?? throw new InvalidOperationException("Некорректный outbound профиля");
        outbound["tag"] = "proxy";

        var processRegex = new JsonArray();
        foreach (var r in ClaudeProcessRegex(cfg)) processRegex.Add(r);
        foreach (var r in cfg.ExtraProxyProcessRegex.Where(x => !string.IsNullOrWhiteSpace(x))) processRegex.Add(r);

        var dnsDomains = new JsonArray();
        foreach (var d in cfg.RemoteDnsDomains.Where(x => !string.IsNullOrWhiteSpace(x))) dnsDomains.Add(d.Trim());

        var dnsRules = new JsonArray();
        if (dnsDomains.Count > 0)
            dnsRules.Add(new JsonObject { ["domain_suffix"] = dnsDomains, ["server"] = "dns-remote" });

        var root = new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = false },
            ["dns"] = new JsonObject
            {
                ["servers"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["type"] = "https",
                        ["tag"] = "dns-remote",
                        ["server"] = cfg.RemoteDnsServer,
                        ["detour"] = "proxy"
                    },
                    new JsonObject { ["type"] = "local", ["tag"] = "dns-local" }
                },
                ["rules"] = dnsRules,
                ["final"] = "dns-local"
            },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "tun",
                    ["tag"] = "tun-in",
                    ["interface_name"] = cfg.TunInterfaceName,
                    ["address"] = new JsonArray { cfg.TunAddress },
                    ["auto_route"] = true,
                    ["strict_route"] = true,
                    ["stack"] = cfg.TunStack
                },
                new JsonObject
                {
                    ["type"] = "socks",
                    ["tag"] = ProbeInboundTag,
                    ["listen"] = "127.0.0.1",
                    ["listen_port"] = socksPort,
                    ["users"] = new JsonArray
                    {
                        new JsonObject { ["username"] = socksUser, ["password"] = socksPass }
                    }
                }
            },
            ["outbounds"] = new JsonArray
            {
                outbound,
                new JsonObject { ["type"] = "direct", ["tag"] = "direct" }
            },
            ["route"] = new JsonObject
            {
                ["auto_detect_interface"] = true,
                ["default_domain_resolver"] = "dns-local",
                ["rules"] = new JsonArray
                {
                    new JsonObject { ["action"] = "sniff" },
                    new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" },
                    new JsonObject { ["inbound"] = new JsonArray { ProbeInboundTag }, ["outbound"] = "proxy" },
                    new JsonObject { ["process_path_regex"] = processRegex, ["outbound"] = "proxy" },
                    // safety net: any process talking to Claude domains (helpers outside the package,
                    // sockets whose owner process could not be resolved) still goes to the proxy
                    new JsonObject { ["domain_suffix"] = dnsDomains.DeepClone(), ["outbound"] = "proxy" }
                },
                ["final"] = "direct"
            }
        };
        return root.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Version-independent regex for every executable of the Claude Desktop package
    /// (the package folder changes on each update), plus the override folder if configured.</summary>
    public static IEnumerable<string> ClaudeProcessRegex(Config cfg)
    {
        var pfn = cfg.ClaudePackageFamilyName ?? "";
        var i = pfn.IndexOf('_');
        var publisher = i >= 0 ? pfn[(i + 1)..] : pfn;
        yield return @"(?i)\\WindowsApps\\Claude_[^\\]+__" + Re2Escape(publisher) + @"\\";
        // bundled Claude Code and per-user helper binaries live outside the package folder
        yield return @"(?i)\\AppData\\Roaming\\Claude\\";
        yield return @"(?i)\\AppData\\Local\\AnthropicClaude\\";
        if (!string.IsNullOrWhiteSpace(cfg.ClaudeInstallDirOverride))
            yield return "(?i)^" + Re2Escape(cfg.ClaudeInstallDirOverride.TrimEnd('\\')) + @"\\";
    }

    /// <summary>Escape for Go RE2 (Regex.Escape also escapes spaces/#, which RE2 rejects).</summary>
    private static string Re2Escape(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s)
        {
            if (@"\.+*?()|[]{}^$".IndexOf(c) >= 0) sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    public static string RandomToken(int bytes = 12)
        => Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();
}

/// <summary>Runs sing-box.exe as a child of the service and restarts it when it exits.</summary>
public sealed class SingBoxRunner : IDisposable
{
    private readonly string _exe;
    private readonly object _sync = new();
    private Process _proc;
    private int _logBudget;
    private DateTimeOffset _logBudgetReset = DateTimeOffset.MinValue;
    private readonly Queue<string> _lastLines = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, byte> _checkers = new();

    public SingBoxRunner(string exePath) => _exe = exePath;

    /// <summary>Server address to hide in logged sing-box output (logs are readable by all users).</summary>
    public string RedactHost { get; set; } = "";

    public string ExePath => _exe;
    public bool Exists => File.Exists(_exe);

    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                try { return _proc != null && !_proc.HasExited; } catch { return false; }
            }
        }
    }

    public int Pid
    {
        get { lock (_sync) { try { return IsRunning ? _proc.Id : 0; } catch { return 0; } } }
    }

    public string LastOutput
    {
        get { lock (_lastLines) return string.Join(" | ", _lastLines); }
    }

    /// <summary>Validates a config with `sing-box check`. Returns null on success, otherwise the error text.</summary>
    public string Check(string configPath, int timeoutMs = 15000)
    {
        if (!Exists) return $"sing-box.exe не найден: {_exe}";
        try
        {
            var psi = new ProcessStartInfo(_exe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(configPath)!
            };
            psi.ArgumentList.Add("check");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(configPath);
            using var p = Process.Start(psi)!;
            _checkers[p.Id] = 0; // KillOrphans must not kill a running `check`
            try
            {
            var errTask = p.StandardError.ReadToEndAsync();
            var outTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return "sing-box check: таймаут";
            }
            if (p.ExitCode == 0) return null;
            var text = (errTask.Result + " " + outTask.Result).Trim();
            return string.IsNullOrEmpty(text) ? $"sing-box check: код {p.ExitCode}" : text;
            }
            finally { _checkers.TryRemove(p.Id, out _); }
        }
        catch (Exception ex)
        {
            return "sing-box check: " + ex.Message;
        }
    }

    public bool Start(string configPath, out string error)
    {
        error = "";
        lock (_sync)
        {
            StopCore();
            KillOrphans();
            if (!Exists) { error = $"sing-box.exe не найден: {_exe}"; return false; }
            try
            {
                var psi = new ProcessStartInfo(_exe)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(configPath)!
                };
                psi.ArgumentList.Add("run");
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add(configPath);
                psi.ArgumentList.Add("--disable-color");

                var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
                p.OutputDataReceived += (_, e) => OnLine(e.Data);
                p.ErrorDataReceived += (_, e) => OnLine(e.Data);
                if (!p.Start()) { error = "Process.Start вернул false"; return false; }
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                _proc = p;
                Log.Info("SINGBOX_START", $"sing-box запущен, pid={p.Id}");
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    public void Stop()
    {
        lock (_sync) StopCore();
    }

    private void StopCore()
    {
        if (_proc == null) return;
        try
        {
            if (!_proc.HasExited)
            {
                _proc.Kill(entireProcessTree: true);
                _proc.WaitForExit(5000);
                Log.Info("SINGBOX_STOP", "sing-box остановлен");
            }
        }
        catch (Exception ex) { Log.Error("SINGBOX_STOP", ex.Message); }
        finally
        {
            try { _proc.Dispose(); } catch { }
            _proc = null;
        }
    }

    /// <summary>sing-box left over from a crashed service instance would hold the TUN adapter.</summary>
    private void KillOrphans()
    {
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(_exe)))
        {
            try
            {
                if (_checkers.ContainsKey(p.Id)) continue;
                var path = p.MainModule?.FileName;
                if (path != null && string.Equals(Path.GetFullPath(path), Path.GetFullPath(_exe), StringComparison.OrdinalIgnoreCase))
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(5000);
                    Log.Warn("SINGBOX_ORPHAN", $"Завершён оставшийся sing-box pid={p.Id}");
                }
            }
            catch { }
            finally { p.Dispose(); }
        }
    }

    private void OnLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        var host = RedactHost;
        if (!string.IsNullOrEmpty(host)) line = line.Replace(host, "<server>", StringComparison.OrdinalIgnoreCase);
        lock (_lastLines)
        {
            _lastLines.Enqueue(line.Length > 300 ? line[..300] : line);
            while (_lastLines.Count > 5) _lastLines.Dequeue();
        }

        // sing-box can be chatty on a broken network: at most 30 lines per minute in our log
        var now = DateTimeOffset.Now;
        if (now - _logBudgetReset > TimeSpan.FromMinutes(1))
        {
            _logBudgetReset = now;
            _logBudget = 30;
        }
        if (_logBudget <= 0) return;
        _logBudget--;

        var level = line.Contains("FATAL") || line.Contains("ERROR") ? "ERROR" : "WARN";
        Log.Write(level, "SINGBOX", line);
    }

    public void Dispose() => Stop();
}
