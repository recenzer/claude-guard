using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace ClaudeGuard.Core;

public sealed class SelfTestResult
{
    public bool Ok { get; set; }
    public List<string> Steps { get; } = new();
    public string Error { get; set; } = "";
}

public sealed class ProfileResult
{
    public bool Ok { get; set; }
    public string Error { get; set; } = "";
    public string Summary { get; set; } = "";
}

/// <summary>
/// Protection engine. sing-box (our child process) creates a TUN adapter and routes only
/// Claude Desktop processes to the proxy; everything else goes direct.
/// Firewall: Claude executables are always blocked on physical interfaces, so without
/// a working TUN they cannot reach the network at all (fail-closed).
/// One dedicated thread owns all mutable state; IPC calls only enqueue commands.
/// </summary>
public sealed class GuardEngine : IDisposable
{
    private sealed class ProbeSnapshot
    {
        public bool Ok;
        public string Code = "";
        public string Msg = "";
        public int Ms;
        public long Ticks;      // Environment.TickCount64 when completed
        public int Generation;  // sing-box generation the probe ran against
    }

    private readonly Config _cfg;
    private readonly Firewall _fw;
    private readonly string _probeExe;
    private readonly SingBoxRunner _singBox;
    private readonly ConcurrentQueue<Action> _commands = new();
    private readonly AutoResetEvent _probeNow = new(false);
    private readonly object _statusLock = new();
    private GuardStatus _published = new();

    private volatile bool _stop;
    private volatile bool _paused;

    // ---- sing-box ----
    private ProxyProfile _profile;
    private volatile int _singBoxGeneration;
    private volatile int _socksPort;
    private volatile string _socksUser = "";
    private volatile string _socksPass = "";
    private DateTimeOffset _singBoxStartedAt = DateTimeOffset.MinValue;
    private DateTimeOffset _nextSingBoxStart = DateTimeOffset.MinValue;
    private int _singBoxRestarts;
    private string _singBoxError = "";

    // ---- probe ----
    private ProbeSnapshot _probe; // written by the probe thread, read via Volatile
    private long _lastCountedProbeTicks;
    private long _waitProbeSince = Environment.TickCount64;

    // ---- state ----
    private GuardState _state = GuardState.Starting;
    private DateTimeOffset _stateSince = DateTimeOffset.Now;
    private DateTimeOffset? _allowedSince;
    private string _reasonCode = ReasonCodes.Startup;
    private string _reasonText = "Инициализация";
    private bool _blockAll;
    private DateTimeOffset _lastKillAttempt = DateTimeOffset.MinValue;
    private bool _killedEver;
    private bool _restartPending;
    private int _successStreak;
    private int _softFailStreak;
    private DateTimeOffset? _healthySince;
    private bool _rulesOk;
    private bool _rulesRemovedForPause;
    private DateTimeOffset _lastVerify = DateTimeOffset.MinValue;
    private DateTimeOffset _lastScan = DateTimeOffset.MinValue;
    private DateTimeOffset _lastProcScan = DateTimeOffset.MinValue;
    private List<string> _programs = new();
    private string _installDir = "";
    private string _physicalIp = "";
    private string _tunIp = "";
    private bool _firewallEnabled = true;
    private string _firewallDetail = "";
    private string _lastReasonLogged = "";
    private bool _claudeRunning;
    private int[] _claudePids = Array.Empty<int>();

    private IPAddress _cachedProbeIp;
    private DateTimeOffset _cachedProbeIpAt = DateTimeOffset.MinValue;

    private Thread _thread;
    private Thread _probeThread;

    public GuardEngine(Config cfg, string probeExePath)
    {
        _cfg = cfg;
        _probeExe = probeExePath;
        _fw = new Firewall();
        _singBox = new SingBoxRunner(cfg.ResolvedSingBoxPath);
    }

    public bool IsReady { get; private set; }

    public void Start()
    {
        Log.Info("ENGINE_START", $"Claude Guard {ProgramInfo.Version}, sing-box={_singBox.ExePath}");
        _thread = new Thread(Loop) { IsBackground = true, Name = "guard-engine" };
        _thread.Start();
        _probeThread = new Thread(ProbeLoop) { IsBackground = true, Name = "guard-probe" };
        _probeThread.Start();
    }

    public void Stop()
    {
        if (_stop) return;
        _stop = true;
        _probeNow.Set();
        try { _thread?.Join(5000); } catch { }
        try { _probeThread?.Join(3000); } catch { }
        // sing-box stops -> TUN disappears -> Claude has only physical interfaces -> blocked
        _singBox.Stop();
    }

    public void Dispose()
    {
        Stop();
        _fw.Dispose();
    }

    // ---------------- commands (thread-safe: executed on the engine thread) ----------------

    public void Pause(string by) => _commands.Enqueue(() =>
    {
        if (_paused) return;
        _paused = true;
        Log.Warn("PROTECTION_PAUSED", $"Защита приостановлена ({by}). Claude НЕ защищён и работает напрямую.");
    });

    public void Resume(string by) => _commands.Enqueue(() =>
    {
        if (!_paused) return;
        _paused = false;
        ResetHealth();
        _killedEver = false;
        _restartPending = false;
        Log.Warn("PROTECTION_RESUMED", $"Защита включена ({by}). Требуется проверка прокси.");
    });

    public void CheckNow() => _probeNow.Set();

    public void RequestRestartClaude() => _commands.Enqueue(() => _restartPending = true);

    public void AcknowledgeRestart() => _commands.Enqueue(() =>
    {
        _restartPending = false;
        _killedEver = false;
    });

    /// <summary>Parses and validates the profile (sing-box check) on the caller thread,
    /// then applies it on the engine thread.</summary>
    public ProfileResult SetProfile(string input, int timeoutMs = 30000)
    {
        ProxyProfile profile;
        try { profile = ProfileParser.Parse(input); }
        catch (Exception ex) { return new ProfileResult { Error = ex.Message }; }

        var checkErr = CheckProfile(profile);
        if (checkErr != null) return new ProfileResult { Error = checkErr };

        var tcs = new TaskCompletionSource<ProfileResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        _commands.Enqueue(() =>
        {
            try
            {
                ProfileStore.Save(_cfg, profile);
                _profile = profile;
                Log.Info("PROFILE_SET", "Профиль прокси: " + profile.Summary);
                RestartSingBox("новый профиль");
                tcs.TrySetResult(new ProfileResult { Ok = true, Summary = profile.Summary });
            }
            catch (Exception ex) { tcs.TrySetResult(new ProfileResult { Error = ex.Message }); }
        });
        return tcs.Task.Wait(timeoutMs) ? tcs.Task.Result : new ProfileResult { Error = "таймаут применения профиля" };
    }

    public void ClearProfile() => _commands.Enqueue(() =>
    {
        ProfileStore.Delete(_cfg);
        _profile = null;
        _singBox.Stop();
        _singBoxGeneration++;
        Log.Warn("PROFILE_CLEARED", "Профиль прокси удалён — Claude заблокирован");
    });

    public GuardStatus GetStatus()
    {
        lock (_statusLock) return _published;
    }

    // ---------------- main loop ----------------

    private void Loop()
    {
        try
        {
            ScanPrograms(force: true);
            if (_programs.Count > 0)
            {
                _blockAll = true;
                ApplyRules();
                Log.Warn("STARTUP_BLOCKED", "Старт: применено состояние BLOCKED (fail-closed)");
            }
            else Log.Error("CLAUDE_NOT_FOUND", "Claude Desktop не найден. Правила не созданы.");

            _profile = ProfileStore.Load(_cfg);
            if (_profile != null) RestartSingBox("старт службы");
            else Log.Warn("NO_PROFILE", "Профиль прокси не задан — импортируйте ссылку или конфиг в окне Claude Guard");
        }
        catch (Exception ex)
        {
            Log.Critical("STARTUP_FAILED", ex.ToString());
        }
        IsReady = true;

        SetState(GuardState.Checking, ReasonCodes.Checking, "Проверка прокси и туннеля");

        while (!_stop)
        {
            try
            {
                while (_commands.TryDequeue(out var cmd))
                {
                    try { cmd(); } catch (Exception ex) { Log.Error("CMD_FAILED", ex.ToString()); }
                }
                Tick();
            }
            catch (Exception ex) { Log.Error("ENGINE_TICK", ex.ToString()); }
            PublishStatus();
            Thread.Sleep(200);
        }
    }

    private void Tick()
    {
        if (_paused)
        {
            if (!_rulesRemovedForPause)
            {
                try { _fw.RemoveAll(); } catch (Exception ex) { Log.Error("FW_REMOVE", ex.Message); }
                _singBox.Stop();
                _singBoxGeneration++;
                _rulesRemovedForPause = true;
                _blockAll = false;
                SetState(GuardState.Paused, ReasonCodes.Paused, "Защита отключена пользователем", forceLog: true);
            }
            RefreshClaudeState(force: false);
            return;
        }
        if (_rulesRemovedForPause)
        {
            // leaving pause: full block immediately, then bring the tunnel back
            _rulesRemovedForPause = false;
            _blockAll = true;
            if (_programs.Count > 0) ApplyRules();
            if (_profile != null) RestartSingBox("защита включена");
            SetState(GuardState.Checking, ReasonCodes.Checking, "Проверка прокси и туннеля", forceLog: true);
        }

        RefreshClaudeState(force: false);

        var rescanDue = (DateTimeOffset.Now - _lastScan).TotalSeconds >= (_programs.Count == 0 ? 5 : _cfg.PackageRescanSeconds);
        if (rescanDue) ScanPrograms(force: false);

        if (_programs.Count == 0)
        {
            if (_state != GuardState.Error)
                SetState(GuardState.Error, ReasonCodes.NoClaude, "Claude Desktop не установлен или путь не найден", forceLog: true);
            return;
        }

        string failCode = null, failText = null;
        bool pending = false;

        // --- hard checks: reaction < 200 ms ---
        if (_profile == null)
        {
            failCode = ReasonCodes.NoProfile;
            failText = "Профиль прокси не задан — импортируйте ссылку или конфиг";
        }
        else if (!_singBox.Exists)
        {
            failCode = ReasonCodes.SingBoxMissing;
            failText = "Не найден sing-box.exe: " + _singBox.ExePath;
        }
        else if (!_singBox.IsRunning)
        {
            failCode = ReasonCodes.SingBoxDown;
            failText = "sing-box не запущен" + (string.IsNullOrEmpty(_singBoxError) ? "" : ": " + _singBoxError);
            var tail = _singBox.LastOutput;
            if (!string.IsNullOrEmpty(tail) && string.IsNullOrEmpty(_singBoxError)) failText += " (" + tail + ")";
            if (DateTimeOffset.Now >= _nextSingBoxStart) RestartSingBox("sing-box завершился");
        }

        var tun = NetInfo.GetTun(_cfg.TunInterfaceName, _cfg.TunAddress);
        _tunIp = tun.Ipv4;
        // the TUN adapter appears a few seconds after sing-box starts
        var tunGrace = (DateTimeOffset.Now - _singBoxStartedAt).TotalSeconds < 10;

        if (failCode == null)
        {
            string tunCode = null, tunText = null;
            if (!tun.Exists) { tunCode = ReasonCodes.TunMissing; tunText = $"TUN-интерфейс «{_cfg.TunInterfaceName}» отсутствует"; }
            else if (!tun.Up) { tunCode = ReasonCodes.TunDown; tunText = $"TUN-интерфейс «{_cfg.TunInterfaceName}» не активен"; }
            else if (string.IsNullOrEmpty(tun.Ipv4)) { tunCode = ReasonCodes.TunNoIp; tunText = "У TUN-интерфейса нет IPv4"; }
            else if (!tun.IpMatchesExpected) { tunCode = ReasonCodes.TunNoIp; tunText = $"IP TUN {tun.Ipv4} не совпадает с {_cfg.TunAddress}"; }

            if (tunCode != null)
            {
                if (tunGrace) pending = true;
                else { failCode = tunCode; failText = tunText; }
            }
        }

        if (failCode == null && !pending)
        {
            var probeIp = GetCachedProbeIp();
            if (probeIp != null)
            {
                var routeIdx = NetInfo.GetRouteInterfaceIndex(probeIp);
                if (routeIdx != tun.IfIndex)
                {
                    if (tunGrace) pending = true;
                    else
                    {
                        failCode = ReasonCodes.RouteNotViaTun;
                        failText = $"Маршрут к {probeIp} идёт через ifIndex={routeIdx}, а не через TUN ({tun.IfIndex})";
                    }
                }
            }
        }

        if (failCode == null && !pending && !_firewallEnabled)
        {
            failCode = ReasonCodes.FirewallDisabled;
            failText = "Windows Firewall выключен (" + _firewallDetail + ")";
        }

        // --- soft check: proxy probe ---
        bool newProbeResult = false;
        if (failCode == null && !pending)
        {
            var pr = Volatile.Read(ref _probe);
            var gen = _singBoxGeneration;
            var maxAgeMs = _cfg.ProbeIntervalMs + _cfg.ProbeTimeoutMs + 3000;
            if (pr == null || pr.Generation != gen)
            {
                // no result for the current sing-box yet: wait, but not forever
                if (Environment.TickCount64 - _waitProbeSince < maxAgeMs) pending = true;
                else { failCode = ReasonCodes.ProbeTimeout; failText = "Нет результата проверки прокси"; }
            }
            else
            {
                newProbeResult = pr.Ticks != _lastCountedProbeTicks;
                if (Environment.TickCount64 - pr.Ticks > maxAgeMs)
                {
                    failCode = ReasonCodes.ProbeTimeout;
                    failText = "Нет свежего результата проверки прокси";
                    newProbeResult = true; // staleness counts once per interval below
                }
                else if (!pr.Ok)
                {
                    failCode = string.IsNullOrEmpty(pr.Code) ? ReasonCodes.ProbeTimeout : pr.Code;
                    failText = $"Проверка через прокси не прошла: {pr.Msg}";
                }
                if (newProbeResult) _lastCountedProbeTicks = pr.Ticks;
            }
        }

        if (pending)
        {
            _successStreak = 0;
            _healthySince = null;
            if (_state is GuardState.Starting or GuardState.Error)
                SetState(GuardState.Checking, ReasonCodes.Checking, "Проверка прокси и туннеля");
        }
        else if (failCode != null)
        {
            _successStreak = 0;
            _healthySince = null;

            // Hard failures (no profile/sing-box/TUN/route/firewall): block at once.
            // Soft ones (proxy probe): only after N consecutive *probe results*, not engine ticks.
            // While soft-failing, Claude still cannot leak: it is blocked on physical
            // interfaces and its TUN traffic can only reach the proxy outbound.
            bool soft = IsSoftProbeFailure(failCode);
            if (soft)
            {
                if (newProbeResult) _softFailStreak++;
            }
            else _softFailStreak = 0;

            if (soft && _softFailStreak < _cfg.ProbeFailuresToBlock)
            {
                if (newProbeResult)
                    Log.Warn("PROBE_SOFT_FAIL", $"{failCode} ({_softFailStreak}/{_cfg.ProbeFailuresToBlock}): {failText}");
                if (_state is GuardState.Starting or GuardState.Checking)
                    SetState(GuardState.Checking, ReasonCodes.Checking, failText);
            }
            else
            {
                EnterBlocked(failCode, failText);
            }
        }
        else
        {
            _softFailStreak = 0;
            if (newProbeResult) _successStreak++;
            _healthySince ??= DateTimeOffset.Now;
            if (_state != GuardState.Allowed)
            {
                var stable = (DateTimeOffset.Now - _healthySince.Value).TotalSeconds;
                if (_successStreak >= _cfg.SuccessStreakToAllow && stable >= _cfg.StableSecondsToAllow)
                    EnterAllowed();
            }
        }

        // --- kill Claude while blocked (also when the user relaunches it) ---
        if (_state == GuardState.Blocked && _cfg.KillClaudeOnFailure && _claudeRunning
            && (DateTimeOffset.Now - _lastKillAttempt).TotalSeconds >= _cfg.KillDelaySeconds)
        {
            _lastKillAttempt = DateTimeOffset.Now;
            Log.Warn("CLAUDE_KILL_START", $"Прокси недоступен {_cfg.KillDelaySeconds} с — завершаю Claude Desktop");
            var n = ClaudeApp.KillDesktopProcesses(_installDir);
            if (n > 0)
            {
                _killedEver = true;
                _restartPending = false;
                RefreshClaudeState(force: true);
                Log.Warn("CLAUDE_KILLED_ALL", $"Завершено процессов Claude: {n}");
            }
        }

        // --- auto restart only after a stable recovery (once per kill) ---
        if (_state == GuardState.Allowed && _killedEver && !_restartPending && _cfg.AutoRestartClaude
            && _allowedSince.HasValue && _softFailStreak == 0
            && (DateTimeOffset.Now - _allowedSince.Value).TotalSeconds >= _cfg.AutoRestartStableSeconds)
        {
            _restartPending = true;
            Log.Info("RESTART_READY", "Прокси стабилен — Claude можно запускать автоматически");
        }

        // --- rule integrity ---
        if ((DateTimeOffset.Now - _lastVerify).TotalMilliseconds >= _cfg.VerifyIntervalMs)
        {
            _lastVerify = DateTimeOffset.Now;
            VerifyRules();
        }
    }

    private void ResetHealth()
    {
        _successStreak = 0;
        _softFailStreak = 0;
        _healthySince = null;
        _waitProbeSince = Environment.TickCount64;
    }

    private void RestartSingBox(string why)
    {
        if (_profile == null) return;

        // crash-loop backoff: a restart within a minute of the previous start doubles the delay
        // before the next automatic attempt (5, 10, 20, 40, 60 s)
        var now = DateTimeOffset.Now;
        _singBoxRestarts = (now - _singBoxStartedAt).TotalSeconds < 60 ? Math.Min(_singBoxRestarts + 1, 4) : 0;
        _nextSingBoxStart = now.AddSeconds(Math.Min(60, 5 << _singBoxRestarts));

        _singBoxGeneration++;
        ResetHealth();
        _singBoxStartedAt = now;
        _singBoxError = "";

        try
        {
            var port = FreeLoopbackPort();
            var user = SingBoxConfig.RandomToken(6);
            var pass = SingBoxConfig.RandomToken(16);
            Directory.CreateDirectory(_cfg.SecretsDir);
            var path = Path.Combine(_cfg.SecretsDir, "sing-box.json");
            File.WriteAllText(path, SingBoxConfig.Build(_cfg, _profile, port, user, pass));

            if (_singBox.Start(path, out var err))
            {
                _socksPort = port;
                _socksUser = user;
                _socksPass = pass;
                Log.Info("SINGBOX_RESTART", $"sing-box запущен ({why})");
                _probeNow.Set();
            }
            else
            {
                _singBoxError = err;
                Log.Error("SINGBOX_START_FAILED", err);
            }
        }
        catch (Exception ex)
        {
            _singBoxError = ex.Message;
            Log.Error("SINGBOX_START_FAILED", ex.ToString());
        }
    }

    private static int FreeLoopbackPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try { return ((IPEndPoint)l.LocalEndpoint).Port; }
        finally { l.Stop(); }
    }

    /// <summary>Validates a profile with `sing-box check` using a throwaway config.</summary>
    private string CheckProfile(ProxyProfile profile)
    {
        string path = null;
        try
        {
            Directory.CreateDirectory(_cfg.SecretsDir);
            path = Path.Combine(_cfg.SecretsDir, $"check-{SingBoxConfig.RandomToken(4)}.json");
            File.WriteAllText(path, SingBoxConfig.Build(_cfg, profile, 1080, "check", "check"));
            var err = _singBox.Check(path);
            return err == null ? null : "sing-box отклонил конфиг: " + err;
        }
        catch (Exception ex) { return ex.Message; }
        finally
        {
            try { if (path != null) File.Delete(path); } catch { }
        }
    }

    private void RefreshClaudeState(bool force)
    {
        if (!force && (DateTimeOffset.Now - _lastProcScan).TotalMilliseconds < 1000) return;
        _lastProcScan = DateTimeOffset.Now;
        _claudePids = _installDir == "" ? Array.Empty<int>() : ClaudeApp.GetRunningPids(_installDir);
        _claudeRunning = _claudePids.Length > 0;

        // Claude updated (new versioned package folder): its new executables have no
        // physical-interface block yet — rescan right away instead of waiting for the timer.
        if (!_paused && ClaudeApp.HasUnknownPackageProcess(_installDir))
        {
            Log.Warn("CLAUDE_NEW_PATH", "Claude запущен из нового каталога пакета — пересканирую");
            ScanPrograms(force: false);
        }
    }

    private IPAddress GetCachedProbeIp()
    {
        if (_cachedProbeIp != null && (DateTimeOffset.Now - _cachedProbeIpAt).TotalSeconds < 60) return _cachedProbeIp;
        try
        {
            var t = _cfg.ProbeTargets.FirstOrDefault();
            if (t == null) return null;
            _cachedProbeIp = Dns.GetHostAddresses(t.Host).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            _cachedProbeIpAt = DateTimeOffset.Now;
            return _cachedProbeIp;
        }
        catch { return _cachedProbeIp; }
    }

    private static bool IsSoftProbeFailure(string code) => code is
        ReasonCodes.ProbeTimeout or
        ReasonCodes.ProbeDnsFailed or
        ReasonCodes.ProbeRefused or
        ReasonCodes.ProbeTlsFailed or
        ReasonCodes.ProbeTunBlocked;

    private void EnterBlocked(string code, string text)
    {
        if (_state != GuardState.Blocked)
        {
            _allowedSince = null;
            _lastKillAttempt = DateTimeOffset.Now; // first kill after KillDelaySeconds
            _lastReasonLogged = code;
            SetState(GuardState.Blocked, code, text, forceLog: true);
            Log.Warn("STATE_BLOCKED", $"{code}: {text}");
        }
        else
        {
            _reasonCode = code;
            _reasonText = text;
            if (_lastReasonLogged != code)
            {
                _lastReasonLogged = code;
                Log.Warn("REASON_CHANGED", $"{code}: {text}");
            }
        }

        if (!_blockAll || !_rulesOk)
        {
            _blockAll = true;
            ApplyRules();
        }
    }

    private void EnterAllowed()
    {
        _blockAll = false;
        ApplyRules();
        if (!_rulesOk || _blockAll)
        {
            _blockAll = true;
            ApplyRules();
            EnterBlocked(ReasonCodes.RulesError, "Не удалось применить правила firewall — блокировка сохранена");
            return;
        }
        _allowedSince = DateTimeOffset.Now;
        _successStreak = 0;
        _softFailStreak = 0;
        _healthySince = null;
        _lastReasonLogged = "";
        SetState(GuardState.Allowed, ReasonCodes.VpnConnected, "Прокси работает, Claude идёт через туннель", forceLog: true);
        Log.Info("STATE_ALLOWED", "Прокси проверен: Claude разрешён (только через sing-box)");
    }

    private void SetState(GuardState s, string code, string text, bool forceLog = false)
    {
        bool changed = _state != s || _reasonCode != code;
        _state = s;
        _reasonCode = code;
        _reasonText = text;
        if (changed || forceLog) _stateSince = DateTimeOffset.Now;
    }

    private void PublishStatus()
    {
        var st = new GuardStatus
        {
            State = _state,
            Vpn = DeriveVpn(),
            Protection = _paused ? ProtectionState.Disabled : ProtectionState.Active,
            Network = DeriveNetwork(),
            ReasonCode = _reasonCode,
            ReasonText = _reasonText,
            Since = _stateSince,
            ClaudeRunning = _claudeRunning,
            ClaudePids = _claudePids,
            KilledByGuard = _killedEver,
            RestartPending = _restartPending,
            LastProbeMs = Volatile.Read(ref _probe)?.Ms ?? 0,
            SuccessStreak = _successStreak,
            SoftFailStreak = _softFailStreak,
            RulesOk = _rulesOk,
            FirewallEnabled = _firewallEnabled,
            TunAlias = _cfg.TunInterfaceName,
            TunIp = _tunIp,
            PhysicalIp = _physicalIp,
            HasProfile = _profile != null,
            ProfileSummary = _profile?.Summary ?? "",
            SingBoxRunning = _singBox.IsRunning,
            SingBoxPid = _singBox.Pid,
            Updated = DateTimeOffset.Now,
            Version = ProgramInfo.Version,
            PausedUntilRestart = _paused ? "protection paused" : ""
        };
        lock (_statusLock) _published = st;
    }

    private VpnState DeriveVpn()
    {
        if (_paused) return VpnState.Unknown;
        if (_state == GuardState.Allowed) return VpnState.Connected;
        if (_state is GuardState.Checking or GuardState.Starting) return VpnState.Checking;
        if (_state == GuardState.Blocked)
        {
            return _reasonCode switch
            {
                ReasonCodes.NoProfile => VpnState.Unknown,
                ReasonCodes.SingBoxMissing or ReasonCodes.SingBoxDown or ReasonCodes.SingBoxConfigError => VpnState.Down,
                ReasonCodes.TunMissing or ReasonCodes.TunDown or ReasonCodes.TunNoIp => VpnState.Down,
                _ => VpnState.Unknown
            };
        }
        return VpnState.Unknown;
    }

    private NetworkState DeriveNetwork()
    {
        if (_paused) return NetworkState.Unknown;
        if (_state == GuardState.Allowed) return NetworkState.TunOk;
        if (_state == GuardState.Blocked)
        {
            if (_reasonCode is ReasonCodes.TunMissing or ReasonCodes.TunDown or ReasonCodes.SingBoxDown
                or ReasonCodes.SingBoxMissing or ReasonCodes.NoProfile) return NetworkState.NoTun;
            if (_reasonCode is ReasonCodes.RouteNotViaTun) return NetworkState.NoRoute;
            return NetworkState.NoInternet;
        }
        return NetworkState.Unknown;
    }

    // ---------------- firewall rules ----------------

    private void ScanPrograms(bool force)
    {
        _lastScan = DateTimeOffset.Now;
        var dir = ClaudeApp.FindInstallDir(_cfg);
        var exes = ClaudeApp.EnumerateExecutables(dir);
        if (dir == _installDir && !force && exes.SequenceEqual(_programs)) return;

        _installDir = dir;
        _programs = exes;
        _rulesOk = false;
        Log.Info("CLAUDE_SCAN", $"Каталог: {dir}; исполняемых файлов: {exes.Count}");

        if (_programs.Count > 0)
        {
            _blockAll = true; // any change of the set: block first
            ApplyRules();

            // EnterAllowed runs only on the transition into Allowed, so re-check from scratch
            if (_state == GuardState.Allowed)
            {
                _allowedSince = null;
                ResetHealth();
                SetState(GuardState.Checking, ReasonCodes.Checking, "Набор файлов Claude изменился — повторная проверка", forceLog: true);
            }
        }
    }

    private void ApplyRules()
    {
        if (_programs.Count == 0) return;
        var specs = Firewall.BuildSpecs(_programs, new[] { _probeExe }, _blockAll);
        var ok = _fw.Apply(specs, out var err);
        _rulesOk = ok;
        if (!ok)
        {
            Log.Error("FW_APPLY_FAILED", err);
            if (!_blockAll)
            {
                _blockAll = true;
                if (_fw.Apply(Firewall.BuildSpecs(_programs, new[] { _probeExe }, true), out var err2))
                {
                    _rulesOk = true;
                    Log.Critical("FW_FAILSAFE", "Применён аварийный блок всех интерфейсов");
                }
                else Log.Critical("FW_FAILSAFE_FAILED", err2);
            }
        }
        else
        {
            Log.Info("FW_APPLIED", $"Правил: {specs.Count}; режим: {(_blockAll ? "BLOCK_ALL" : "PHYSICAL_ONLY")}");
        }

        _firewallEnabled = _fw.IsFirewallEnabled(out _firewallDetail);
        _physicalIp = NetInfo.GetPhysicalIpv4(_cfg.TunInterfaceName);
    }

    private void VerifyRules()
    {
        if (_programs.Count == 0) return;
        var expected = Firewall.BuildSpecs(_programs, new[] { _probeExe }, _blockAll);
        var actual = _fw.GetOurRules();
        var exp = expected.ToDictionary(x => x.Name, StringComparer.Ordinal);

        bool ok = actual.Count == expected.Count;
        if (ok)
        {
            foreach (var a in actual)
            {
                if (!exp.TryGetValue(a.Name, out var e)) { ok = false; break; }
                if (a.Enabled != e.Enabled || !Firewall.SameInterfaceTypes(a.InterfaceTypes, e.InterfaceTypes))
                {
                    ok = false;
                    break;
                }
            }
        }

        bool fwEnabled = _fw.IsFirewallEnabled(out var fwDetail);
        if (!fwEnabled && _firewallEnabled)
            Log.Critical("FIREWALL_DISABLED", "Windows Firewall выключен: " + fwDetail);
        _firewallEnabled = fwEnabled;
        _firewallDetail = fwDetail;

        if (!ok)
        {
            Log.Warn("FW_INTEGRITY", "Набор правил изменён извне — восстанавливаю");
            ApplyRules();
            if (_state == GuardState.Allowed && (!_rulesOk || _blockAll))
                EnterBlocked(ReasonCodes.RulesMissing, "Правила firewall повреждены — доступ заблокирован");
        }
    }

    // ---------------- proxy probe ----------------

    private void ProbeLoop()
    {
        while (!_stop)
        {
            try
            {
                var gen = _singBoxGeneration;
                var port = _socksPort;
                var user = _socksUser;
                var pass = _socksPass;
                if (!_paused && port > 0 && _singBox.IsRunning)
                {
                    var ep = new IPEndPoint(IPAddress.Loopback, port);
                    var tasks = _cfg.ProbeTargets
                        .Select(t => Task.Run(() => TunnelProbe.RunViaSocks(ep, user, pass, t, _cfg.ProbeTimeoutMs)))
                        .ToArray();
                    try { Task.WaitAll(tasks, _cfg.ProbeTimeoutMs + 1500); } catch { }

                    ProbeResult best = null;
                    foreach (var t in tasks)
                    {
                        if (!t.IsCompletedSuccessfully) continue;
                        var r = t.Result;
                        if (r.Ok) { best = r; break; }
                        best ??= r;
                    }
                    var snap = new ProbeSnapshot
                    {
                        Ok = best?.Ok ?? false,
                        Code = best?.Code ?? ReasonCodes.ProbeTimeout,
                        Msg = best == null ? "проба не завершилась (все цели)"
                            : string.IsNullOrEmpty(best.Target) ? best.Message : $"{best.Target}: {best.Message}",
                        Ms = best?.ElapsedMs ?? 0,
                        Ticks = Environment.TickCount64,
                        Generation = gen
                    };
                    // a result for an old sing-box instance is useless
                    if (gen == _singBoxGeneration) Volatile.Write(ref _probe, snap);
                }
            }
            catch (Exception ex)
            {
                Log.Error("PROBE_LOOP", ex.Message);
            }
            _probeNow.WaitOne(_cfg.ProbeIntervalMs);
        }
    }

    // ---------------- self-test (runs on the engine thread) ----------------

    public SelfTestResult RunSelfTest(int timeoutMs = 60000)
    {
        var tcs = new TaskCompletionSource<SelfTestResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        _commands.Enqueue(() => tcs.TrySetResult(SelfTestCore()));
        if (!tcs.Task.Wait(timeoutMs)) return new SelfTestResult { Error = "таймаут самопроверки" };
        return tcs.Task.Result;
    }

    private SelfTestResult SelfTestCore()
    {
        var r = new SelfTestResult();
        try
        {
            if (_programs.Count == 0) { r.Error = "Claude не найден"; return r; }
            r.Steps.Add($"claude_dir={_installDir}");
            r.Steps.Add($"programs={_programs.Count}");

            var actual = _fw.GetOurRules();
            r.Steps.Add($"our_rules={actual.Count}");
            if (actual.Count == 0) { r.Error = "правила не созданы"; return r; }

            // 1) physical block really works: the service exe has the same Phys rule as Claude
            var phys = NetInfo.GetPhysicalInterface(_cfg.TunInterfaceName);
            r.Steps.Add($"physical_ip={phys.ipv4} ifIndex={phys.ifIndex}");
            if (!string.IsNullOrEmpty(phys.ipv4) && phys.ifIndex > 0)
            {
                var target = _cfg.ProbeTargets[0];
                var probeRule = Firewall.MakeName("Probe", _probeExe);
                bool disabled = _fw.SetEnabled(probeRule, false);
                var t2 = TunnelProbe.Run(IPAddress.Parse(phys.ipv4), target, Math.Min(_cfg.ProbeTimeoutMs, 4000), phys.ifIndex);
                r.Steps.Add($"probe_rule_disabled={disabled} phys_without_rule ok={t2.Ok} code={t2.Code}");
                _fw.SetEnabled(probeRule, true);
                var t3 = TunnelProbe.Run(IPAddress.Parse(phys.ipv4), target, Math.Min(_cfg.ProbeTimeoutMs, 4000), phys.ifIndex);
                r.Steps.Add($"phys_with_rule ok={t3.Ok} code={t3.Code} {t3.Message}");
                if (t3.Ok) { r.Error = "правило физического блока не работает: прямой выход возможен"; return r; }
                if (!t2.Ok) r.Steps.Add("WARN: прямой выход недоступен и без правила — проверка блока неинформативна");
            }

            // 2) proxy part
            if (_profile == null) { r.Error = "нет профиля прокси"; return r; }
            r.Steps.Add($"profile={_profile.Protocol} {_profile.Server}:{_profile.Port}");

            // sing-box needs a few seconds to bring the TUN up
            var deadline = DateTimeOffset.Now.AddSeconds(15);
            TunInfo tun;
            do
            {
                tun = NetInfo.GetTun(_cfg.TunInterfaceName, _cfg.TunAddress);
                if (tun.Up && !string.IsNullOrEmpty(tun.Ipv4)) break;
                Thread.Sleep(500);
            } while (DateTimeOffset.Now < deadline && _singBox.IsRunning);
            r.Steps.Add($"singbox_running={_singBox.IsRunning} tun={tun.Alias} up={tun.Up} ip={tun.Ipv4} ifIndex={tun.IfIndex}");
            if (!_singBox.IsRunning) { r.Error = "sing-box не запустился: " + (_singBoxError + " " + _singBox.LastOutput).Trim(); return r; }
            if (!tun.Up || string.IsNullOrEmpty(tun.Ipv4)) { r.Error = "TUN sing-box не поднялся"; return r; }

            var viaProxy = TunnelProbe.RunViaSocks(new IPEndPoint(IPAddress.Loopback, _socksPort), _socksUser, _socksPass,
                _cfg.ProbeTargets[0], _cfg.ProbeTimeoutMs);
            r.Steps.Add($"probe_via_proxy ok={viaProxy.Ok} code={viaProxy.Code} ms={viaProxy.ElapsedMs} {viaProxy.Message}");
            if (!viaProxy.Ok) { r.Error = "прокси не пропускает трафик: " + viaProxy.Message; return r; }

            // 3) the TUN interface must NOT fall under the physical block (Claude goes there)
            var viaTun = TunnelProbe.Run(IPAddress.Parse(tun.Ipv4), _cfg.ProbeTargets[0], _cfg.ProbeTimeoutMs);
            r.Steps.Add($"probe_via_tun ok={viaTun.Ok} code={viaTun.Code} {viaTun.Message}");
            if (!viaTun.Ok) { r.Error = "трафик через TUN блокируется — тип интерфейса попал под физический блок?"; return r; }

            r.Ok = true;
            return r;
        }
        catch (Exception ex)
        {
            r.Error = ex.ToString();
            return r;
        }
    }
}

public static class ProgramInfo
{
    public static string Version => typeof(ProgramInfo).Assembly.GetName().Version?.ToString(3) ?? "2.0.0";
}
