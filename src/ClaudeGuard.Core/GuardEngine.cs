using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace ClaudeGuard.Core;

public sealed class SelfTestResult
{
    public bool Ok { get; set; }
    public List<string> Steps { get; } = new();
    public string Error { get; set; } = "";
}

/// <summary>
/// Движок защиты. Один выделенный поток владеет COM-объектами firewall;
/// проба туннеля выполняется в отдельном потоке. Все команды выполняются в потоке движка.
/// Инвариант: состояние по умолчанию — BLOCKED. Разрешение выдаётся только после
/// серии успешных активных проверок через TUN.
/// </summary>
public sealed class GuardEngine : IDisposable
{
    private readonly Config _cfg;
    private readonly Firewall _fw;
    private readonly string _probeExe;
    private readonly object _statusLock = new();
    private readonly GuardStatus _status = new();
    private readonly ConcurrentQueue<Action> _commands = new();
    private readonly AutoResetEvent _probeNow = new(false);

    private volatile bool _paused;
    private volatile bool _stop;

    // результат фоновой пробы
    private volatile bool _probeOk;
    private volatile string _probeCode = "";
    private volatile string _probeMsg = "";
    private volatile int _probeMs;
    private long _probeCompletedTicks;
    private volatile string _probeTarget = "";
    // момент, с которого ждём первую свежую пробу (старт службы / снятие паузы)
    private DateTimeOffset _probeResetAt = DateTimeOffset.Now;
    private DateTimeOffset _lastSoftCountAt = DateTimeOffset.MinValue;
    private int _lastSoftLoggedStreak = -1;

    private GuardState _state = GuardState.Starting;
    private DateTimeOffset _stateSince = DateTimeOffset.Now;
    private DateTimeOffset? _allowedSince;
    private string _reasonCode = ReasonCodes.Startup;
    private string _reasonText = "Инициализация";
    private bool _blockAll;
    private DateTimeOffset? _blockedSince;
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
    private bool _firewallEnabled = true;
    private string _firewallDetail = "";
    private string _lastReasonLogged = "";
    private bool _claudeRunning;
    private int[] _claudePids = Array.Empty<int>();

    // кэш DNS для проверки маршрута
    private IPAddress _cachedProbeIp;
    private DateTimeOffset _cachedProbeIpAt = DateTimeOffset.MinValue;

    private Thread _thread;
    private Thread _probeThread;

    public GuardEngine(Config cfg, string probeExePath)
    {
        _cfg = cfg;
        _probeExe = probeExePath;
        _fw = new Firewall();
    }

    public bool IsReady => _programs.Count > 0;
    public string InstallDir => _installDir;

    public void Start()
    {
        _probeResetAt = DateTimeOffset.Now;
        Log.Info("ENGINE_START", $"Claude Guard {ProgramInfo.Version}, probe={_probeExe}");
        _thread = new Thread(Loop) { IsBackground = true, Name = "guard-engine" };
        _thread.Start();
        _probeThread = new Thread(ProbeLoop) { IsBackground = true, Name = "guard-probe" };
        _probeThread.Start();
    }

    public void Stop()
    {
        _stop = true;
        _probeNow.Set();
        try { _thread?.Join(3000); } catch { }
        try { _probeThread?.Join(3000); } catch { }
    }

    public void Dispose()
    {
        Stop();
        _fw.Dispose();
    }

    // ---------------- команды (потокобезопасные, исполняются в потоке движка) ----------------

    public void Pause(string by)
    {
        if (_paused) return;
        _paused = true;
        Log.Warn("PROTECTION_PAUSED", $"Защита приостановлена ({by}). Claude НЕ защищён.");
    }

    public void Resume(string by)
    {
        if (!_paused) return;
        _paused = false;
        _successStreak = 0;
        _softFailStreak = 0;
        _healthySince = null;
        _killedEver = false;
        _restartPending = false;
        // старый результат пробы (до паузы) недействителен — ждём свежий
        Interlocked.Exchange(ref _probeCompletedTicks, 0);
        _probeResetAt = DateTimeOffset.Now;
        Log.Warn("PROTECTION_RESUMED", $"Защита включена ({by}). Требуется проверка VPN.");
        _probeNow.Set();
    }

    public void CheckNow()
    {
        _probeNow.Set();
    }

    public void RequestRestartClaude() => _restartPending = true;
    public void AcknowledgeRestart()
    {
        _restartPending = false;
        _killedEver = false;
    }

    public GuardStatus GetStatus()
    {
        // новый объект на каждый вызов: сериализация в IPC идёт вне блокировки
        lock (_statusLock)
        {
            return new GuardStatus
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
                LastProbeMs = _probeMs,
                SuccessStreak = _successStreak,
                SoftFailStreak = _softFailStreak,
                RulesOk = _rulesOk,
                FirewallEnabled = _firewallEnabled,
                TunAlias = _cfg.TunAlias,
                TunIp = _tunIp,
                PhysicalIp = _physicalIp,
                Processes = _processes,
                Updated = DateTimeOffset.Now,
                Version = ProgramInfo.Version,
                PausedUntilRestart = _paused ? "protection paused" : ""
            };
        }
    }

    private string _tunIp = "";
    private string[] _processes = Array.Empty<string>();

    private VpnState DeriveVpn()
    {
        if (_paused) return VpnState.Unknown;
        if (_state == GuardState.Allowed) return VpnState.Connected;
        if (_state == GuardState.Checking || _state == GuardState.Starting) return VpnState.Checking;
        if (_state == GuardState.Blocked)
        {
            return _reasonCode switch
            {
                ReasonCodes.VpnProcessMissing => VpnState.Down,
                ReasonCodes.TunMissing => VpnState.Down,
                ReasonCodes.TunDown => VpnState.Down,
                ReasonCodes.TunNoIp => VpnState.Down,
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
            if (_reasonCode is ReasonCodes.TunMissing or ReasonCodes.TunDown) return NetworkState.NoTun;
            if (_reasonCode is ReasonCodes.RouteNotViaTun) return NetworkState.NoRoute;
            return NetworkState.NoInternet;
        }
        return NetworkState.Unknown;
    }

    // ---------------- основной цикл ----------------

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
            else
            {
                Log.Error("CLAUDE_NOT_FOUND", "Claude Desktop не найден. Правила не созданы.");
            }
        }
        catch (Exception ex)
        {
            Log.Critical("STARTUP_FAILED", ex.ToString());
        }

        SetState(GuardState.Checking, ReasonCodes.Checking, "Проверка VPN и туннеля");

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
                _rulesRemovedForPause = true;
                _blockAll = false;
                SetState(GuardState.Paused, ReasonCodes.Paused, "Защита отключена пользователем", forceLog: true);
            }
            RefreshClaudeState(force: false);
            return;
        }
        if (_rulesRemovedForPause)
        {
            // выход из паузы: сразу возвращаем полный блок, не ждём результата проверки
            _rulesRemovedForPause = false;
            _blockAll = true;
            if (_programs.Count > 0) ApplyRules();
            SetState(GuardState.Checking, ReasonCodes.Checking, "Проверка VPN и туннеля", forceLog: true);
        }

        if ((DateTimeOffset.Now - _lastScan).TotalSeconds >= _cfg.PackageRescanSeconds || _programs.Count == 0)
            ScanPrograms(force: false);

        if (_programs.Count == 0)
        {
            SetState(GuardState.Error, ReasonCodes.NoClaude, "Claude Desktop не установлен или путь не найден", forceLog: true);
            RefreshClaudeState(force: true);
            return;
        }

        // --- дешёвые проверки: реакция < 200 мс ---
        string failCode = null, failText = null;
        bool pending = false;

        var missing = _cfg.RequiredProcesses.Where(p => !NetInfo.IsProcessRunning(p)).ToArray();
        if (missing.Length > 0)
        {
            failCode = ReasonCodes.VpnProcessMissing;
            failText = "Не запущены процессы VPN: " + string.Join(", ", missing);
        }

        var tun = NetInfo.GetTun(_cfg.TunAlias, _cfg.TunExpectedPrefix);
        _tunIp = tun.Ipv4;
        if (failCode == null)
        {
            if (!tun.Exists) { failCode = ReasonCodes.TunMissing; failText = $"TUN-интерфейс «{_cfg.TunAlias}» отсутствует"; }
            else if (!tun.Up) { failCode = ReasonCodes.TunDown; failText = $"TUN-интерфейс «{_cfg.TunAlias}» не активен"; }
            else if (string.IsNullOrEmpty(tun.Ipv4)) { failCode = ReasonCodes.TunNoIp; failText = "У TUN-интерфейса нет IPv4"; }
            else if (!tun.IpMatchesExpected) { failCode = ReasonCodes.TunNoIp; failText = $"IP TUN {tun.Ipv4} вне подсети {_cfg.TunExpectedPrefix}"; }
        }

        if (failCode == null)
        {
            var probeIp = GetCachedProbeIp();
            if (probeIp != null)
            {
                var routeIdx = NetInfo.GetRouteInterfaceIndex(probeIp);
                if (routeIdx != tun.IfIndex)
                {
                    failCode = ReasonCodes.RouteNotViaTun;
                    failText = $"Маршрут к {probeIp} идёт через ifIndex={routeIdx}, а не через TUN ({tun.IfIndex})";
                }
            }
        }

        if (failCode == null && !_firewallEnabled)
        {
            failCode = ReasonCodes.FirewallDisabled;
            failText = "Windows Firewall выключен (" + _firewallDetail + ")";
        }

        if (failCode == null)
        {
            var completed = Interlocked.Read(ref _probeCompletedTicks);
            var ageMs = Environment.TickCount64 - completed;
            var maxAge = _cfg.ProbeIntervalMs + _cfg.ProbeTimeoutMs + 2500;
            var graceMs = _cfg.ProbeTimeoutMs + 3000;
            if (completed == 0 && (DateTimeOffset.Now - _probeResetAt).TotalMilliseconds < graceMs)
            {
                // первая проба ещё выполняется — это не сбой, просто ждём
                pending = true;
            }
            else if (completed == 0 || ageMs > maxAge)
            {
                failCode = ReasonCodes.ProbeTimeout;
                failText = "Нет свежего результата проверки туннеля";
            }
            else if (!_probeOk)
            {
                failCode = _probeCode;
                failText = $"Проверка через туннель не прошла: {_probeMsg}";
            }
        }

        if (pending)
        {
            // нет данных для решения: состояние не меняем, счётчики не трогаем
            _successStreak = 0;
            _healthySince = null;
            if (_state is GuardState.Starting or GuardState.Error)
                SetState(GuardState.Checking, ReasonCodes.Checking, "Проверка VPN и туннеля");
        }
        else if (failCode != null)
        {
            _successStreak = 0;
            _healthySince = null;

            // Жёсткие сбои (нет процесса/TUN/маршрута/firewall) — блок сразу.
            // Мягкие (таймаут/TLS/DNS самой пробы) — только после серии подряд:
            // физический блок при этом уже действует, утечки нет.
            // Серия считается по интервалам проб, а не по тикам движка (200 мс),
            // иначе одна неудачная проба давала бы блок и kill Claude за 0.6 с.
            bool soft = IsSoftProbeFailure(failCode);
            if (soft)
            {
                if ((DateTimeOffset.Now - _lastSoftCountAt).TotalMilliseconds >= _cfg.ProbeIntervalMs)
                {
                    _lastSoftCountAt = DateTimeOffset.Now;
                    _softFailStreak++;
                }
            }
            else _softFailStreak = 0;

            if (soft && _softFailStreak < _cfg.ProbeFailuresToBlock)
            {
                if (_lastSoftLoggedStreak != _softFailStreak)
                {
                    _lastSoftLoggedStreak = _softFailStreak;
                    Log.Warn("PROBE_SOFT_FAIL",
                        $"{failCode} ({_softFailStreak}/{_cfg.ProbeFailuresToBlock}): {failText}");
                }
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
            _lastSoftLoggedStreak = -1;
            _successStreak++;
            _healthySince ??= DateTimeOffset.Now;
            if (_state != GuardState.Allowed)
            {
                var stable = (DateTimeOffset.Now - _healthySince.Value).TotalSeconds;
                if (_successStreak >= _cfg.SuccessStreakToAllow && stable >= _cfg.StableSecondsToAllow)
                    EnterAllowed();
            }
        }

        RefreshClaudeState(force: false);

        // --- завершение Claude при аварии (в том числе повторный запуск вручную) ---
        if (_state == GuardState.Blocked && _cfg.KillClaudeOnFailure && _claudeRunning)
        {
            var since = _lastKillAttempt == DateTimeOffset.MinValue
                ? (_blockedSince ?? DateTimeOffset.Now)
                : _lastKillAttempt;
            if ((DateTimeOffset.Now - since).TotalSeconds >= _cfg.KillDelaySeconds)
            {
                _lastKillAttempt = DateTimeOffset.Now;
                Log.Warn("CLAUDE_KILL_START", $"VPN недоступен {_cfg.KillDelaySeconds} с — завершаю Claude Desktop");
                var n = ClaudeApp.KillDesktopProcesses(_installDir);
                if (n > 0)
                {
                    _killedEver = true;
                    _restartPending = false;
                    RefreshClaudeState(force: true);
                    Log.Warn("CLAUDE_KILLED_ALL", $"Завершено процессов Claude: {n}");
                }
            }
        }

        // --- авто-перезапуск только после устойчивого восстановления ---
        if (_state == GuardState.Allowed && _killedEver && _cfg.AutoRestartClaude && _allowedSince.HasValue
            && _softFailStreak == 0)
        {
            if ((DateTimeOffset.Now - _allowedSince.Value).TotalSeconds >= _cfg.AutoRestartStableSeconds)
            {
                _restartPending = true;
                Log.Info("RESTART_READY", "VPN стабилен — Claude можно запускать автоматически");
            }
        }

        // --- целостность правил ---
        if ((DateTimeOffset.Now - _lastVerify).TotalMilliseconds >= _cfg.VerifyIntervalMs)
        {
            _lastVerify = DateTimeOffset.Now;
            VerifyRules();
        }
    }

    private void RefreshClaudeState(bool force)
    {
        if (!force && (DateTimeOffset.Now - _lastProcScan).TotalMilliseconds < 1000) return;
        _lastProcScan = DateTimeOffset.Now;
        _claudeRunning = _installDir != "" && ClaudeApp.IsRunning(_installDir);
        _claudePids = _installDir == "" ? Array.Empty<int>() : ClaudeApp.GetRunningPids(_installDir);
        _processes = _cfg.RequiredProcesses.Where(NetInfo.IsProcessRunning).ToArray();
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

    /// <summary>Мягкий сбой — проблема самой пробы (сеть медленная, DNS, TLS), а не VPN.
    /// Физический блок при таком сбое уже действует, поэтому даём несколько попыток.</summary>
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
            _blockedSince = DateTimeOffset.Now;
            _allowedSince = null;
            _lastKillAttempt = DateTimeOffset.Now;
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
        SetState(GuardState.Allowed, ReasonCodes.VpnConnected, "VPN работает, туннель проверен", forceLog: true);
        Log.Info("STATE_ALLOWED", "VPN проверен: Claude разрешён");
    }

    private void SetState(GuardState s, string code, string text, bool forceLog = false)
    {
        bool changed = _state != s || _reasonCode != code;
        _state = s;
        _reasonCode = code;
        _reasonText = text;
        if (changed || forceLog) _stateSince = DateTimeOffset.Now;
    }

    // ---------------- правила ----------------

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
            _blockAll = true; // при любом изменении набора — сначала блок
            ApplyRules();

            // Иначе в состоянии Allowed блок «на всех интерфейсах» остался бы навсегда:
            // EnterAllowed вызывается только при переходе в Allowed.
            if (_state == GuardState.Allowed)
            {
                _allowedSince = null;
                _successStreak = 0;
                _healthySince = null;
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
        _physicalIp = NetInfo.GetPhysicalIpv4(_cfg.TunAlias);
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
                var expIf = string.IsNullOrEmpty(e.InterfaceTypes) ? "All" : e.InterfaceTypes;
                var actIf = string.IsNullOrEmpty(a.InterfaceTypes) ? "All" : a.InterfaceTypes;
                if (a.Enabled != e.Enabled || !string.Equals(actIf, expIf, StringComparison.OrdinalIgnoreCase))
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
            // аварийный блок (ApplyRules мог принудительно включить _blockAll) несовместим с Allowed
            if (_state == GuardState.Allowed && (!_rulesOk || _blockAll))
                EnterBlocked(ReasonCodes.RulesMissing, "Правила firewall повреждены — доступ заблокирован");
        }
    }

    // ---------------- проба туннеля ----------------

    private void ProbeLoop()
    {
        while (!_stop)
        {
            try
            {
                if (!_paused)
                {
                    var tun = NetInfo.GetTun(_cfg.TunAlias, _cfg.TunExpectedPrefix);
                    if (tun.Exists && tun.Up && !string.IsNullOrEmpty(tun.Ipv4))
                    {
                        var bind = IPAddress.Parse(tun.Ipv4);
                        var tasks = _cfg.ProbeTargets
                            .Select(t => Task.Run(() => TunnelProbe.Run(bind, t, _cfg.ProbeTimeoutMs)))
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
                        if (best != null)
                        {
                            _probeOk = best.Ok;
                            _probeCode = best.Code;
                            _probeMsg = string.IsNullOrEmpty(best.Target) ? best.Message : $"{best.Target}: {best.Message}";
                            _probeMs = best.ElapsedMs;
                            _probeTarget = best.Target;
                        }
                        else
                        {
                            _probeOk = false;
                            _probeCode = ReasonCodes.ProbeTimeout;
                            _probeMsg = "проба не завершилась (все цели)";
                        }
                        _probeCompletedTicks = Environment.TickCount64;
                    }
                    else
                    {
                        _probeOk = false;
                        _probeCode = ReasonCodes.TunMissing;
                        _probeMsg = "TUN недоступен для пробы";
                        _probeCompletedTicks = Environment.TickCount64;
                    }
                }
            }
            catch (Exception ex)
            {
                _probeOk = false;
                _probeCode = ReasonCodes.ProbeTimeout;
                _probeMsg = ex.Message;
                _probeCompletedTicks = Environment.TickCount64;
            }
            _probeNow.WaitOne(_cfg.ProbeIntervalMs);
        }
    }

    // ---------------- самопроверка (выполняется в потоке движка) ----------------

    public SelfTestResult RunSelfTest(int timeoutMs = 30000)
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

            var tun = NetInfo.GetTun(_cfg.TunAlias, _cfg.TunExpectedPrefix);
            r.Steps.Add($"tun={tun.Alias} exists={tun.Exists} up={tun.Up} ip={tun.Ipv4} ifIndex={tun.IfIndex}");
            if (!tun.Up || string.IsNullOrEmpty(tun.Ipv4)) { r.Error = "TUN не активен"; return r; }

            var bind = IPAddress.Parse(tun.Ipv4);
            var t1 = TunnelProbe.Run(bind, _cfg.ProbeTargets[0], _cfg.ProbeTimeoutMs);
            r.Steps.Add($"probe_via_tun ok={t1.Ok} code={t1.Code} ms={t1.ElapsedMs} {t1.Message}");
            if (!t1.Ok) { r.Error = "трафик через TUN не проходит — правило блокирует туннель?"; return r; }

            var phys = NetInfo.GetPhysicalInterface(_cfg.TunAlias);
            var physIp = phys.ipv4;
            r.Steps.Add($"physical_ip={physIp} ifIndex={phys.ifIndex}");
            if (!string.IsNullOrEmpty(physIp) && phys.ifIndex > 0)
            {
                var probeRule = Firewall.MakeName("Probe", _probeExe);
                bool disabled = _fw.SetEnabled(probeRule, false);
                r.Steps.Add($"probe_rule_disabled={disabled}");
                var t2 = TunnelProbe.Run(IPAddress.Parse(physIp), _cfg.ProbeTargets[0], Math.Min(_cfg.ProbeTimeoutMs, 4000), phys.ifIndex);
                r.Steps.Add($"probe_via_phys_without_rule ok={t2.Ok} code={t2.Code} {t2.Message}");
                _fw.SetEnabled(probeRule, true);
                var t3 = TunnelProbe.Run(IPAddress.Parse(physIp), _cfg.ProbeTargets[0], Math.Min(_cfg.ProbeTimeoutMs, 4000), phys.ifIndex);
                r.Steps.Add($"probe_via_phys_with_rule ok={t3.Ok} code={t3.Code} {t3.Message}");
                if (t3.Ok)
                {
                    r.Error = "правило физического блока не работает: прямой выход возможен";
                    return r;
                }
            }
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
    public static string Version => typeof(ProgramInfo).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
}
