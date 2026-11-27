using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClaudeGuard.Core;

public sealed class ProbeTarget
{
    public string Host { get; set; } = "api.anthropic.com";
    public int Port { get; set; } = 443;
}

public sealed class Config
{
    // ---- sing-box TUN (our own adapter; only Claude traffic goes to the proxy) ----
    public string TunInterfaceName { get; set; } = "ClaudeGuard";
    /// <summary>TUN address in CIDR form. Also used to verify the adapter IP.</summary>
    public string TunAddress { get; set; } = "172.19.0.1/30";
    /// <summary>sing-box TUN stack: gvisor | system | mixed.</summary>
    public string TunStack { get; set; } = "gvisor";
    /// <summary>Path to sing-box.exe; empty = next to the service executable.</summary>
    public string SingBoxPath { get; set; } = "";

    /// <summary>Extra processes (Go RE2 regex on the full path) to route through the proxy,
    /// e.g. a standalone Claude Code CLI. The Claude Desktop package is always included.</summary>
    public string[] ExtraProxyProcessRegex { get; set; } = Array.Empty<string>();

    /// <summary>DNS for Claude domains is resolved through the proxy (no DNS leak to the ISP).</summary>
    public string RemoteDnsServer { get; set; } = "1.1.1.1";
    public string[] RemoteDnsDomains { get; set; } =
    {
        "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"
    };

    /// <summary>Keep Claude domains in the system proxy bypass list, so another VPN client in
    /// "system proxy" mode (e.g. Happ) does not pull Claude traffic away from our TUN.</summary>
    public bool ManageSystemProxyBypass { get; set; } = true;

    // ---- Claude Desktop ----
    public string ClaudePackageFamilyName { get; set; } = "Claude_pzs8sxrjxfjjc";
    public string ClaudeAppUserModelId { get; set; } = "Claude_pzs8sxrjxfjjc!Claude";
    public string ClaudeInstallDirOverride { get; set; } = "";

    // ---- health checks ----
    public ProbeTarget[] ProbeTargets { get; set; } =
    {
        new() { Host = "api.anthropic.com", Port = 443 },
        new() { Host = "www.cloudflare.com", Port = 443 }
    };

    /// <summary>Light health check: plain HTTP "204" endpoints through the proxy (~1 KB each).
    /// The second URL is tried only if the first fails.</summary>
    public string[] ProbeUrls { get; set; } =
    {
        "http://cp.cloudflare.com/generate_204",
        "http://www.gstatic.com/generate_204"
    };
    /// <summary>Full TLS check of probeTargets (~5 KB): after every sing-box start, on "Check now"
    /// and then every N minutes. 0 = TLS on every probe (old behaviour, more traffic).</summary>
    public int FullTlsCheckMinutes { get; set; } = 30;
    /// <summary>Probe only while Claude Desktop is running: no proxy traffic while it is closed.</summary>
    public bool ProbeOnlyWhileClaudeRuns { get; set; } = true;

    public int ProbeIntervalMs { get; set; } = 2000;
    public int ProbeTimeoutMs { get; set; } = 6000;
    /// <summary>Consecutive failed probe results (not engine ticks) before BLOCK_ALL and killing Claude.</summary>
    public int ProbeFailuresToBlock { get; set; } = 3;
    public int SuccessStreakToAllow { get; set; } = 2;
    public int StableSecondsToAllow { get; set; } = 4;

    public bool KillClaudeOnFailure { get; set; } = true;
    public int KillDelaySeconds { get; set; } = 5;
    public bool AutoRestartClaude { get; set; } = true;
    public int AutoRestartStableSeconds { get; set; } = 15;

    public int VerifyIntervalMs { get; set; } = 5000;
    public int PackageRescanSeconds { get; set; } = 60;

    public string DataDir { get; set; } = @"C:\ProgramData\ClaudeGuard";
    public string LogDir { get; set; } = @"C:\ProgramData\ClaudeGuard\logs";
    /// <summary>Profile and generated sing-box config. ACL: SYSTEM + Administrators only.</summary>
    public string SecretsDir { get; set; } = @"C:\ProgramData\ClaudeGuard\secrets";
    public int LogRetentionDays { get; set; } = 14;

    public static string DefaultPath => Path.Combine(@"C:\ProgramData\ClaudeGuard", "config.json");

    [JsonIgnore]
    public string ResolvedSingBoxPath => string.IsNullOrWhiteSpace(SingBoxPath)
        ? Path.Combine(AppContext.BaseDirectory, "sing-box.exe")
        : SingBoxPath;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static Config Load(string path = null)
    {
        path ??= DefaultPath;
        try
        {
            if (File.Exists(path))
            {
                var cfg = JsonSerializer.Deserialize<Config>(File.ReadAllText(path), JsonOpts);
                if (cfg != null) return cfg.Normalize();
            }
        }
        catch (Exception ex)
        {
            Log.Write("ERROR", "CONFIG_READ", $"Не удалось прочитать {path}: {ex.Message}. Используются значения по умолчанию.");
        }

        var def = new Config().Normalize();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(def, JsonOpts));
        }
        catch (Exception ex)
        {
            Log.Write("ERROR", "CONFIG_WRITE", $"Не удалось записать {path}: {ex.Message}");
        }
        return def;
    }

    public Config Normalize()
    {
        if (string.IsNullOrWhiteSpace(TunInterfaceName)) TunInterfaceName = "ClaudeGuard";
        if (string.IsNullOrWhiteSpace(TunAddress) || !TunAddress.Contains('/')) TunAddress = "172.19.0.1/30";
        if (TunStack is not ("gvisor" or "system" or "mixed")) TunStack = "gvisor";
        if (ProbeIntervalMs < 500) ProbeIntervalMs = 500;
        if (ProbeTimeoutMs < 1000) ProbeTimeoutMs = 1000;
        if (ProbeFailuresToBlock < 1) ProbeFailuresToBlock = 1;
        if (SuccessStreakToAllow < 1) SuccessStreakToAllow = 1;
        if (StableSecondsToAllow < 0) StableSecondsToAllow = 0;
        if (KillDelaySeconds < 0) KillDelaySeconds = 0;
        if (AutoRestartStableSeconds < 5) AutoRestartStableSeconds = 5;
        if (VerifyIntervalMs < 1000) VerifyIntervalMs = 1000;
        ExtraProxyProcessRegex ??= Array.Empty<string>();
        RemoteDnsDomains ??= Array.Empty<string>();
        if (string.IsNullOrWhiteSpace(RemoteDnsServer)) RemoteDnsServer = "1.1.1.1";
        ProbeTargets = (ProbeTargets ?? Array.Empty<ProbeTarget>())
            .Where(t => t != null && !string.IsNullOrWhiteSpace(t.Host) && t.Port is > 0 and <= 65535)
            .ToArray();
        ProbeUrls = (ProbeUrls ?? Array.Empty<string>())
            .Where(u => Uri.TryCreate(u, UriKind.Absolute, out var x) && x.Scheme == Uri.UriSchemeHttp)
            .ToArray();
        if (FullTlsCheckMinutes < 0) FullTlsCheckMinutes = 0;
        if (ProbeTargets.Length == 0)
            ProbeTargets = new[] { new ProbeTarget { Host = "api.anthropic.com", Port = 443 } };
        if (string.IsNullOrWhiteSpace(DataDir)) DataDir = @"C:\ProgramData\ClaudeGuard";
        if (string.IsNullOrWhiteSpace(LogDir)) LogDir = Path.Combine(DataDir, "logs");
        if (string.IsNullOrWhiteSpace(SecretsDir)) SecretsDir = Path.Combine(DataDir, "secrets");
        return this;
    }
}
