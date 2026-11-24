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
    public string TunAlias { get; set; } = "happ-tun";
    /// <summary>Ожидаемая подсеть TUN (используется только для проверки, что IP из неё).</summary>
    public string TunExpectedPrefix { get; set; } = "172.18.0.0/30";

    public string ClaudePackageFamilyName { get; set; } = "Claude_pzs8sxrjxfjjc";
    public string ClaudeAppUserModelId { get; set; } = "Claude_pzs8sxrjxfjjc!Claude";
    public string ClaudeInstallDirOverride { get; set; } = "";

    public string[] RequiredProcesses { get; set; } = { "Happ.exe", "happd.exe", "sing-box.exe", "xray.exe" };

    public ProbeTarget[] ProbeTargets { get; set; } =
    {
        new() { Host = "api.anthropic.com", Port = 443 },
        new() { Host = "www.cloudflare.com", Port = 443 }
    };

    public int ProbeIntervalMs { get; set; } = 2000;
    public int ProbeTimeoutMs { get; set; } = 4000;
    /// <summary>Сколько подряд неудачных «мягких» проб (таймаут/TLS/DNS) нужно,
    /// чтобы включить BLOCK_ALL и завершить Claude. Физический блок действует всегда.</summary>
    public int ProbeFailuresToBlock { get; set; } = 3;
    public int SuccessStreakToAllow { get; set; } = 3;
    public int StableSecondsToAllow { get; set; } = 8;

    public bool KillClaudeOnFailure { get; set; } = true;
    public int KillDelaySeconds { get; set; } = 5;
    public bool AutoRestartClaude { get; set; } = true;
    public int AutoRestartStableSeconds { get; set; } = 25;

    public int VerifyIntervalMs { get; set; } = 5000;
    public int PackageRescanSeconds { get; set; } = 60;

    public string DataDir { get; set; } = @"C:\ProgramData\ClaudeGuard";
    public string LogDir { get; set; } = @"C:\ProgramData\ClaudeGuard\logs";
    public int LogRetentionDays { get; set; } = 14;

    public static string DefaultPath => Path.Combine(@"C:\ProgramData\ClaudeGuard", "config.json");

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
        if (string.IsNullOrWhiteSpace(TunAlias)) TunAlias = "happ-tun";
        if (ProbeIntervalMs < 500) ProbeIntervalMs = 500;
        if (ProbeTimeoutMs < 1000) ProbeTimeoutMs = 1000;
        if (ProbeFailuresToBlock < 1) ProbeFailuresToBlock = 1;
        if (SuccessStreakToAllow < 1) SuccessStreakToAllow = 1;
        if (StableSecondsToAllow < 0) StableSecondsToAllow = 0;
        if (KillDelaySeconds < 0) KillDelaySeconds = 0;
        if (AutoRestartStableSeconds < 5) AutoRestartStableSeconds = 5;
        if (VerifyIntervalMs < 1000) VerifyIntervalMs = 1000;
        if (RequiredProcesses == null || RequiredProcesses.Length == 0)
            RequiredProcesses = new[] { "Happ.exe", "happd.exe", "sing-box.exe", "xray.exe" };
        if (ProbeTargets == null || ProbeTargets.Length == 0)
            ProbeTargets = new[] { new ProbeTarget { Host = "api.anthropic.com", Port = 443 } };
        if (string.IsNullOrWhiteSpace(DataDir)) DataDir = @"C:\ProgramData\ClaudeGuard";
        if (string.IsNullOrWhiteSpace(LogDir)) LogDir = Path.Combine(DataDir, "logs");
        return this;
    }
}
