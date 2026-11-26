using System.Text.Json.Serialization;

namespace ClaudeGuard.Core;

public enum GuardState { Starting, Checking, Allowed, Blocked, Paused, Error }
public enum VpnState { Unknown, Checking, Connected, Down }
public enum ProtectionState { Unknown, Active, Disabled }
public enum NetworkState { Unknown, TunOk, NoTun, NoRoute, NoInternet }

public sealed class GuardStatus
{
    public GuardState State { get; set; } = GuardState.Starting;
    public VpnState Vpn { get; set; } = VpnState.Unknown;
    public ProtectionState Protection { get; set; } = ProtectionState.Unknown;
    public NetworkState Network { get; set; } = NetworkState.Unknown;

    public string ReasonCode { get; set; } = "STARTING";
    public string ReasonText { get; set; } = "Инициализация";
    public DateTimeOffset Since { get; set; } = DateTimeOffset.Now;

    public bool ClaudeRunning { get; set; }
    public int[] ClaudePids { get; set; } = Array.Empty<int>();
    public bool KilledByGuard { get; set; }
    public bool RestartPending { get; set; }

    public int LastProbeMs { get; set; }
    public bool RulesOk { get; set; }
    public bool FirewallEnabled { get; set; }
    public int SuccessStreak { get; set; }
    public int SoftFailStreak { get; set; }

    public string TunAlias { get; set; } = "";
    public string TunIp { get; set; } = "";
    public string PhysicalIp { get; set; } = "";

    public bool HasProfile { get; set; }
    /// <summary>Profile summary without secrets: name, protocol, server:port.</summary>
    public string ProfileSummary { get; set; } = "";
    public bool SingBoxRunning { get; set; }
    public int SingBoxPid { get; set; }

    public DateTimeOffset Updated { get; set; } = DateTimeOffset.Now;
    public string Version { get; set; } = "";
    public string PausedUntilRestart { get; set; } = "";
}

public sealed record LogEvent(DateTimeOffset Ts, string Level, string Code, string Message);

public static class ReasonCodes
{
    public const string Startup = "STARTUP";
    public const string VpnConnected = "VPN_CONNECTED";
    public const string NoProfile = "NO_PROFILE";
    public const string SingBoxMissing = "SINGBOX_MISSING";
    public const string SingBoxDown = "SINGBOX_DOWN";
    public const string SingBoxConfigError = "SINGBOX_CONFIG_ERROR";
    public const string TunMissing = "TUN_INTERFACE_MISSING";
    public const string TunDown = "TUN_INTERFACE_DOWN";
    public const string TunNoIp = "TUN_NO_IPV4";
    public const string RouteNotViaTun = "ROUTE_NOT_VIA_TUN";
    public const string ProbeDnsFailed = "PROBE_DNS_FAILED";
    public const string ProbeTimeout = "PROBE_TIMEOUT";
    public const string ProbeRefused = "PROBE_REFUSED";
    public const string ProbeTlsFailed = "PROBE_TLS_FAILED";
    public const string ProbeTunBlocked = "PROBE_TUN_BLOCKED";
    public const string FirewallDisabled = "FIREWALL_DISABLED";
    public const string RulesMissing = "FIREWALL_RULES_MISSING";
    public const string RulesError = "FIREWALL_RULES_ERROR";
    public const string Checking = "CHECKING";
    public const string Paused = "PROTECTION_PAUSED";
    public const string Recovering = "RECOVERING";
    public const string ConfigError = "CONFIG_ERROR";
    public const string NoClaude = "CLAUDE_NOT_INSTALLED";
}
