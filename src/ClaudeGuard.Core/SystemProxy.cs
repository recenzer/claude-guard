using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ClaudeGuard.Core;

public sealed class SystemProxyState
{
    public bool Enabled { get; set; }
    public string Server { get; set; } = "";
    public string AutoConfigUrl { get; set; } = "";
    public bool BypassOk { get; set; } = true;
    /// <summary>True if this call added missing Claude domains to the bypass list.</summary>
    public bool Fixed { get; set; }
}

/// <summary>
/// Another VPN client in "system proxy" mode (Happ, v2rayN, Clash…) sets the per-user WinINet proxy.
/// Claude Desktop (Chromium) would then send its traffic to that local proxy instead of our TUN.
/// We add Claude domains to the bypass list (ProxyOverride) so Claude connects "directly" —
/// which, for Claude processes, means into the Claude Guard TUN.
/// Runs in the user's context (UI process): the settings live in HKCU.
/// </summary>
public static class SystemProxy
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public static string[] BypassEntries(Config cfg)
        => cfg.RemoteDnsDomains
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .SelectMany(d => new[] { d.Trim(), "*." + d.Trim() })
            .ToArray();

    public static SystemProxyState Inspect(Config cfg, bool fix)
    {
        var st = new SystemProxyState();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: fix);
            if (key == null) return st;
            st.Enabled = Convert.ToInt32(key.GetValue("ProxyEnable", 0)) != 0;
            st.Server = key.GetValue("ProxyServer") as string ?? "";
            st.AutoConfigUrl = key.GetValue("AutoConfigURL") as string ?? "";
            if (!st.Enabled) return st;

            var current = (key.GetValue("ProxyOverride") as string ?? "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
            var missing = BypassEntries(cfg)
                .Where(e => !current.Contains(e, StringComparer.OrdinalIgnoreCase))
                .ToList();
            st.BypassOk = missing.Count == 0;
            if (st.BypassOk || !fix) return st;

            // keep "<local>" last, as the Windows UI writes it
            var local = current.Where(x => x.Equals("<local>", StringComparison.OrdinalIgnoreCase)).ToList();
            var merged = current.Except(local, StringComparer.OrdinalIgnoreCase).Concat(missing).Concat(local);
            key.SetValue("ProxyOverride", string.Join(";", merged), RegistryValueKind.String);
            NotifyChanged();
            st.BypassOk = true;
            st.Fixed = true;
        }
        catch { }
        return st;
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);

    private static void NotifyChanged()
    {
        try
        {
            InternetSetOption(IntPtr.Zero, 39 /*INTERNET_OPTION_SETTINGS_CHANGED*/, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, 37 /*INTERNET_OPTION_REFRESH*/, IntPtr.Zero, 0);
        }
        catch { }
    }
}
