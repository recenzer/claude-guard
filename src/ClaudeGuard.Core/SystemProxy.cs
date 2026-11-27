using System.Net;
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
    /// <summary>System proxy points to a local port (another VPN client): loopback is not filtered
    /// by Windows Firewall, so this is a path around our TUN unless Claude domains are bypassed.</summary>
    public bool Loopback { get; set; }
}

/// <summary>
/// Another VPN client in "system proxy" mode (Happ, v2rayN, Clash…) sets the per-user WinINet proxy.
/// Claude Desktop (Chromium) would then send its traffic to that local proxy instead of our TUN.
/// We add Claude domains to the bypass list (ProxyOverride) so Claude connects "directly" —
/// which, for Claude processes, means into the Claude Guard TUN.
/// The service (SYSTEM) enforces this for every loaded user profile; the UI shows hints.
/// </summary>
public static class SystemProxy
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public static string[] BypassEntries(Config cfg)
        => cfg.RemoteDnsDomains
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .SelectMany(d => new[] { d.Trim(), "*." + d.Trim() })
            .ToArray();

    /// <summary>Current user (UI process).</summary>
    public static SystemProxyState Inspect(Config cfg, bool fix) => Inspect(Registry.CurrentUser, cfg, fix);

    /// <summary>All loaded interactive user hives (service running as SYSTEM).</summary>
    public static List<(string sid, SystemProxyState state)> InspectAllUsers(Config cfg, bool fix)
    {
        var list = new List<(string, SystemProxyState)>();
        try
        {
            foreach (var sid in Registry.Users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    using var hive = Registry.Users.OpenSubKey(sid);
                    if (hive != null) list.Add((sid, Inspect(hive, cfg, fix)));
                }
                catch { }
            }
        }
        catch { }
        return list;
    }

    /// <summary>Removes our bypass entries (uninstall / protection disabled is not needed: they are harmless).</summary>
    public static void RemoveBypass(RegistryKey root, Config cfg)
    {
        try
        {
            using var key = root.OpenSubKey(KeyPath, writable: true);
            if (key?.GetValue("ProxyOverride") is not string cur) return;
            var ours = new HashSet<string>(BypassEntries(cfg), StringComparer.OrdinalIgnoreCase);
            var kept = cur.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(x => !ours.Contains(x));
            key.SetValue("ProxyOverride", string.Join(";", kept), RegistryValueKind.String);
        }
        catch { }
    }

    private static SystemProxyState Inspect(RegistryKey root, Config cfg, bool fix)
    {
        var st = new SystemProxyState();
        try
        {
            using var key = root.OpenSubKey(KeyPath, writable: fix);
            if (key == null) return st;
            st.Enabled = Convert.ToInt32(key.GetValue("ProxyEnable", 0)) != 0;
            st.Server = key.GetValue("ProxyServer") as string ?? "";
            st.AutoConfigUrl = key.GetValue("AutoConfigURL") as string ?? "";
            st.Loopback = IsLoopbackProxy(st.Server) || IsLoopbackUrl(st.AutoConfigUrl);
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

    /// <summary>"127.0.0.1:10808", "http=127.0.0.1:1;https=localhost:2", "socks=[::1]:1080"…</summary>
    private static bool IsLoopbackProxy(string server)
    {
        if (string.IsNullOrWhiteSpace(server)) return false;
        foreach (var part in server.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var v = part.Contains('=') ? part[(part.IndexOf('=') + 1)..] : part;
            if (v.Contains("://")) v = v[(v.IndexOf("://", StringComparison.Ordinal) + 3)..];
            string host;
            if (v.StartsWith('[')) host = v[1..Math.Max(1, v.IndexOf(']'))];
            else host = v.Split(':')[0];
            if (IsLoopbackHost(host)) return true;
        }
        return false;
    }

    private static bool IsLoopbackUrl(string url)
        => !string.IsNullOrWhiteSpace(url) && Uri.TryCreate(url, UriKind.Absolute, out var u) && IsLoopbackHost(u.Host.Trim('[', ']'));

    private static bool IsLoopbackHost(string host)
        => host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
           || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));

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
