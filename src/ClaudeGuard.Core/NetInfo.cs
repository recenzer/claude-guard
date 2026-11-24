using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ClaudeGuard.Core;

public sealed class TunInfo
{
    public bool Exists { get; set; }
    public bool Up { get; set; }
    public string Alias { get; set; } = "";
    public string Ipv4 { get; set; } = "";
    public int IfIndex { get; set; }
    public bool IpMatchesExpected { get; set; }
    public string Detail { get; set; } = "";
}

public static class NetInfo
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPFORWARDROW
    {
        public uint dwForwardDest;
        public uint dwForwardMask;
        public uint dwForwardPolicy;
        public uint dwForwardNextHop;
        public uint dwForwardIfIndex;
        public uint dwForwardType;
        public uint dwForwardProto;
        public uint dwForwardAge;
        public uint dwForwardNextHopAS;
        public uint dwForwardMetric1;
        public uint dwForwardMetric2;
        public uint dwForwardMetric3;
        public uint dwForwardMetric4;
        public uint dwForwardMetric5;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetBestRoute(uint dwDestAddr, uint dwSourceAddr, out MIB_IPFORWARDROW pBestRoute);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetIpForwardTable(IntPtr pIpForwardTable, ref uint pdwSize, bool bOrder);

    public static uint IpToUInt32(IPAddress ip)
    {
        var b = ip.MapToIPv4().GetAddressBytes();
        return BitConverter.ToUInt32(b, 0);
    }

    /// <summary>Индекс интерфейса, через который Windows отправит пакет на адрес.</summary>
    public static int GetRouteInterfaceIndex(IPAddress destination)
    {
        try
        {
            if (destination.AddressFamily == AddressFamily.InterNetworkV6) return -1;
            var rc = GetBestRoute(IpToUInt32(destination), 0, out var row);
            if (rc != 0) return -1;
            return (int)row.dwForwardIfIndex;
        }
        catch { return -1; }
    }

    public static TunInfo GetTun(string alias, string expectedCidr)
    {
        var info = new TunInfo { Alias = alias };
        try
        {
            var ni = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(x => string.Equals(x.Name, alias, StringComparison.OrdinalIgnoreCase));
            if (ni == null)
            {
                info.Detail = "адаптер не найден";
                return info;
            }
            info.Exists = true;
            info.Up = ni.OperationalStatus == OperationalStatus.Up;
            var props = ni.GetIPProperties();
            var v4 = props.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (v4 != null)
            {
                info.Ipv4 = v4.Address.ToString();
                info.IpMatchesExpected = string.IsNullOrWhiteSpace(expectedCidr) || IpInCidr(expectedCidr, v4.Address);
            }
            try { info.IfIndex = props.GetIPv4Properties()?.Index ?? -1; } catch { info.IfIndex = -1; }
            if (info.IfIndex < 0) info.IfIndex = ni.GetIPProperties().GetIPv4Properties()?.Index ?? -1;
            info.Detail = $"status={ni.OperationalStatus} ip={info.Ipv4} ifIndex={info.IfIndex}";
            return info;
        }
        catch (Exception ex)
        {
            info.Detail = "ошибка: " + ex.Message;
            return info;
        }
    }

    public static bool IpInCidr(string cidr, IPAddress ip)
    {
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) return true;
            var net = IPAddress.Parse(parts[0]).MapToIPv4().GetAddressBytes();
            int prefix = int.Parse(parts[1]);
            var a = ip.MapToIPv4().GetAddressBytes();
            int full = prefix / 8, rem = prefix % 8;
            for (int i = 0; i < full; i++) if (net[i] != a[i]) return false;
            if (rem > 0)
            {
                int mask = 0xFF << (8 - rem) & 0xFF;
                if ((net[full] & mask) != (a[full] & mask)) return false;
            }
            return true;
        }
        catch { return true; }
    }

    public static bool IsProcessRunning(string name)
    {
        try
        {
            var bare = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
            return Process.GetProcessesByName(bare).Length > 0;
        }
        catch { return false; }
    }

    /// <summary>Маршруты по умолчанию (0.0.0.0/0): ifIndex + метрика маршрута.</summary>
    public static List<(int ifIndex, uint metric)> GetDefaultRoutes()
    {
        var list = new List<(int, uint)>();
        uint size = 0;
        try
        {
            var rc = GetIpForwardTable(IntPtr.Zero, ref size, false);
            if (size == 0) return list;
            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                rc = GetIpForwardTable(buf, ref size, false);
                if (rc != 0) return list;
                int count = Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MIB_IPFORWARDROW>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_IPFORWARDROW>(IntPtr.Add(buf, 4 + i * rowSize));
                    if (row.dwForwardDest == 0 && row.dwForwardMask == 0)
                        list.Add(((int)row.dwForwardIfIndex, row.dwForwardMetric1));
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        return list;
    }

    public static string GetInterfaceIpv4(int ifIndex)
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                int idx;
                try { idx = ni.GetIPProperties().GetIPv4Properties()?.Index ?? -1; } catch { continue; }
                if (idx != ifIndex) continue;
                var v4 = ni.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                return v4?.Address.ToString() ?? "";
            }
        }
        catch { }
        return "";
    }

    /// <summary>IPv4 физического интерфейса, через который реально идёт интернет (не TUN),
    /// выбирается по таблице маршрутов: маршрут по умолчанию с наименьшей метрикой.</summary>
    public static string GetPhysicalIpv4(string tunAlias)
        => GetPhysicalInterface(tunAlias).ipv4;

    /// <summary>Индекс и IPv4 физического интерфейса с интернет-маршрутом по умолчанию
    /// (наименьшая метрика среди маршрутов, не относящихся к TUN).</summary>
    public static (int ifIndex, string ipv4) GetPhysicalInterface(string tunAlias)
    {
        try
        {
            var tun = GetTun(tunAlias, null);
            var routes = GetDefaultRoutes()
                .Where(r => r.ifIndex != tun.IfIndex)
                .OrderBy(r => r.metric)
                .ToList();
            foreach (var r in routes)
            {
                var ip = GetInterfaceIpv4(r.ifIndex);
                if (!string.IsNullOrEmpty(ip)) return (r.ifIndex, ip);
            }

            // резерв: любой активный интерфейс с IPv4 и шлюзом
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (string.Equals(ni.Name, tunAlias, StringComparison.OrdinalIgnoreCase)) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var props = ni.GetIPProperties();
                if (!props.GatewayAddresses.Any(g => g.Address != null && !g.Address.Equals(IPAddress.Any))) continue;
                var v4 = props.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                if (v4 != null)
                {
                    int idx = -1;
                    try { idx = props.GetIPv4Properties()?.Index ?? -1; } catch { }
                    return (idx, v4.Address.ToString());
                }
            }
        }
        catch { }
        return (-1, "");
    }

    public static List<string> GetCandidatePhysicalIps(string tunAlias)
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (string.Equals(ni.Name, tunAlias, StringComparison.OrdinalIgnoreCase)) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(ua.Address)) continue;
                    list.Add(ua.Address.ToString());
                }
            }
        }
        catch { }
        return list;
    }
}
