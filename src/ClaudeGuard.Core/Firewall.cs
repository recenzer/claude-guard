using System.Collections;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;

namespace ClaudeGuard.Core;

public sealed class FirewallRuleSpec
{
    public string Name = "";
    public string Program = "";          // полный путь; пусто = правило для пакета
    public string Package = "";          // PackageFamilyName (не используется по умолчанию)
    public string InterfaceTypes = "";   // "LAN,Wireless,RemoteAccess" или "" = все интерфейсы
    public bool Enabled = true;

    public string ConditionKey => $"{Program}|{Package}|{InterfaceTypes}";
}

public sealed class ExistingRule
{
    public string Name = "";
    public string Program = "";
    public string InterfaceTypes = "";
    public int Action;
    public bool Enabled;
}

/// <summary>
/// Управление правилами Windows Defender Firewall через COM (HNetCfg.FwPolicy2).
/// Никакого PowerShell в рантайме: правила создаются/включаются/выключаются нативно.
/// </summary>
public sealed class Firewall : IDisposable
{
    public const string Prefix = "ClaudeGuard#";
    public const string Grouping = "Claude Guard";
    private const int DirOut = 2;
    private const int ActionBlock = 0;
    private const int ProfilesAll = 0x7FFFFFFF;
    private const int ProtoAny = 256;

    private readonly object _sync = new();
    private dynamic _policy;
    private dynamic _rules;

    public Firewall()
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("HNetCfg.FwPolicy2 недоступен (Windows Firewall API)");
        _policy = Activator.CreateInstance(policyType)!;
        _rules = _policy.Rules;
    }

    public static string PhysicalInterfaceTypes => "LAN,Wireless,RemoteAccess";

    /// <summary>Полный набор правил: для каждой программы — блок на физических интерфейсах (всегда)
    /// и (опционально) блок на всех интерфейсах. Пробная программа блокируется только на физических.</summary>
    public static List<FirewallRuleSpec> BuildSpecs(IEnumerable<string> programs, IEnumerable<string> probePrograms, bool blockAll)
    {
        var list = new List<FirewallRuleSpec>();
        foreach (var p in programs.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            list.Add(new FirewallRuleSpec
            {
                Name = MakeName("Phys", p),
                Program = p,
                InterfaceTypes = PhysicalInterfaceTypes,
                Enabled = true
            });
            list.Add(new FirewallRuleSpec
            {
                Name = MakeName("All", p),
                Program = p,
                InterfaceTypes = "",
                Enabled = blockAll
            });
        }
        foreach (var p in probePrograms.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // пробник должен иметь возможность проверять туннель всегда, поэтому только физический блок
            list.Add(new FirewallRuleSpec
            {
                Name = MakeName("Probe", p),
                Program = p,
                InterfaceTypes = PhysicalInterfaceTypes,
                Enabled = true
            });
        }
        return list;
    }

    /// <summary>Compares interface type lists ignoring order and case ("" and "All" mean all interfaces).</summary>
    public static bool SameInterfaceTypes(string a, string b)
    {
        static string[] Norm(string s) => string.IsNullOrWhiteSpace(s)
            ? new[] { "all" }
            : s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => x.ToLowerInvariant()).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        return Norm(a).SequenceEqual(Norm(b));
    }

    public static string MakeName(string kind, string program)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(program.ToLowerInvariant())))[..8];
        var exe = Path.GetFileName(program);
        if (exe.Length > 40) exe = exe[..40];
        return $"{Prefix}{kind}#{exe}#{hash}";
    }

    public List<ExistingRule> GetOurRules()
    {
        lock (_sync)
        {
            var result = new List<ExistingRule>();
            foreach (var obj in Enumerate(_rules))
            {
                dynamic r = obj;
                string name;
                try { name = (string)r.Name; } catch { continue; }
                if (name == null || !name.StartsWith(Prefix, StringComparison.Ordinal)) continue;
                var er = new ExistingRule { Name = name };
                try { er.Program = (string)r.ApplicationName ?? ""; } catch { }
                try { er.InterfaceTypes = (string)r.InterfaceTypes ?? ""; } catch { }
                try { er.Action = (int)r.Action; } catch { }
                try { er.Enabled = (bool)r.Enabled; } catch { }
                result.Add(er);
            }
            return result;
        }
    }

    /// <summary>Приводит набор правил к желаемому состоянию. Возвращает true при успехе.</summary>
    public bool Apply(IReadOnlyList<FirewallRuleSpec> desired, out string error)
    {
        error = "";
        lock (_sync)
        {
            try
            {
                var all = GetOurRules();
                var desiredNames = new HashSet<string>(desired.Select(d => d.Name), StringComparer.Ordinal);

                // Windows allows several rules with one name (e.g. after `netsh advfirewall import`).
                // Remove every copy of a duplicated name and recreate it below; otherwise
                // ToDictionary would throw and the rules could never be applied again.
                foreach (var g in all.GroupBy(x => x.Name, StringComparer.Ordinal).Where(g => g.Count() > 1))
                {
                    for (int i = 0; i < g.Count(); i++)
                    {
                        try { _rules.Remove(g.Key); } catch { }
                    }
                }
                var existing = GetOurRules()
                    .GroupBy(x => x.Name, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

                foreach (var old in existing.Values)
                {
                    if (!desiredNames.Contains(old.Name))
                    {
                        try { _rules.Remove(old.Name); } catch { }
                    }
                }

                foreach (var d in desired)
                {
                    if (existing.TryGetValue(d.Name, out var cur))
                    {
                        bool same = string.Equals(cur.Program, d.Program, StringComparison.OrdinalIgnoreCase)
                                    && SameInterfaceTypes(cur.InterfaceTypes, d.InterfaceTypes)
                                    && cur.Action == ActionBlock;
                        if (!same)
                        {
                            try { _rules.Remove(d.Name); } catch { }
                            AddRule(d);
                        }
                        else if (cur.Enabled != d.Enabled)
                        {
                            SetEnabled(d.Name, d.Enabled);
                        }
                    }
                    else
                    {
                        AddRule(d);
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    public void RemoveAll()
    {
        lock (_sync)
        {
            foreach (var r in GetOurRules())
            {
                try { _rules.Remove(r.Name); } catch { }
            }
        }
    }

    public bool IsFirewallEnabled(out string detail)
    {
        detail = "";
        lock (_sync)
        {
            try
            {
                bool domain = (bool)_policy.FirewallEnabled[1];
                bool priv = (bool)_policy.FirewallEnabled[2];
                bool pub = (bool)_policy.FirewallEnabled[4];
                int current = 0;
                try { current = (int)_policy.CurrentProfileTypes; } catch { }
                detail = $"domain={domain} private={priv} public={pub} current={current}";
                // важны только активные сейчас профили; неиспользуемый профиль может быть выключен
                if (current == 0) return domain && priv && pub;
                if ((current & 1) != 0 && !domain) return false;
                if ((current & 2) != 0 && !priv) return false;
                if ((current & 4) != 0 && !pub) return false;
                return true;
            }
            catch (Exception ex)
            {
                detail = "unknown: " + ex.Message;
                return false;
            }
        }
    }

    private void AddRule(FirewallRuleSpec d)
    {
        var ruleType = Type.GetTypeFromProgID("HNetCfg.FwRule")
            ?? throw new InvalidOperationException("HNetCfg.FwRule недоступен");
        dynamic rule = Activator.CreateInstance(ruleType)!;
        rule.Name = d.Name;
        rule.Description = "Claude Guard: блокировка сетевого доступа Claude Desktop вне VPN";
        rule.Grouping = Grouping;
        rule.Direction = DirOut;
        rule.Action = ActionBlock;
        rule.Profiles = ProfilesAll;
        rule.Enabled = d.Enabled;
        if (!string.IsNullOrEmpty(d.Program)) rule.ApplicationName = d.Program;
        if (!string.IsNullOrEmpty(d.InterfaceTypes)) rule.InterfaceTypes = d.InterfaceTypes;
        if (!string.IsNullOrEmpty(d.Package)) rule.LocalAppPackageId = d.Package;
        try
        {
            _rules.Add(rule);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Не удалось добавить правило «{d.Name}» (if={d.InterfaceTypes}): {ex.Message}", ex);
        }
    }

    public bool SetEnabled(string name, bool enabled)
    {
        lock (_sync)
        {
            foreach (var obj in Enumerate(_rules))
            {
                dynamic r = obj;
                string n;
                try { n = (string)r.Name; } catch { continue; }
                if (!string.Equals(n, name, StringComparison.Ordinal)) continue;
                try { r.Enabled = enabled; return true; } catch { return false; }
            }
            return false;
        }
    }

    private static List<object> Enumerate(dynamic collection)
    {
        var list = new List<object>();
        object enumObj = null;
        try { enumObj = collection._NewEnum; } catch { }
        if (enumObj is IEnumVARIANT ev)
        {
            var buf = new object[1];
            while (ev.Next(1, buf, IntPtr.Zero) == 0)
            {
                if (buf[0] != null) list.Add(buf[0]);
                buf[0] = null;
            }
            return list;
        }
        if (collection is IEnumerable en)
        {
            foreach (var o in en) if (o != null) list.Add(o);
        }
        return list;
    }

    public void Dispose()
    {
        try { if (_rules != null && Marshal.IsComObject(_rules)) Marshal.ReleaseComObject(_rules); } catch { }
        try { if (_policy != null && Marshal.IsComObject(_policy)) Marshal.ReleaseComObject(_policy); } catch { }
        _rules = null;
        _policy = null;
    }
}
