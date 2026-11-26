using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;

namespace ClaudeGuard.Core;

/// <summary>Proxy profile: one sing-box outbound (tag "proxy") built from a share link or JSON.</summary>
public sealed class ProxyProfile
{
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string Server { get; set; } = "";
    public int Port { get; set; }
    /// <summary>sing-box outbound JSON. Contains secrets: never send it to the UI.</summary>
    public string Outbound { get; set; } = "";
    public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.Now;

    public string Summary => string.IsNullOrEmpty(Name)
        ? $"{Protocol} {Server}:{Port}"
        : $"{Name} ({Protocol} {Server}:{Port})";
}

/// <summary>Profile storage in a directory readable only by SYSTEM and Administrators.</summary>
public static class ProfileStore
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string PathFor(Config cfg) => Path.Combine(cfg.SecretsDir, "profile.json");

    public static ProxyProfile Load(Config cfg)
    {
        try
        {
            var p = PathFor(cfg);
            if (!File.Exists(p)) return null;
            var prof = JsonSerializer.Deserialize<ProxyProfile>(File.ReadAllText(p), Opts);
            return string.IsNullOrWhiteSpace(prof?.Outbound) ? null : prof;
        }
        catch (Exception ex)
        {
            Log.Error("PROFILE_READ", ex.Message);
            return null;
        }
    }

    public static void Save(Config cfg, ProxyProfile profile)
    {
        Directory.CreateDirectory(cfg.SecretsDir);
        var p = PathFor(cfg);
        var tmp = p + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(profile, Opts), new UTF8Encoding(false));
        File.Move(tmp, p, overwrite: true);
    }

    public static void Delete(Config cfg)
    {
        try { File.Delete(PathFor(cfg)); } catch { }
    }
}

/// <summary>
/// Converts user input into a sing-box outbound.
/// Supported: vless://, vmess://, trojan://, ss://, hysteria2:// (hy2://),
/// an Xray JSON config (first proxy outbound), a sing-box config or a single sing-box outbound.
/// </summary>
public static class ProfileParser
{
    private static readonly HashSet<string> SingBoxProxyTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "anytls", "socks", "http"
    };

    public static ProxyProfile Parse(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) throw new FormatException("Пустой ввод");
        var text = input.Trim().TrimStart('﻿');

        // subscription-style base64 blob with links inside
        if (!text.StartsWith('{') && !text.Contains("://") && TryBase64(text, out var decoded) && decoded.Contains("://"))
            text = decoded.Trim();

        // several lines: take the first that looks like a link
        if (!text.StartsWith('{'))
        {
            var line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(l => l.Contains("://"));
            if (line == null) throw new FormatException("Не похоже ни на ссылку, ни на JSON");
            return ParseLink(line);
        }
        return ParseJson(text);
    }

    // ------------------------------------------------------------------ links

    private static ProxyProfile ParseLink(string link)
    {
        var idx = link.IndexOf("://", StringComparison.Ordinal);
        var scheme = link[..idx].ToLowerInvariant();
        return scheme switch
        {
            "vless" => ParseVlessTrojan(link, "vless"),
            "trojan" => ParseVlessTrojan(link, "trojan"),
            "vmess" => ParseVmess(link),
            "ss" => ParseShadowsocks(link),
            "hysteria2" or "hy2" => ParseHysteria2(link),
            _ => throw new FormatException($"Протокол «{scheme}» не поддерживается")
        };
    }

    private sealed class LinkParts
    {
        public string UserInfo = "";
        public string Host = "";
        public int Port;
        public string Name = "";
        public System.Collections.Specialized.NameValueCollection Query = new();
    }

    private static LinkParts SplitLink(string link)
    {
        var p = new LinkParts();
        var rest = link[(link.IndexOf("://", StringComparison.Ordinal) + 3)..];

        var hash = rest.IndexOf('#');
        if (hash >= 0)
        {
            p.Name = Uri.UnescapeDataString(rest[(hash + 1)..]);
            rest = rest[..hash];
        }
        var q = rest.IndexOf('?');
        if (q >= 0)
        {
            p.Query = HttpUtility.ParseQueryString(rest[(q + 1)..]);
            rest = rest[..q];
        }
        rest = rest.TrimEnd('/');

        var at = rest.LastIndexOf('@');
        if (at >= 0)
        {
            p.UserInfo = Uri.UnescapeDataString(rest[..at]);
            rest = rest[(at + 1)..];
        }

        string portText;
        if (rest.StartsWith('['))
        {
            var close = rest.IndexOf(']');
            if (close < 0) throw new FormatException("Некорректный IPv6-адрес");
            p.Host = rest[1..close];
            portText = rest[(close + 1)..].TrimStart(':');
        }
        else
        {
            var colon = rest.LastIndexOf(':');
            if (colon < 0) throw new FormatException("В ссылке нет порта");
            p.Host = rest[..colon];
            portText = rest[(colon + 1)..];
        }
        if (!int.TryParse(portText, out p.Port) || p.Port is <= 0 or > 65535)
            throw new FormatException($"Некорректный порт «{portText}»");
        if (string.IsNullOrWhiteSpace(p.Host)) throw new FormatException("В ссылке нет адреса сервера");
        return p;
    }

    private static ProxyProfile ParseVlessTrojan(string link, string protocol)
    {
        var p = SplitLink(link);
        if (string.IsNullOrWhiteSpace(p.UserInfo))
            throw new FormatException(protocol == "vless" ? "В ссылке нет UUID" : "В ссылке нет пароля");

        var q = p.Query;
        var ob = new JsonObject
        {
            ["type"] = protocol,
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port
        };
        if (protocol == "vless")
        {
            ob["uuid"] = p.UserInfo;
            var flow = NormalizeFlow(q["flow"]);
            if (!string.IsNullOrEmpty(flow)) ob["flow"] = flow;
            ob["packet_encoding"] = "xudp";
        }
        else
        {
            ob["password"] = p.UserInfo;
        }

        var security = (q["security"] ?? (protocol == "trojan" ? "tls" : "none")).ToLowerInvariant();
        var tls = BuildTls(security, q["sni"] ?? q["peer"], q["fp"], q["alpn"],
            IsTrue(q["allowInsecure"]) || IsTrue(q["insecure"]), q["pbk"], q["sid"], p.Host);
        if (tls != null) ob["tls"] = tls;

        var transport = BuildTransport(q["type"], q["host"], q["path"], q["serviceName"], q["headerType"]);
        if (transport != null) ob["transport"] = transport;

        return Make(ob, p.Name, protocol, p.Host, p.Port);
    }

    private static ProxyProfile ParseVmess(string link)
    {
        var body = link[(link.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var hash = body.IndexOf('#');
        if (hash >= 0) body = body[..hash];
        if (!TryBase64(body, out var json)) throw new FormatException("vmess: ссылка не в формате base64-JSON");

        JsonNode n;
        try { n = JsonNode.Parse(json); }
        catch (Exception ex) { throw new FormatException("vmess: некорректный JSON: " + ex.Message); }

        string S(string key) => n?[key]?.ToString() ?? "";
        var host = S("add");
        if (!int.TryParse(S("port"), out var port)) throw new FormatException("vmess: некорректный порт");
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(S("id")))
            throw new FormatException("vmess: нет адреса или id");

        var ob = new JsonObject
        {
            ["type"] = "vmess",
            ["tag"] = "proxy",
            ["server"] = host,
            ["server_port"] = port,
            ["uuid"] = S("id"),
            ["security"] = string.IsNullOrEmpty(S("scy")) ? "auto" : S("scy"),
            ["alter_id"] = int.TryParse(S("aid"), out var aid) ? aid : 0,
            ["packet_encoding"] = "xudp"
        };
        var tlsMode = S("tls").ToLowerInvariant();
        var tls = BuildTls(tlsMode == "tls" ? "tls" : "none", S("sni"), S("fp"), S("alpn"), false, null, null,
            string.IsNullOrEmpty(S("host")) ? host : S("host"));
        if (tls != null) ob["tls"] = tls;
        var transport = BuildTransport(S("net"), S("host"), S("path"), S("path"), S("type"));
        if (transport != null) ob["transport"] = transport;
        return Make(ob, S("ps"), "vmess", host, port);
    }

    private static ProxyProfile ParseShadowsocks(string link)
    {
        // ss://base64(method:password)@host:port#name   (SIP002)
        // ss://base64(method:password@host:port)#name   (legacy)
        var body = link[(link.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var name = "";
        var hash = body.IndexOf('#');
        if (hash >= 0) { name = Uri.UnescapeDataString(body[(hash + 1)..]); body = body[..hash]; }
        var q = body.IndexOf('?');
        if (q >= 0) body = body[..q];
        body = body.TrimEnd('/');

        string userInfo;
        string hostPort;
        if (body.Contains('@'))
        {
            var at = body.LastIndexOf('@');
            var ui = Uri.UnescapeDataString(body[..at]);
            userInfo = ui.Contains(':') ? ui : (TryBase64(ui, out var d) ? d : throw new FormatException("ss: некорректные учётные данные"));
            hostPort = body[(at + 1)..];
        }
        else
        {
            if (!TryBase64(body, out var full)) throw new FormatException("ss: некорректный base64");
            var at = full.LastIndexOf('@');
            if (at < 0) throw new FormatException("ss: нет адреса сервера");
            userInfo = full[..at];
            hostPort = full[(at + 1)..];
        }

        var colon = userInfo.IndexOf(':');
        if (colon < 0) throw new FormatException("ss: ожидается method:password");
        var parts = SplitLink("ss://" + hostPort);

        var ob = new JsonObject
        {
            ["type"] = "shadowsocks",
            ["tag"] = "proxy",
            ["server"] = parts.Host,
            ["server_port"] = parts.Port,
            ["method"] = userInfo[..colon],
            ["password"] = userInfo[(colon + 1)..]
        };
        return Make(ob, name, "shadowsocks", parts.Host, parts.Port);
    }

    private static ProxyProfile ParseHysteria2(string link)
    {
        var p = SplitLink(link);
        var q = p.Query;
        var tls = new JsonObject
        {
            ["enabled"] = true,
            ["server_name"] = q["sni"] ?? p.Host,
            ["insecure"] = IsTrue(q["insecure"])
        };
        if (!string.IsNullOrEmpty(q["alpn"])) tls["alpn"] = ToArray(q["alpn"]);
        var ob = new JsonObject
        {
            ["type"] = "hysteria2",
            ["tag"] = "proxy",
            ["server"] = p.Host,
            ["server_port"] = p.Port,
            ["password"] = p.UserInfo,
            ["tls"] = tls
        };
        if (string.Equals(q["obfs"], "salamander", StringComparison.OrdinalIgnoreCase))
            ob["obfs"] = new JsonObject { ["type"] = "salamander", ["password"] = q["obfs-password"] ?? "" };
        return Make(ob, p.Name, "hysteria2", p.Host, p.Port);
    }

    // ------------------------------------------------------------------ JSON

    private static ProxyProfile ParseJson(string text)
    {
        JsonNode root;
        try
        {
            root = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
        }
        catch (Exception ex) { throw new FormatException("Некорректный JSON: " + ex.Message); }

        if (root is not JsonObject obj) throw new FormatException("Ожидается JSON-объект");

        // single sing-box outbound
        if (obj["type"] != null && obj["server"] != null) return FromSingBoxOutbound(obj);
        // single Xray outbound
        if (obj["protocol"] != null) return FromXrayOutbound(obj);

        if (obj["outbounds"] is JsonArray outs)
        {
            foreach (var o in outs.OfType<JsonObject>())
            {
                var type = o["type"]?.ToString();
                if (type != null && SingBoxProxyTypes.Contains(type)) return FromSingBoxOutbound(o);
                var proto = o["protocol"]?.ToString();
                if (proto is "vless" or "vmess" or "trojan" or "shadowsocks") return FromXrayOutbound(o);
            }
            throw new FormatException("В конфиге нет поддерживаемого прокси-outbound (vless/vmess/trojan/shadowsocks)");
        }
        throw new FormatException("JSON не похож ни на конфиг Xray, ни на конфиг sing-box");
    }

    private static ProxyProfile FromSingBoxOutbound(JsonObject o)
    {
        var ob = (JsonObject)o.DeepClone();
        ob["tag"] = "proxy";
        if (ob["detour"] != null)
            throw new FormatException("Outbound с detour (цепочки) не поддерживается");
        var server = ob["server"]?.ToString() ?? "";
        var port = Int(ob["server_port"]);
        if (string.IsNullOrWhiteSpace(server) || port <= 0) throw new FormatException("В outbound нет server/server_port");
        return Make(ob, "", ob["type"]?.ToString() ?? "", server, port);
    }

    private static ProxyProfile FromXrayOutbound(JsonObject o)
    {
        var proto = o["protocol"]?.ToString()?.ToLowerInvariant() ?? "";
        var settings = o["settings"] as JsonObject ?? new JsonObject();
        var stream = o["streamSettings"] as JsonObject ?? new JsonObject();

        string host;
        int port;
        var ob = new JsonObject { ["tag"] = "proxy" };

        switch (proto)
        {
            case "vless":
            case "vmess":
            {
                var vnext = (settings["vnext"] as JsonArray)?.FirstOrDefault() as JsonObject
                            ?? throw new FormatException($"{proto}: нет settings.vnext");
                var user = (vnext["users"] as JsonArray)?.FirstOrDefault() as JsonObject
                           ?? throw new FormatException($"{proto}: нет users");
                host = vnext["address"]?.ToString() ?? "";
                port = Int(vnext["port"]);
                ob["type"] = proto;
                ob["uuid"] = user["id"]?.ToString() ?? "";
                if (proto == "vless")
                {
                    var flow = NormalizeFlow(user["flow"]?.ToString());
                    if (!string.IsNullOrEmpty(flow)) ob["flow"] = flow;
                }
                else
                {
                    ob["security"] = user["security"]?.ToString() ?? "auto";
                    ob["alter_id"] = Int(user["alterId"]);
                }
                ob["packet_encoding"] = "xudp";
                break;
            }
            case "trojan":
            case "shadowsocks":
            {
                var srv = (settings["servers"] as JsonArray)?.FirstOrDefault() as JsonObject
                          ?? throw new FormatException($"{proto}: нет settings.servers");
                host = srv["address"]?.ToString() ?? "";
                port = Int(srv["port"]);
                ob["type"] = proto;
                ob["password"] = srv["password"]?.ToString() ?? "";
                if (proto == "shadowsocks") ob["method"] = srv["method"]?.ToString() ?? "";
                break;
            }
            default:
                throw new FormatException($"Xray-протокол «{proto}» не поддерживается");
        }

        if (string.IsNullOrWhiteSpace(host) || port <= 0) throw new FormatException("В outbound нет адреса или порта");
        ob["server"] = host;
        ob["server_port"] = port;

        if (proto != "shadowsocks")
        {
            var security = stream["security"]?.ToString()?.ToLowerInvariant() ?? "none";
            JsonObject tlsNode = null;
            if (security == "tls")
            {
                var t = stream["tlsSettings"] as JsonObject ?? new JsonObject();
                tlsNode = BuildTls("tls", t["serverName"]?.ToString(), t["fingerprint"]?.ToString(),
                    JoinArray(t["alpn"]), (bool?)t["allowInsecure"] ?? false, null, null, host);
            }
            else if (security == "reality")
            {
                var r = stream["realitySettings"] as JsonObject ?? new JsonObject();
                tlsNode = BuildTls("reality", r["serverName"]?.ToString(), r["fingerprint"]?.ToString(), null, false,
                    r["publicKey"]?.ToString(), r["shortId"]?.ToString(), host);
            }
            if (tlsNode != null) ob["tls"] = tlsNode;

            var network = stream["network"]?.ToString()?.ToLowerInvariant() ?? "tcp";
            string tHost = null, tPath = null, tService = null, tHeader = null;
            switch (network)
            {
                case "ws":
                {
                    var ws = stream["wsSettings"] as JsonObject ?? new JsonObject();
                    tPath = ws["path"]?.ToString();
                    tHost = ws["host"]?.ToString() ?? (ws["headers"] as JsonObject)?["Host"]?.ToString();
                    break;
                }
                case "grpc":
                    tService = (stream["grpcSettings"] as JsonObject)?["serviceName"]?.ToString();
                    break;
                case "httpupgrade":
                {
                    var hu = stream["httpupgradeSettings"] as JsonObject ?? new JsonObject();
                    tPath = hu["path"]?.ToString();
                    tHost = hu["host"]?.ToString();
                    break;
                }
                case "h2":
                case "http":
                {
                    var h = stream["httpSettings"] as JsonObject ?? new JsonObject();
                    tPath = h["path"]?.ToString();
                    tHost = JoinArray(h["host"]);
                    break;
                }
                case "tcp":
                case "raw":
                    tHeader = ((stream["tcpSettings"] ?? stream["rawSettings"]) as JsonObject)?["header"]?["type"]?.ToString();
                    break;
            }
            var transport = BuildTransport(network, tHost, tPath, tService, tHeader);
            if (transport != null) ob["transport"] = transport;
        }

        return Make(ob, o["tag"]?.ToString() ?? "", proto, host, port);
    }

    // ------------------------------------------------------------------ building blocks

    private static JsonObject BuildTls(string security, string sni, string fp, string alpn, bool insecure,
        string publicKey, string shortId, string fallbackSni)
    {
        security = (security ?? "none").ToLowerInvariant();
        if (security is "none" or "") return null;
        if (security is not ("tls" or "reality" or "xtls"))
            throw new FormatException($"security=«{security}» не поддерживается");

        var tls = new JsonObject
        {
            ["enabled"] = true,
            ["server_name"] = string.IsNullOrWhiteSpace(sni) ? fallbackSni : sni
        };
        if (insecure) tls["insecure"] = true;
        if (!string.IsNullOrWhiteSpace(alpn)) tls["alpn"] = ToArray(alpn);

        var isReality = security == "reality";
        if (isReality && string.IsNullOrWhiteSpace(fp)) fp = "chrome"; // REALITY requires uTLS in sing-box
        if (!string.IsNullOrWhiteSpace(fp))
            tls["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = fp };

        if (isReality)
        {
            if (string.IsNullOrWhiteSpace(publicKey)) throw new FormatException("REALITY: нет публичного ключа (pbk)");
            tls["reality"] = new JsonObject
            {
                ["enabled"] = true,
                ["public_key"] = publicKey,
                ["short_id"] = shortId ?? ""
            };
        }
        return tls;
    }

    private static JsonObject BuildTransport(string network, string host, string path, string serviceName, string headerType)
    {
        network = (network ?? "tcp").ToLowerInvariant();
        switch (network)
        {
            case "":
            case "tcp":
            case "raw":
                if (string.Equals(headerType, "http", StringComparison.OrdinalIgnoreCase))
                    throw new FormatException("TCP с HTTP-обфускацией (headerType=http) не поддерживается sing-box");
                return null;
            case "ws":
            {
                var t = new JsonObject { ["type"] = "ws" };
                var p = string.IsNullOrEmpty(path) ? "/" : path;
                // Xray-style early data: /path?ed=2048
                var edIdx = p.IndexOf("?ed=", StringComparison.Ordinal);
                if (edIdx >= 0)
                {
                    if (int.TryParse(new string(p[(edIdx + 4)..].TakeWhile(char.IsDigit).ToArray()), out var ed) && ed > 0)
                    {
                        t["max_early_data"] = ed;
                        t["early_data_header_name"] = "Sec-WebSocket-Protocol";
                    }
                    p = p[..edIdx];
                }
                t["path"] = p;
                if (!string.IsNullOrWhiteSpace(host)) t["headers"] = new JsonObject { ["Host"] = host };
                return t;
            }
            case "grpc":
                return new JsonObject { ["type"] = "grpc", ["service_name"] = serviceName ?? "" };
            case "httpupgrade":
            {
                var t = new JsonObject { ["type"] = "httpupgrade", ["path"] = string.IsNullOrEmpty(path) ? "/" : path };
                if (!string.IsNullOrWhiteSpace(host)) t["host"] = host;
                return t;
            }
            case "h2":
            case "http":
            {
                var t = new JsonObject { ["type"] = "http", ["path"] = string.IsNullOrEmpty(path) ? "/" : path };
                if (!string.IsNullOrWhiteSpace(host)) t["host"] = ToArray(host);
                return t;
            }
            case "xhttp":
            case "splithttp":
                throw new FormatException("Транспорт XHTTP есть только в Xray, sing-box его не поддерживает");
            default:
                throw new FormatException($"Транспорт «{network}» не поддерживается");
        }
    }

    private static string NormalizeFlow(string flow)
    {
        if (string.IsNullOrWhiteSpace(flow)) return "";
        // sing-box knows only xtls-rprx-vision; the -udp443 variant only changes UDP/443 handling in Xray
        return flow.StartsWith("xtls-rprx-vision", StringComparison.OrdinalIgnoreCase) ? "xtls-rprx-vision"
            : throw new FormatException($"flow=«{flow}» не поддерживается sing-box");
    }

    private static ProxyProfile Make(JsonObject outbound, string name, string protocol, string host, int port)
        => new()
        {
            Name = (name ?? "").Trim(),
            Protocol = protocol,
            Server = host,
            Port = port,
            Outbound = outbound.ToJsonString(),
            ImportedAt = DateTimeOffset.Now
        };

    private static JsonArray ToArray(string csv)
        => new(csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => (JsonNode)JsonValue.Create(x)).ToArray());

    private static string JoinArray(JsonNode n) => n switch
    {
        JsonArray a => string.Join(",", a.Select(x => x?.ToString()).Where(x => !string.IsNullOrEmpty(x))),
        null => null,
        _ => n.ToString()
    };

    private static bool IsTrue(string v) => v is "1" or "true" or "True" or "TRUE";

    /// <summary>Port/number that may be stored either as a JSON number or as a string.</summary>
    private static int Int(JsonNode n)
    {
        if (n is JsonValue v)
        {
            if (v.TryGetValue<int>(out var i)) return i;
            if (v.TryGetValue<long>(out var l)) return (int)l;
            if (v.TryGetValue<string>(out var s) && int.TryParse(s, out var p)) return p;
        }
        return 0;
    }

    private static bool TryBase64(string s, out string result)
    {
        result = "";
        try
        {
            var t = s.Trim().Replace('-', '+').Replace('_', '/').Replace("\r", "").Replace("\n", "");
            t = t.PadRight(t.Length + (4 - t.Length % 4) % 4, '=');
            result = Encoding.UTF8.GetString(Convert.FromBase64String(t));
            return true;
        }
        catch { return false; }
    }
}
