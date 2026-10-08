using System;
using System.Collections.Generic;
using System.Linq;

namespace Sentinel
{
    public sealed class Step
    {
        public string Title { get; init; } = "";
        public string Cmd { get; init; } = "";
        public string Raw { get; init; } = "";
        public bool Ok { get; init; }
        public bool Optional { get; init; }
        public long ElapsedMs { get; init; }
    }

    public sealed class ActionResult
    {
        public List<Step> Steps { get; init; } = new();
        public bool Ok => Steps.Where(s => !s.Optional).All(s => s.Ok);
    }

    /// <summary>处置动作 —— 每一步都返回真实命令与输出，界面逐步展示</summary>
    public static class Actions
    {
        public static ActionResult BlockIp(string ip)
        {
            var r = new ActionResult();
            string nm = $"Block SMB - {ip}";

            var del = Cmd.Run($"netsh advfirewall firewall delete rule name=\"{nm}\"", "清理同名旧规则", 15000);
            r.Steps.Add(new Step { Title = "清理同名旧规则", Cmd = del.Cmd, Raw = del.Raw, Ok = del.Ok, Optional = true, ElapsedMs = del.ElapsedMs });

            var add = Cmd.Run($"netsh advfirewall firewall add rule name=\"{nm}\" dir=in action=block protocol=TCP localport=445 remoteip={ip} profile=any", "添加阻断规则", 15000);
            r.Steps.Add(new Step { Title = "添加阻断规则", Cmd = add.Cmd, Raw = add.Raw, Ok = add.Ok, ElapsedMs = add.ElapsedMs });

            var vf = Cmd.Run($"netsh advfirewall firewall show rule name=\"{nm}\"", "验证规则生效", 15000);
            r.Steps.Add(new Step { Title = "验证规则生效", Cmd = vf.Cmd, Raw = vf.Raw, Ok = vf.Ok, ElapsedMs = vf.ElapsedMs });

            return r;
        }

        public static ActionResult UnblockIp(string ip)
        {
            var r = new ActionResult();
            var d = Cmd.Run($"netsh advfirewall firewall delete rule name=\"Block SMB - {ip}\"", "删除阻断规则", 15000);
            r.Steps.Add(new Step { Title = "删除阻断规则", Cmd = d.Cmd, Raw = d.Raw, Ok = d.Ok, ElapsedMs = d.ElapsedMs });
            return r;
        }

        public static ActionResult UnlockAccount()
        {
            var r = new ActionResult();
            var a = Cmd.Run("net user Administrator /active:yes", "解除账户锁定", 10000);
            r.Steps.Add(new Step { Title = "解除账户锁定", Cmd = a.Cmd, Raw = a.Raw, Ok = a.Ok, ElapsedMs = a.ElapsedMs });

            var c = Cmd.Run("net user Administrator", "验证账户状态", 10000);
            r.Steps.Add(new Step { Title = "验证账户状态", Cmd = c.Cmd, Raw = c.Raw, Ok = c.Ok, ElapsedMs = c.ElapsedMs });
            return r;
        }

        public static ActionResult EnableLanOnly()
        {
            var r = new ActionResult();

            var allow = Cmd.Run(
                "netsh advfirewall firewall add rule name=\"SMB LAN Only\" dir=in action=allow protocol=TCP localport=445 remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/24,127.0.0.1 profile=any",
                "添加局域网放行规则", 15000);
            r.Steps.Add(new Step { Title = "添加局域网放行规则", Cmd = allow.Cmd, Raw = allow.Raw, Ok = allow.Ok, ElapsedMs = allow.ElapsedMs });

            var legacy = Cmd.Run("netsh advfirewall firewall set rule group=\"文件和打印机共享\" new enable=No", "禁用共享放行规则组", 20000);
            r.Steps.Add(new Step { Title = "禁用共享放行规则组（关键）", Cmd = legacy.Cmd, Raw = legacy.Raw, Ok = legacy.Ok, ElapsedMs = legacy.ElapsedMs });

            var block = Cmd.Run(
                "netsh advfirewall firewall add rule name=\"Block SMB ALL inbound\" dir=in action=block protocol=TCP localport=445 remoteip=any profile=any",
                "添加全局阻断兜底", 15000);
            r.Steps.Add(new Step { Title = "添加全局阻断兜底", Cmd = block.Cmd, Raw = block.Raw, Ok = block.Ok, ElapsedMs = block.ElapsedMs });

            return r;
        }

        public static ActionResult DisableLanOnly()
        {
            var r = new ActionResult();
            var d = Cmd.Run("netsh advfirewall firewall delete rule name=\"Block SMB ALL inbound\"", "删除全局阻断", 15000);
            r.Steps.Add(new Step { Title = "删除全局阻断", Cmd = d.Cmd, Raw = d.Raw, Ok = d.Ok, ElapsedMs = d.ElapsedMs });
            var e = Cmd.Run("netsh advfirewall firewall set rule group=\"文件和打印机共享\" new enable=Yes", "恢复共享放行", 20000);
            r.Steps.Add(new Step { Title = "恢复共享放行", Cmd = e.Cmd, Raw = e.Raw, Ok = e.Ok, ElapsedMs = e.ElapsedMs });
            return r;
        }

        /// <summary>紧急加固：解锁 + 局域网专用 + 封禁全部当前威胁 IP</summary>
        public static ActionResult EmergencyHarden(IEnumerable<string> ips)
        {
            var r = new ActionResult();
            var un = UnlockAccount();
            r.Steps.AddRange(un.Steps);

            var lan = EnableLanOnly();
            r.Steps.AddRange(lan.Steps);

            foreach (var ip in ips)
            {
                if (string.IsNullOrWhiteSpace(ip)) continue;
                var b = Cmd.Run($"netsh advfirewall firewall add rule name=\"Block SMB - {ip}\" dir=in action=block protocol=TCP localport=445 remoteip={ip} profile=any", $"封禁 {ip}", 15000);
                r.Steps.Add(new Step { Title = "封禁威胁 IP " + ip, Cmd = b.Cmd, Raw = b.Raw, Ok = b.Ok, ElapsedMs = b.ElapsedMs });
            }
            return r;
        }

        public static ActionResult DropConnections()
        {
            var r = new ActionResult();
            var q = Cmd.Run("netstat -ano | findstr :445", "查询当前连接", 10000);
            r.Steps.Add(new Step { Title = "查询当前连接", Cmd = q.Cmd, Raw = q.Raw, Ok = q.Ok, ElapsedMs = q.ElapsedMs });

            var s = Cmd.Run("net stop LanmanServer /y & net start LanmanServer", "重启 Server 服务释放会话", 25000);
            r.Steps.Add(new Step { Title = "重启 Server 服务释放会话", Cmd = s.Cmd, Raw = s.Raw, Ok = s.Ok, ElapsedMs = s.ElapsedMs });
            return r;
        }

        /// <summary>查询 IP 归属地，返回可读描述（失败返回空串，不抛异常）</summary>
        public static string LookupIpOnly(string ip)
        {
            var r = Cmd.Run($"curl -s --max-time 10 https://ipinfo.io/{ip}/json", "IP 归属查询", 14000);
            if (!r.Ok || !r.Raw.TrimStart().StartsWith("{")) return "";
            try
            {
                var j = System.Text.Json.JsonDocument.Parse(r.Raw).RootElement;
                var parts = new List<string>();
                if (j.TryGetProperty("city", out var c) && !string.IsNullOrWhiteSpace(c.GetString())) parts.Add(c.GetString());
                if (j.TryGetProperty("region", out var reg) && !string.IsNullOrWhiteSpace(reg.GetString())) parts.Add(reg.GetString());
                if (j.TryGetProperty("country", out var co) && !string.IsNullOrWhiteSpace(co.GetString())) parts.Add(co.GetString());
                string org = j.TryGetProperty("org", out var o) ? o.GetString() ?? "" : "";
                //去掉 AS 号前缀，只留运营商名
                if (org.StartsWith("AS")) { var idx = org.IndexOf(' '); if (idx > 0) org = org[(idx + 1)..]; }
                if (org.Length > 0) parts.Add(org);
                return parts.Count > 0 ? string.Join(" · ", parts) : "未知归属";
            }
            catch { return ""; }
        }
    }
}