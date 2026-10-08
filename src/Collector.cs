using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Sentinel
{
    public sealed class ConnInfo
    {
        public string Local { get; set; } = "";
        public string Remote { get; set; } = "";
        public string RemoteIp { get; set; } = "";
        public string State { get; set; } = "";
        public ushort RemotePort { get; set; }
        public bool IsInboundRisk { get; set; }
    }

    public sealed class Snapshot
    {
        public DateTime Time { get; set; } = DateTime.Now;
        public List<ushort> ListeningPorts { get; set; } = new();
        public List<ConnInfo> InboundRisk { get; set; } = new();
        public bool AccountLocked { get; set; }
        public bool AccountDisabled { get; set; }
        public bool AccountEnabled { get; set; }
        public string LastLogon { get; set; } = "";
        public string PasswordLastSet { get; set; } = "";
        public bool HasLanOnlyRule { get; set; }
        public bool HasBlockAllRule { get; set; }
        public int LegacyEnabledRules { get; set; }
        public int BlockedIpRules { get; set; }
        public string PublicIp { get; set; } = "";
        public string PublicGeo { get; set; } = "";
        public int FailedAttempts { get; set; }
        public int SuccessLogins { get; set; }
        public HashSet<string> AttackIps { get; set; } = new();
        public List<string> Accounts { get; set; } = new();
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "safe";
        public List<string> Issues { get; set; } = new();
        public long ElapsedMs { get; set; }
    }

    /// <summary>采集器
    /// 性能设计：按数据真实变化频率分层调度
    ///   · 入站连接（告警源）→ 2 秒
    ///   · 账户状态（变化即重要）→ 3 秒
    ///   · 防火墙规则（极少变）→ 60 秒
    ///   · 公网 IP（几乎不变）→ 10 分钟
    ///   · 安全日志（变化慢）→ 15 秒
    /// </summary>
    public sealed class Collector
    {
        // 实测结论（GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL = 5）：
        //   AF_INET  → 返回 MIB_TCPROW布局（6 个 uint32，无 OwningPid/Uid）
        //   AF_INET6 → 返回 MIB_TCP6ROW_OWNER_PID 布局（多 dwOwningPid/dwUid）
        // 两者布局不同，必须分别定义，混用会导致 dwState 读到错误偏移。
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwStateSeg;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] dwLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] dwRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public uint dwState;
            public uint dwOwningPid;
            public uint dwUid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int AF, int tableClass, int reserved);

        private const int AF_INET = 2, AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int MIB_TCP_STATE_LISTEN = 2;
        private const int MIB_TCP_STATE_ESTABLISHED = 5;

        private string _publicIp = "";
        private string _publicGeo = "";
        private DateTime _publicIpAt = DateTime.MinValue;
        private bool _fwCached = false;
        private DateTime _fwAt = DateTime.MinValue;
        private bool _lanOnly = false, _blockAll = false, _legacyEnabled = false;
        private int _blockedRules = 0;

        /// <summary>轻量采集：TCP 连接表 + 账户状态。走原生 API，耗时 &lt; 50ms。</summary>
        /// <summary>本轮采集实际执行的命令记录（供界面完整展示，审计用）</summary>
        public List<CmdResult> Executed { get; } = new();

        /// <summary>是否记录命令详情（仅手动扫描时开启，避免每 2 秒刷屏）</summary>
        public bool TraceCommands { get; set; }

        public void CollectFast(Snapshot snap)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Executed.Clear();

            var (listening, inbound) = ReadTcpTable();
            foreach (var p in listening) if (!snap.ListeningPorts.Contains(p)) snap.ListeningPorts.Add(p);
            snap.InboundRisk = inbound;

            // 原生 API 也要记录，界面才能说明「这轮没起子进程」
            if (TraceCommands)
                Executed.Add(new CmdResult
                {
                    Label = "读取TCP 连接表",
                    Cmd = "GetExtendedTcpTable (iphlpapi.dll)",
                    Raw = $"监听端口: {(listening.Count > 0 ? string.Join(", ", listening) : "无")}\n"
                        + $"ESTABLISHED 连接: {inbound.Count} 条",
                    Ok = true, ElapsedMs = 0
                });

            if (TryReadAccountNative(snap))
            {
                if (TraceCommands)
                    Executed.Add(new CmdResult
                    {
                        Label = "读取账户状态",
                        Cmd = "NetUserGetInfo (netapi32.dll)",
                        Raw = $"账户 Administrator: "
                            + (snap.AccountLocked ? "已锁定" : snap.AccountDisabled ? "已禁用" : "正常"),
                        Ok = true
                    });
            }
            else
            {
                var acct = Cmd.Run("net user Administrator", "管理员账户状态", 8000);
                if (TraceCommands) Executed.Add(acct);
                snap.AccountLocked = acct.Raw.Contains("账户启用") && acct.Raw.Contains("已锁定");
                snap.AccountDisabled = acct.Raw.Contains("账户启用") && (acct.Raw.Contains(" No") || acct.Raw.Contains("否"));
                snap.LastLogon = Extract(acct.Raw, "上次登录");
                snap.PasswordLastSet = Extract(acct.Raw, "上次设置密码");
            }

            // 公网 IP 缓存 10 分钟 —— 它几乎不变，没必要反复查
            if (DateTime.Now - _publicIpAt > TimeSpan.FromMinutes(10))
            {
                var pub = Cmd.Run("curl -s --max-time 15 https://ipinfo.io/json", "公网出口 IP 查询", 19000);
                if (TraceCommands) Executed.Add(pub);
                try
                {
                    if (pub.Ok && pub.Raw.TrimStart().StartsWith("{"))
                    {
                        var j = System.Text.Json.JsonDocument.Parse(pub.Raw).RootElement;
                        if (j.TryGetProperty("ip", out var ip)) _publicIp = ip.GetString() ?? "";
                        var parts = new List<string>();
                        if (j.TryGetProperty("city", out var c)) parts.Add(c.GetString() ?? "");
                        if (j.TryGetProperty("region", out var r)) parts.Add(r.GetString() ?? "");
                        if (j.TryGetProperty("org", out var o)) parts.Add(o.GetString() ?? "");
                        _publicGeo = string.Join(" · ", parts.Where(p => !string.IsNullOrEmpty(p)));
                    }
                }
                catch { /* 网络失败则保持旧值 */ }
                _publicIpAt = DateTime.Now;
            }
            snap.PublicIp = _publicIp;
            snap.PublicGeo = _publicGeo;

            // 防火墙规则缓存 60 秒
            if (DateTime.Now - _fwAt > TimeSpan.FromSeconds(60))
            {
                var fw = Cmd.Run("netsh advfirewall firewall show rule name=all", "防火墙规则清单", 25000);
                if (TraceCommands) Executed.Add(fw);
                ParseFirewall(fw.Raw);
                _fwAt = DateTime.Now;
                _fwCached = true;
            }
            snap.HasLanOnlyRule = _lanOnly;
            snap.HasBlockAllRule = _blockAll;
            snap.LegacyEnabledRules = _legacyEnabled ? 1 : 0;
            snap.BlockedIpRules = _blockedRules;

            sw.Stop();
            snap.ElapsedMs = sw.ElapsedMilliseconds;
            Assess(snap);
        }

        /// <summary>读取 TCP 连接表 —— 纯原生 API，无子进程开销</summary>
        /// <summary>端口字段为网络字节序（低字节在前），需交换后才是主机序</summary>
        private static uint Swap16(uint v) => ((v & 0xFF) << 8) | ((v >> 8) & 0xFF);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_ACCOUNT_INFOW
        {
            public string sUserName;
            public string sPassword;
            public uint dwFlags;
            public bool bEnabled;   // Win32BOOL 在 C# 中按 4 字节对齐，用uint 更稳
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint NetUserGetInfo(string server, string user, int level,
            out USER_ACCOUNT_INFOW info, int prefmaxlen, out int actual, out int total);

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern uint NetUserAdd2(string server, int level, ref USER_INFO_2 info, out uint parmError);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_INFO_2
        {
            public string name;
            public string password;
            public uint priv;
            public string home_dir;
            public string comment;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string script_path;
            public uint auth_flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 135)] public string full_name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 135)] public string usr_comment;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 265)] public string parms;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 133)] public string workstations;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1025)] public string script_path_long;
            public uint auth_flags_long;
        }

        /// <summary>UF_ACCOUNTDISABLE = 0x0002；UF_LOCKOUT = 0x000010</summary>
        private const uint UF_ACCOUNTDISABLE = 0x0002;
        private const uint UF_LOCKOUT = 0x0010;

        /// <summary>用原生 API 读取账户状态，避免每次启动子进程（实测 685ms → &lt;1ms）</summary>
        private bool TryReadAccountNative(Snapshot snap)
        {
            try
            {
                if (NetUserGetInfo(null, "Administrator", 2, out var info, 1024, out _, out _) != 0)
                    return false;

                snap.AccountDisabled = (info.dwFlags & UF_ACCOUNTDISABLE) != 0;
                // ACCOUNTDISABLE 位为 0 时，UF_LOCKOUT 才有意义
                snap.AccountLocked = !snap.AccountDisabled && (info.dwFlags & UF_LOCKOUT) != 0;
                snap.AccountEnabled = !snap.AccountDisabled && !snap.AccountLocked;
                return true;
            }
            catch { return false; }
        }

        private (List<ushort> listening, List<ConnInfo> inbound) ReadTcpTable()
        {
            var listening = new List<ushort>();
            var inbound = new List<ConnInfo>();

            foreach (var addrFamily in new[] { AF_INET, AF_INET6 })
            {
                int size = 0;
                // 第一次调用固定返回 ERROR_INSUFFICIENT_BUFFER(122)，属正常探测行为，
                // 只应检查 size 是否有效，不能因 ret != 0 就跳过。
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, addrFamily, TCP_TABLE_OWNER_PID_ALL, 0);
                if (size <= 0) continue;

                // 二次调用返回的行数为实际有效字节数，需重新分配并复调
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    uint ret = GetExtendedTcpTable(buf, ref size, false, addrFamily, TCP_TABLE_OWNER_PID_ALL, 0);
                    if (ret != 0 || size <= 4) continue;

                    int rowSize = addrFamily == AF_INET ? Marshal.SizeOf<MIB_TCPROW>() : Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

                    // 关键：返回的缓冲区首4 字节是 dwNumEntries 表头，行数据从偏移 4 开始。
                    // 若不跳过表头，dwState 会读到行数字段，导致状态判断全部失效。
                    int count = (size - 4) / rowSize;
                    if (count <= 0) continue;

                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = IntPtr.Add(buf, 4 + i * rowSize);
                        string localAddr, remoteAddr;
                        uint lport, rport, state;

                        if (addrFamily == AF_INET)
                        {
                            var row = Marshal.PtrToStructure<MIB_TCPROW>(p);
                            lport = Swap16(row.dwLocalPort);
                            rport = Swap16(row.dwRemotePort);
                            state = row.dwState;
                            localAddr = new IPAddress(row.dwLocalAddr).ToString();
                            remoteAddr = new IPAddress(row.dwRemoteAddr).ToString();
                        }
                        else
                        {
                            var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(p);
                            lport = Swap16(row.dwLocalPort);
                            rport = Swap16(row.dwRemotePort);
                            state = row.dwState;
                            localAddr = "[" + new IPAddress(row.dwLocalAddr).ToString() + "]";
                            remoteAddr = "[" + new IPAddress(row.dwRemoteAddr).ToString() + "]";
                        }

                        if (state == MIB_TCP_STATE_LISTEN)
                        {
                            if (lport is 445 or 139 or 3389) listening.Add((ushort)lport);
                            continue;
                        }

                        if (lport != 445) continue;           // 只关注 SMB 风险端口
                        if (state != MIB_TCP_STATE_ESTABLISHED) continue;

                        var ip = remoteAddr.Trim('[', ']').Split('%')[0];
                        if (IsPrivate(ip)) continue;

                        inbound.Add(new ConnInfo
                        {
                            Local = $"{localAddr}:{lport}",
                            Remote = $"{remoteAddr}:{rport}",
                            RemoteIp = ip,
                            RemotePort = (ushort)rport,
                            State = "ESTABLISHED",
                            IsInboundRisk = true
                        });
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return (listening, inbound);
        }

        public static bool IsPrivate(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return true;
            if (IPAddress.TryParse(ip, out var addr))
            {
                if (IPAddress.IsLoopback(addr)) return true;
                var b = addr.GetAddressBytes();
                if (b.Length == 4)
                {
                    if (b[0] == 10) return true;
                    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                    if (b[0] == 192 && b[1] == 168) return true;
                    if (b[0] == 169 && b[1] == 254) return true;
                }
                if (addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.IsIPv6LinkLocal) return true;
                return false;
            }
            return true;
        }

        private void ParseFirewall(string raw)
        {
            _lanOnly = false; _blockAll = false; _legacyEnabled = false; _blockedRules = 0;
            if (string.IsNullOrEmpty(raw) || !raw.Contains("规则名称")) return;

            var lines = raw.Replace("\r\n", "\n").Split('\n');
            // 以「规则名称」为块边界，避免字段串块
            var blocks = new List<string>();
            var cur = new List<string>();
            foreach (var ln in lines)
            {
                if (ln.TrimStart().StartsWith("规则名称"))
                {
                    if (cur.Count > 0) blocks.Add(string.Join("\n", cur));
                    cur.Clear();
                }
                cur.Add(ln);
            }
            if (cur.Count > 0) blocks.Add(string.Join("\n", cur));

            foreach (var b in blocks)
            {
                var name = Extract(b, "规则名称").Trim();
                bool enabled = b.Contains("已启用:") && b.Contains("是") &&
                                b.IndexOf("已启用:", StringComparison.Ordinal) < IndexOfEnabledIs(b);
                var action = Extract(b, "操作");
                var localPort = Extract(b, "本地端口");
                var remoteIp = Extract(b, "远程 IP");

                if (!localPort.Contains("445") && !name.Contains("SMB") &&
                    !name.Contains("445") && !name.Contains("文件和打印机共享")) continue;

                if (name == "SMB LAN Only" && enabled) _lanOnly = true;
                if (name == "Block SMB ALL inbound" && enabled) _blockAll = true;
                if (name.StartsWith("Block SMB") && enabled) _blockedRules++;
                if ((name.Contains("文件和打印机共享") || name.Contains("网络发现")) && enabled)
                    _legacyEnabled = true;
            }
        }

        private static int IndexOfEnabledIs(string block)
        {
            var i = block.IndexOf("已启用:", StringComparison.Ordinal);
            if (i < 0) return -1;
            var seg = block[i..Math.Min(block.Length, i + 24)];
            return seg.Contains("是") ? i : int.MaxValue;
        }

        /// <summary>提取字段值。兼容冒号前后空格与全角冒号。</summary>
        public static string Extract(string text, string field)
        {
            int idx = text.IndexOf(field, StringComparison.Ordinal);
            if (idx < 0) return "";
            int p = idx + field.Length;
            // 跳过冒号与空白（含全角空格）
            while (p < text.Length && (text[p] == ':' || text[p] == '：' || text[p] == ' ' || text[p] == '\t')) p++;
            int end = text.IndexOf('\n', p);
            if (end < 0) end = text.Length;
            return text[p..end].Trim();
        }

        public static void Assess(Snapshot s)
        {
            s.Issues.Clear();
            int score = 0;

            if (s.InboundRisk.Count > 0)
            {
                s.Issues.Add($"检测到 {s.InboundRisk.Count} 条公网入站连接（正在被攻击）");
                score += 35;
            }
            if (s.AccountLocked)
            {
                s.Issues.Add("管理员账户已锁定 —— 正确密码将被拒绝");
                score += 35;
            }
            if (s.ListeningPorts.Contains((ushort)445) && !s.HasLanOnlyRule && !s.HasBlockAllRule)
            {
                s.Issues.Add("445 正在监听且无防护规则（建议执行一键加固）");
                score += 20;
            }
            if (s.LegacyEnabledRules > 0)
            {
                s.Issues.Add("存在仍启用的「文件和打印机共享」放行规则");
                score += 15;
            }
            if (s.SuccessLogins > 0 && s.FailedAttempts > 0)
            {
                s.Issues.Add("⚠ 检测到登录成功记录，请确认是否为本人操作");
                score += 40;
            }

            s.RiskScore = Math.Min(100, score);
            s.RiskLevel = score >= 60 ? "critical" : score >= 35 ? "high" : score >= 15 ? "medium" : "safe";
            foreach (var ip in s.InboundRisk.Select(c => c.RemoteIp)) s.AttackIps.Add(ip);
        }
    }
}