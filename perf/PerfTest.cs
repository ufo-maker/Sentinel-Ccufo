using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Sentinel
{
    /// <summary>核心逻辑性能实测 —— 验证分层调度与原生API 的实际收益</summary>
    internal static class PerfTest
    {
        static void Main()
        {
            Console.WriteLine("========== 采集层性能实测 ==========\n");

            var c = new Collector();
            var snap = new Snapshot();

            // 预热
            c.CollectFast(snap);

            Console.WriteLine("[首次采集（含防火墙规则解析 + 公网IP查询）]");
            var sw = Stopwatch.StartNew();
            c.CollectFast(snap);
            sw.Stop();
            Console.WriteLine($"  耗时 {sw.ElapsedMilliseconds}ms\n");

            Console.WriteLine("[连续 20 次采集 —— 验证分层调度效果]");
            var times = new List<long>();
            for (int i = 0; i < 20; i++)
            {
                var s = new Snapshot();
                var t = Stopwatch.StartNew();
                c.CollectFast(s);
                t.Stop();
                times.Add(t.ElapsedMilliseconds);
                System.Threading.Thread.Sleep(50);
            }
            times.Sort();
            Console.WriteLine($"  最小 {times[0]}ms   中位{times[10]}ms   最大 {times[19]}ms");
            Console.WriteLine($"  平均 {times.Average():F1}ms");
Console.WriteLine($"  若按 2 秒间隔轮询，CPU 占用率约 {times[10] / 20.0:F2}%\n");

            Console.WriteLine("========== 采集结果正确性 ==========\n");
            var s2 = new Snapshot();
            c.CollectFast(s2);
            Console.WriteLine("  监听端口         : " + (s2.ListeningPorts.Count>0?string.Join(",",s2.ListeningPorts):"无"));
            var dbg=new System.Collections.Generic.List<string>();
            foreach(var lp in s2.ListeningPorts) dbg.Add(lp.ToString());
            Console.WriteLine("  [debug] 端口集合大小="+s2.ListeningPorts.Count+" 内容="+string.Join("|",dbg));
            Console.WriteLine($"  公网入站连接     : {s2.InboundRisk.Count} 条");
            foreach (var r in s2.InboundRisk) Console.WriteLine($"      {r.RemoteIp}:{r.RemotePort}");
            Console.WriteLine($"  账户锁定         : {s2.AccountLocked}");
            Console.WriteLine($"  上次登录         : {s2.LastLogon}");
            Console.WriteLine($"  密码设置时间     : {s2.PasswordLastSet}");
            Console.WriteLine($"  局域网放行规则   : {s2.HasLanOnlyRule}");
            Console.WriteLine($"  全局阻断规则: {s2.HasBlockAllRule}");
            Console.WriteLine($"  旧共享规则启用   : {s2.LegacyEnabledRules}");
            Console.WriteLine($"  IP 封禁规则      : {s2.BlockedIpRules} 条");
            Console.WriteLine($"  公网 IP          : {s2.PublicIp}  {s2.PublicGeo}");
            Console.WriteLine($"  风险等级         : {s2.RiskLevel}  评分 {s2.RiskScore}");
            foreach (var i in s2.Issues) Console.WriteLine($"      - {i}");

            Console.WriteLine("\n========== 命令执行开销对照 ==========\n");
            var probes = new (string name, string cmd)[]
            {
                ("netstat -ano", "netstat -ano"),
                ("net user", "net user Administrator"),
                ("netsh 全量规则", "netsh advfirewall firewall show rule name=all"),
                ("wevtutil 200条", "wevtutil qe Security /c:200 /rd:true /f:xml"),
            };
            foreach (var (name, cmd) in probes)
            {
                var r = Cmd.Run(cmd, name, 20000);
                Console.WriteLine($"  {name,-18} {r.ElapsedMs,5}ms  {r.Raw.Length,8} 字符  ok={r.Ok}");
            }

            Console.WriteLine("\n========== 内存占用 ==========\n");
            var me = Process.GetCurrentProcess();
            me.Refresh();
            Console.WriteLine($"  工作集   : {me.WorkingSet64 / 1024 / 1024.0:F1} MB");
            Console.WriteLine($"  专用内存 : {me.PrivateMemorySize64 / 1024 / 1024.0:F1} MB");
            Console.WriteLine($"  线程数   : {me.Threads.Count}");
            Console.WriteLine($"  句柄数   : {me.HandleCount}");
        }
    }
}