using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace Sentinel
{
    /// <summary>命令执行结果 —— 完整保留命令与输出，供界面逐步展示</summary>
    public sealed class CmdResult
    {
        public string Label { get; init; } = "";
        public string Cmd { get; init; } = "";
        public string Raw { get; init; } = "";
        public bool Ok { get; init; }
        public int Code { get; init; }
        public long ElapsedMs { get; init; }
    }

    /// <summary>命令执行器
    /// 关键坑：Windows 中文版命令输出编码不统一
    ///   net user / netsh set → GBK(CP936)
    ///   netsh show           → UTF-8
    /// 必须以字节流读取后「双解码择优」，否则中文全变乱码，字段解析必然失败。
    /// </summary>
    public static class Cmd
    {
        private static readonly Encoding Gb = Encoding.GetEncoding(936); // GBK

        /// <summary>执行命令并返回结果。永不抛异常，失败以 Ok=false 表达。</summary>
        public static CmdResult Run(string cmd, string label, int timeoutMs = 15000)
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = null,   // 不指定 → 交由 BaseStream 取原始字节
                StandardErrorEncoding = null
            };

            var sw = Stopwatch.StartNew();
            try
            {
                using var p = Process.Start(psi);
                if (p == null)
                    return new CmdResult { Label = label, Cmd = cmd, Raw = "进程启动失败", Ok = false, Code = -1 };

                // 读取原始字节，避免 .NET 用默认编码破坏 GBK 内容
                using var ms = new System.IO.MemoryStream();
                p.StandardOutput.BaseStream.CopyTo(ms);
                string stdout = DecodeSmart(ms.ToArray());

                using var msErr = new System.IO.MemoryStream();
                p.StandardError.BaseStream.CopyTo(msErr);
                string stderr = DecodeSmart(msErr.ToArray());

                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch { }
                    return new CmdResult
                    {
                        Label = label, Cmd = cmd,
                        Raw = Truncate(stdout) + $"\n[超时 {timeoutMs}ms 已终止]",
                        Ok = false, Code = -2, ElapsedMs = sw.ElapsedMilliseconds
                    };
                }
                sw.Stop();

                var text = stdout;
                if (stderr.Length > 0) text += (text.Length > 0 ? "\n" : "") + "[stderr] " + stderr;

                return new CmdResult
                {
                    Label = label, Cmd = cmd, Raw = Truncate(text),
                    Ok = p.ExitCode == 0, Code = p.ExitCode, ElapsedMs = sw.ElapsedMilliseconds
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new CmdResult
                {
                    Label = label, Cmd = cmd, Raw = "异常: " + ex.Message,
                    Ok = false, Code = -3, ElapsedMs = sw.ElapsedMilliseconds
                };
            }
        }

        /// <summary>双解码择优：GBK 与 UTF-8 各解一遍，取「乱码更少且含中文」的那份。
        /// 评分 = 替换字符数*10 - 汉字数，越小越优。</summary>
        public static string DecodeSmart(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return "";
            string utf8;
            try { utf8 = Encoding.UTF8.GetString(bytes); }
            catch { utf8 = ""; }

            string gbk;
            try { gbk = Gb.GetString(bytes); }
            catch { gbk = ""; }

            int Score(string s)
            {
                if (string.IsNullOrEmpty(s)) return int.MaxValue;
                int bad = 0, good = 0;
                foreach (var ch in s)
                {
                    if (ch == '\ufffd') bad++;
                    else if (ch >= 0x4E00 && ch <= 0x9FA5) good++;
                }
                return bad * 10 - good;
            }
            return Score(gbk) <= Score(utf8) ? gbk : utf8;
        }

        /// <summary>输出上限保护，防止 netsh 全量规则撑爆内存</summary>
        private static string Truncate(string s, int max = 200_000)
        {
            if (string.IsNullOrEmpty(s)) return "";
            s = s.Replace("\r\n", "\n").Replace('\r', '\n');
            return s.Length <= max ? s : s[..max] + $"\n…(已截断，共 {s.Length} 字符)";
        }
    }
}