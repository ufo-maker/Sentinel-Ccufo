using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Sentinel
{
    /// <summary>命令输出分级
    /// 专业做法：命令永远完整记录（审计需要），输出按量级分级展示——
    /// 小输出内联、中等输出掐头去尾、大输出落盘只给摘要。
    /// 避免几十万行日志灌进界面导致卡死，也避免"什么都没看到"的黑盒感。
    /// </summary>
    public sealed class OutputFormatter
    {
        public const int InlineLimit = 5_000;      // ≤5KB 内联完整显示
        public const int HeadTailLimit = 50_000;   // ≤50KB掐头去尾
        public const int HeadLines = 18;
        public const int TailLines = 12;

        public static string LogDir
        {
            get
            {
                var d = Path.Combine(Path.GetTempPath(), "Sentinel-Ccufo", "logs");
                Directory.CreateDirectory(d);
                return d;
            }
        }

        public enum Level { Inline, HeadTail, FileOnly }

        public static Level Classify(int rawLength)
            => rawLength <= InlineLimit ? Level.Inline
             : rawLength <= HeadTailLimit ? Level.HeadTail
             : Level.FileOnly;

        /// <summary>把完整输出写入日志文件，返回文件路径</summary>
        public static string SaveToFile(string cmd, string raw, bool ok)
        {
            try
            {
                var name = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Sanitize(cmd)}_{raw.Length}b.txt";
                var path = Path.Combine(LogDir, name);

                var sb = new StringBuilder(raw.Length + 512);
                sb.AppendLine("=" .PadRight(72, '='));
                sb.AppendLine($"命令: {cmd}");
                sb.AppendLine($"时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"结果: {(ok ? "成功" : "失败")}    大小: {raw.Length:N0} 字符");
                sb.AppendLine("=".PadRight(72, '='));
                sb.AppendLine();
                sb.Append(raw);
                File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
                return path;
            }
            catch { return ""; }
        }

        /// <summary>生成界面要显示的摘要文本</summary>
        public static string ForDisplay(string raw, out string filePath)
        {
            filePath = "";
            if (string.IsNullOrEmpty(raw)) return "";

            switch (Classify(raw.Length))
            {
                case Level.Inline:
                    return raw;

                case Level.HeadTail:
                {
                    var lines = raw.Split('\n');
                    var sb = new StringBuilder();
                    sb.AppendLine(string.Join("\n", lines.Take(HeadLines)));
                    sb.AppendLine($"\n        ……… 中间省略 {lines.Length - HeadLines - TailLines} 行 "
                                + $"(完整输出 {raw.Length:N0} 字符) ………\n");
                    if (lines.Length > HeadLines + TailLines)
                        sb.AppendLine(string.Join("\n", lines.Skip(lines.Length - TailLines)));
                    return sb.ToString().TrimEnd('\n');
                }

                default:
                {
                    filePath = SaveToFile("", raw, true);
                    var lines = raw.Split('\n');
                    var head = lines.Take(6).Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0);
                    var sb = new StringBuilder();
                    sb.AppendLine(string.Join("\n", head));
                    sb.AppendLine();
                    sb.AppendLine($"⤓ 输出过大，已保存到文件（{raw.Length:N0} 字符 / {lines.Length:N0} 行）");
                    sb.AppendLine($"  {filePath}");
                    return sb.ToString();
                }
            }
        }

        /// <summary>日志面板顶部摘要（无论是否落盘都显示这几行关键信息）</summary>
        public static string Header(string cmd, string raw, long ms, bool ok)
        {
            int lines = string.IsNullOrEmpty(raw) ? 0 : raw.Split('\n').Length;
            var sb = new StringBuilder();
            sb.AppendLine($"命令: {cmd}");
            sb.AppendLine($"结果: {(ok ? "成功" : "失败")}    耗时: {ms}ms    "
                        + $"输出: {raw.Length:N0} 字符 / {lines:N0} 行");
            return sb.ToString();
        }

        static string Sanitize(string cmd)
        {
            var bad = new[] { '/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ' };
            var s = cmd.Length > 28 ? cmd[..28] : cmd;
            foreach (var c in bad) s = s.Replace(c, '_');
            return s;
        }
    }
}