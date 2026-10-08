using System;
using System.Drawing;
using System.Windows.Forms;

namespace Sentinel
{
    /// <summary>主题与字体管理
    /// 问题：原版各处new Font(...) 且硬编码像素尺寸，窗口缩放后字号与间距不跟随，
    /// 高 DPI 下更会错乱。此处集中管理并按当前 DPI 缩放。
    /// </summary>
    public static class Theme
    {
        // ---- 配色 ----
        public static readonly Color Bg0 = Color.FromArgb(9, 12, 19);
        public static readonly Color Bg1 = Color.FromArgb(16, 21, 32);
        public static readonly Color Bg2 = Color.FromArgb(22, 28, 41);
        public static readonly Color Bg3 = Color.FromArgb(30, 38, 54);
        public static readonly Color BgHover = Color.FromArgb(28, 35, 50);
        public static readonly Color Line = Color.FromArgb(32, 40, 55);
        public static readonly Color LineSoft = Color.FromArgb(26, 33, 46);

        public static readonly Color Tx1 = Color.FromArgb(230, 237, 247);
        public static readonly Color Tx2 = Color.FromArgb(147, 163, 184);
        public static readonly Color Tx3 = Color.FromArgb(108, 122, 142);
        public static readonly Color Tx4 = Color.FromArgb(78, 90, 108);

        public static readonly Color Cyan = Color.FromArgb(34, 211, 238);
        public static readonly Color Green = Color.FromArgb(16, 185, 129);
        public static readonly Color Amber = Color.FromArgb(245, 158, 11);
        public static readonly Color Red = Color.FromArgb(239, 68, 68);
        public static readonly Color Purple = Color.FromArgb(167, 139, 250);

        // ---- 字体（延迟创建，随 DPI 更新）----
        static Font _fBase, _fTitle, _fMono, _fMonoBold, _fBig, _fSmall, _fSmallBold,
                    _fStat, _fGaugeNum, _fSection;

        /// <summary>当前缩放因子（1.0 = 100% DPI）</summary>
        public static float Scale { get; private set; } = 1f;

        public static void InitScale(Control reference)
        {
            try
            {
                var dpi = reference.DeviceDpi;
                if (dpi > 0) Scale = dpi / 96f;
            }
            catch { Scale = 1f; }
            if (Scale < 1f) Scale = 1f;
            Rebuild();
        }

        static void Rebuild()
        {
            DisposeAll();
            _fBase = new Font("Microsoft YaHei UI", 9f * Scale, FontStyle.Regular);
            _fTitle = new Font("Microsoft YaHei UI", 9.5f * Scale, FontStyle.Regular);
            _fSection = new Font("Microsoft YaHei UI", 9f * Scale, FontStyle.Bold);
            _fSmall = new Font("Microsoft YaHei UI", 8f * Scale, FontStyle.Regular);
            _fSmallBold = new Font("Microsoft YaHei UI", 8.5f * Scale, FontStyle.Bold);
            _fBig = new Font("Microsoft YaHei UI", 11f * Scale, FontStyle.Regular);
            _fStat = new Font("Consolas", 13f * Scale, FontStyle.Regular);
            _fGaugeNum = new Font("Segoe UI Light", 30f * Scale, FontStyle.Regular);
            _fMono = new Font("Consolas", 8.5f * Scale, FontStyle.Regular);
            _fMonoBold = new Font("Consolas", 9f * Scale, FontStyle.Bold);
        }

        static void DisposeAll()
        {
            foreach (var f in new[] { _fBase, _fTitle, _fMono, _fMonoBold, _fBig,
                                     _fSmall, _fSmallBold, _fStat, _fGaugeNum, _fSection })
                f?.Dispose();
        }

        public static Font Base => _fBase ??= new Font("Microsoft YaHei UI", 9f);
        public static Font Title => _fTitle ??= new Font("Microsoft YaHei UI", 9.5f);
        public static Font Section => _fSection ??= new Font("Microsoft YaHei UI", 9f, FontStyle.Bold);
        public static Font Small => _fSmall ??= new Font("Microsoft YaHei UI", 8f);
        public static Font SmallBold => _fSmallBold ??= new Font("Microsoft YaHei UI", 8.5f, FontStyle.Bold);
        public static Font Big => _fBig ??= new Font("Microsoft YaHei UI", 11f);
        public static Font Stat => _fStat ??= new Font("Consolas", 13f);
        public static Font GaugeNum => _fGaugeNum ??= new Font("Segoe UI Light", 30f);
        public static Font Mono => _fMono ??= new Font("Consolas", 8.5f);
        public static Font MonoBold => _fMonoBold ??= new Font("Consolas", 9f, FontStyle.Bold);

        /// <summary>按缩放构造任意字号的字体（需调用方自行 Dispose）</summary>
        public static Font Bold(float pt) => new("Microsoft YaHei UI", pt * Scale, FontStyle.Bold);

        /// <summary>像素值按 DPI 缩放</summary>
        public static int P(int px) => (int)Math.Round(px * Scale);

        /// <summary>按缩放构造尺寸</summary>
        public static Size Sz(int w, int h) => new(P(w), P(h));
    }
}