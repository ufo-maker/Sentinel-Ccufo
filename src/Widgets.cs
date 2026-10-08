using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Sentinel
{
    /// <summary>圆角面板基类 —— 四段圆弧拼圆角 + 顶部高光</summary>
    public class CardBase : Panel
    {
        public int Radius { get; set; } = 12;
        public Color BorderColor { get; set; } = Theme.Line;
        public Color FillColor { get; set; } = Theme.Bg1;

        public CardBase()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = FillColor;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var g = e.Graphics;
            var r = new Rectangle(0, 0, Width - 1, Height - 1);
            int d = Radius * 2;
            if (d <= 0 || r.Width <= 0 || r.Height <= 0) { base.OnPaint(e); return; }

            using (var path = new GraphicsPath())
            {
                path.AddArc(r.X, r.Y, d, d, 180, 90);
                path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
                path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
                path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
                path.CloseFigure();

                using (var brush = new SolidBrush(FillColor)) g.FillPath(brush, path);
                using (var pen = new Pen(BorderColor, 1f)) g.DrawPath(pen, path);
                using (var hl = new Pen(Color.FromArgb(20, 90, 110), 1f))
                    g.DrawLine(hl, Radius, 1, Math.Max(Radius, Width - Radius), 1);
            }
            base.OnPaint(e);
        }
    }

    /// <summary>圆角卡片</summary>
    public sealed class Card : CardBase
    {
    }

    /// <summary>风险仪表盘
    /// 设计：270° 四段色带 + 外圈刻度 + 中心大数字 + 分级状态胶囊
    /// 比单色圆弧更有层次，刻度让"当前值落在哪个区间"一目了然。
    /// </summary>
    public sealed class Gauge : Control
    {
        int _value;
        Color _accent = Theme.Green;

        public int Value
        {
            get => _value;
            set
            {
                var v = Math.Clamp(value, 0, 100);
                if (_value == v) return;
                _value = v;
                Invalidate();
            }
        }

        public Color Accent
        {
            get => _accent;
            set { if (_accent == value) return; _accent = value; Invalidate(); }
        }

        public Gauge()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Bg1;
            Height = Theme.P(152);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            g.Clear(Theme.Bg1);

            float cx = Width / 2f;
            float cy = Theme.P(84);
            float r = Math.Max(Theme.P(40), Math.Min(Width / 2f - Theme.P(26), Theme.P(60)));

            float stroke = Theme.P(9);
            var rect = new RectangleF(cx - r, cy - r, r * 2, r * 2);
            const float start = 135f, sweep = 270f;

            // 1. 底层轨道
            using (var track = new Pen(Theme.Bg3, stroke) { StartCap = LineCap.Flat, EndCap = LineCap.Flat })
                g.DrawArc(track, rect, start, sweep);

            // 2. 四档区间底色
            DrawBand(g, rect, start, sweep, 0.00f, 0.15f, Color.FromArgb(30, 16, 185, 129));
            DrawBand(g, rect, start, sweep, 0.15f, 0.20f, Color.FromArgb(32, 245, 158, 11));
            DrawBand(g, rect, start, sweep, 0.35f, 0.25f, Color.FromArgb(38, 239, 68, 68));
            DrawBand(g, rect, start, sweep, 0.60f, 0.40f, Color.FromArgb(52, 239, 68, 68));

            // 3. 进度弧
            if (_value > 0)
            {
                using var prog = new Pen(_accent, stroke) { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawArc(prog, rect, start, sweep * (_value / 100f));
            }

            // 4. 外圈刻度
            DrawTicks(g, cx, cy, r + stroke / 2 + Theme.P(6), start, sweep);

            // 5. 中心数值 + 分母
            using (var nb = new SolidBrush(Theme.Tx1))
            {
                var sz = g.MeasureString(_value.ToString(), Theme.GaugeNum);
                g.DrawString(_value.ToString(), Theme.GaugeNum, nb,
                    cx - sz.Width / 2f, cy - sz.Height / 2f - Theme.P(3));
            }
            using (var ub = new SolidBrush(Theme.Tx4))
            {
                var t = "/ 100";
                var sz = g.MeasureString(t, Theme.Small);
                g.DrawString(t, Theme.Small, ub, cx - sz.Width / 2f, cy + Theme.P(15));
            }

            // 6. 状态胶囊
            var (label, col) = LevelInfo();
            DrawCapsule(g, cx, Height - Theme.P(24), label, col);

            // 7. 高危闪烁指示
            if (_value >= 60 && Environment.TickCount % 1000 < 550)
            {
                using var blink = new SolidBrush(Color.FromArgb(210, _accent));
                g.FillEllipse(blink, cx + Theme.P(54), Theme.P(14), Theme.P(7), Theme.P(7));
            }

            base.OnPaint(e);
        }

        void DrawBand(Graphics g, RectangleF rect, float start, float total,
                      float from, float len, Color color)
        {
            if (color.A == 0) return;
            using var pen = new Pen(color, Theme.P(9)) { StartCap = LineCap.Flat, EndCap = LineCap.Flat };
            g.DrawArc(pen, rect, start + total * from, total * len);
        }

        void DrawTicks(Graphics g, float cx, float cy, float r, float start, float sweep)
        {
            for (int i = 0; i <= 10; i++)
            {
                float t = i / 10f;
                double rad = (start + sweep * t) * Math.PI / 180.0;
                bool major = i % 5 == 0;
                float len = major ? Theme.P(7) : 3.5f * Theme.Scale;

                float x1 = cx + (float)(Math.Cos(rad) * r);
                float y1 = cy + (float)(Math.Sin(rad) * r);
                float x2 = cx + (float)(Math.Cos(rad) * (r + len));
                float y2 = cy + (float)(Math.Sin(rad) * (r + len));

                using var pen = new Pen(major
                    ? Color.FromArgb(160, _accent)
                    : Color.FromArgb(64, 147, 163, 184), 1f);
                g.DrawLine(pen, x1, y1, x2, y2);
            }
        }

        void DrawCapsule(Graphics g, float cx, float y, string text, Color col)
        {
            var font = Theme.SmallBold;
            var sz = g.MeasureString(text, font);
            float w = sz.Width + Theme.P(24);
            float h = Theme.P(22);
            var rect = new RectangleF(cx - w / 2, y, w, h);

            using var path = new GraphicsPath();
            path.AddArc(rect.X, rect.Y, h, h, 180, 180);
            path.AddArc(rect.Right - h, rect.Y, h, h, 0, 180);
            path.CloseFigure();

            using (var fill = new SolidBrush(Color.FromArgb(40, col.R, col.G, col.B)))
                g.FillPath(fill, path);
            using (var pen = new Pen(Color.FromArgb(115, col.R, col.G, col.B), 1f))
                g.DrawPath(pen, path);
            using var tb = new SolidBrush(col);
            g.DrawString(text, font, tb, cx - sz.Width / 2f, y + h / 2f - sz.Height / 2f);
        }

        (string, Color) LevelInfo()
        {
            if (_value >= 60) return ("严重风险", Theme.Red);
            if (_value >= 35) return ("偏高", Theme.Amber);
            if (_value >= 15) return ("中等", Color.FromArgb(250, 190, 60));
            if (_value > 0) return ("轻微", Theme.Green);
            return ("安全", Theme.Green);
        }
    }

    /// <summary>托盘图标生成 —— 代码绘制，无外部资源</summary>
    public static class IconFactory
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr h);

        public static Icon CreateShield(Color accent, bool alert)
        {
            using var bmp = new Bitmap(32, 32);
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);

                var col = alert ? Theme.Red : accent;
                using var brush = new SolidBrush(col);
                using var path = new GraphicsPath();
                path.AddArc(6f, 4f, 20f, 20f, 180f, 180f);
                path.AddLine(new PointF(16f, 28f), new PointF(16f, 28f));
                path.CloseFigure();
                g.FillPath(brush, path);

                using var ib = new SolidBrush(Color.FromArgb(12, 18, 28));
                g.FillRectangle(ib, 14, 10, 4, 10);
                g.FillRectangle(ib, 14, 22, 4, 4);
            }

            IntPtr h = bmp.GetHicon();
            try
            {
                using var tmp = Icon.FromHandle(h);
                return (Icon)tmp.Clone();
            }
            finally { DestroyIcon(h); }
        }
    }
}