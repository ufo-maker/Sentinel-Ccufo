using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace Sentinel
{
    /// <summary>生成应用图标 assets\sentinel.ico —— 多尺寸 ICO，纯代码绘制</summary>
    internal static class IconGen
    {
        static Bitmap Render(int s)
        {
            var bmp = new Bitmap(s, s);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            float k = s / 64f;
            var accent = Color.FromArgb(34, 211, 238);
            var dark = Color.FromArgb(10, 15, 24);

            using var shadow = new SolidBrush(Color.FromArgb(90, 0, 0, 0));
            g.FillEllipse(shadow, 6 * k, 52 * k, 52 * k, 10 * k);

            // 盾牌主体：青蓝纵向渐变
            using var path = new System.Drawing.Drawing2D.GraphicsPath();
            path.AddArc(12 * k, 8 * k, 40 * k, 40 * k, 180, 180);
            path.AddLineTo(32 * k, 58 * k);
            path.CloseFigure();

            using (var br = new LinearGradientBrush(
                new RectangleF(0, 0, s, s),
                Color.FromArgb(56, 189, 248),
                Color.FromArgb(14, 116, 144), 90f))
                g.FillPath(br, path);

            using (var pen = new Pen(Color.FromArgb(103, 232, 249), 1.6f * k))
                g.DrawPath(pen, path);

            // 中央感叹号
            using (var ib = new SolidBrush(dark))
            {
                var barW = 5.2f * k;
                g.FillRectangle(ib, 32 * k - barW / 2, 20 * k, barW, 18 * k);
                var d = 5.4f * k;
                g.FillEllipse(ib, 32 * k - d / 2, 42 * k, d, d);
            }
            return bmp;
        }

        public static void Generate(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };

            using var ms = new MemoryStream();
            var writer = new BinaryWriter(ms);
            writer.Write((ushort)0);      // reserved
            writer.Write((ushort)1);      // type=icon
            writer.Write((ushort)sizes.Length);

            var images = new byte[sizes.Length][];
            for (int i = 0; i < sizes.Length; i++)
            {
                using var bmp = Render(sizes[i]);
                using var bms = new MemoryStream();
                bmp.Save(bms, ImageFormat.Png);
                images[i] = bms.ToArray();
            }

            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                int s = sizes[i];
                writer.Write((byte)(s >= 256 ? 0 : s));
                writer.Write((byte)(s >= 256 ? 0 : s));
                writer.Write((byte)0);
                writer.Write((byte)0);
                writer.Write((ushort)1);
                writer.Write((ushort)32);
                writer.Write(images[i].Length);
                writer.Write(offset);
                offset += images[i].Length;
            }
            foreach (var img in images) writer.Write(img);
            writer.Flush();

            File.WriteAllBytes(path, ms.ToArray());
            Console.WriteLine($"icon written: {path} ({new FileInfo(path).Length} bytes, {sizes.Length} sizes)");
        }
    }
}