using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace Sentinel
{
    internal static class IconGen
    {
        static Bitmap Render(int s)
        {
            var bmp = new Bitmap(s, s);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            float k = s / 64f;
            var dark = Color.FromArgb(9, 14, 23);

            using var shadow = new SolidBrush(Color.FromArgb(70, 0, 0, 0));
            g.FillEllipse(shadow, 10 * k, 54 * k, 44 * k, 7 * k);

            using var path = new System.Drawing.Drawing2D.GraphicsPath();
            path.AddArc(12f * k, 8f * k, 40f * k, 40f * k, 180f, 180f);
            path.AddLine(new PointF(32f * k, 57f * k), new PointF(32f * k, 57f * k));
            path.CloseFigure();

            using (var br = new LinearGradientBrush(
                new RectangleF(0, 0, s, s),
                Color.FromArgb(56, 189, 248),
                Color.FromArgb(12, 110, 140), 90f))
                g.FillPath(br, path);

            using (var pen = new Pen(Color.FromArgb(103, 232, 249), 1.7f * k))
                g.DrawPath(pen, path);

            using (var ib = new SolidBrush(dark))
            {
                float bw = 5.4f * k;
                g.FillRectangle(ib, 32 * k - bw / 2, 20 * k, bw, 17 * k);
                float d = 5.6f * k;
                g.FillEllipse(ib, 32 * k - d / 2, 41 * k, d, d);
            }
            return bmp;
        }

        public static void Generate(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };

            var images = new byte[sizes.Length][];
            for (int i = 0; i < sizes.Length; i++)
            {
                using var bmp = Render(sizes[i]);
                using var bms = new MemoryStream();
                bmp.Save(bms, ImageFormat.Png);
                images[i] = bms.ToArray();
            }

            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);
            w.Write((ushort)0);
            w.Write((ushort)1);
            w.Write((ushort)sizes.Length);

            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                int s = sizes[i];
                w.Write((byte)(s >= 256 ? 0 : s));
                w.Write((byte)(s >= 256 ? 0 : s));
                w.Write((byte)0);
                w.Write((byte)0);
                w.Write((ushort)1);
                w.Write((ushort)32);
                w.Write(images[i].Length);
                w.Write(offset);
                offset += images[i].Length;
            }
            foreach (var img in images) w.Write(img);
            w.Flush();

            File.WriteAllBytes(path, ms.ToArray());
            Console.WriteLine($"OK: {path}  {new FileInfo(path).Length} bytes, {sizes.Length} sizes");
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            var target = args.Length > 0 ? args[0] : "sentinel.ico";
            IconGen.Generate(target);
        }
    }
}