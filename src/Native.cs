using System;
using System.Runtime.InteropServices;

namespace Sentinel
{
    /// <summary>Win32 原生调用
    /// 用途：标题栏拖动窗口、双击最大化等系统级行为，
    /// 自绘标题栏若不处理这些消息会导致窗口无法拖动/最大化。
    /// </summary>
    internal static class Native
    {
        // ReleaseCapture：释放鼠标捕获，让系统接管拖动
        [DllImport("user32.dll")]
        public static extern bool ReleaseCapture();

        // SendMessage：发送窗口消息
        // WM_NCLBUTTONDOWN = 0xA1，HTCAPTION = 2 → 表示"在标题栏按下左键"，系统会处理拖动与双击最大化
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        // 贴到工作区最大化（不覆盖任务栏）
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        public const int SW_MAXIMIZE = 3;
        public const int SW_RESTORE = 9;

        [DllImport("user32.dll")]
        public static extern bool IsZoomed(IntPtr hWnd);

        public const int MONITOR_DEFAULTTONEAREST = 2;

        [DllImport("shcore.dll")]
        public static extern int GetDpiForMonitor(IntPtr hmonitor, int dpiType, out uint dpiX, out uint dpiY);
    }
}