using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Sentinel
{
    internal static class Program
    {
        [DllImport("kernel32.dll")]
        private static extern bool SetProcessDpiAwareness(int awareness);

        [STAThread]
        private static void Main()
        {
            // 高DPI 感知，避免模糊
            try { SetProcessDpiAwareness(2); } catch { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetHighDpiMode(HighDpiMode.SystemAware);

            Application.Run(new MainForm());
        }
    }
}