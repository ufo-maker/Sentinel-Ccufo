using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace Sentinel.Perf
{
    internal static class ApiTest
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW
        {
            public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwStateSeg;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr p, ref int len, bool sort, int af, int cls, int res);

        private static void Main()
        {
            const int AF_INET = 2, CLS = 5;
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, CLS, 0);
            Console.WriteLine($"需要的缓冲区大小: {size} bytes");

            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = GetExtendedTcpTable(buf, ref size, false, AF_INET, CLS, 0);
                Console.WriteLine($"调用返回: {ret}  (0=成功)");

                int rowSize = Marshal.SizeOf<MIB_TCPROW>();
                int count = size / rowSize;
                Console.WriteLine($"行结构大小: {rowSize}  行数: {count}\n");

                int listening = 0;
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW>(IntPtr.Add(buf, i * rowSize));
                    // 端口在低 16 位且为网络字节序，需交换
                    ushort lp = (ushort)((row.dwLocalPort & 0xFF) << 8 | (row.dwLocalPort >> 8) & 0xFF);
                    ushort rp = (ushort)((row.dwRemotePort & 0xFF) << 8 | (row.dwRemotePort >> 8) & 0xFF);

                    if (row.dwState == 2)
                    {
                        listening++;
                        var addr = new System.Net.IPAddress(row.dwLocalAddr);
                        if (lp is 445 or 139 or 3389 or 80)
                            Console.WriteLine($"  LISTEN {addr}:{lp}  (原始dwLocalPort=0x{row.dwLocalPort:X8})");
                    }
                    if (row.dwState == 5 && rp > 0 && lp == 445)
                        Console.WriteLine($"  ESTAB local={lp} remote={rp}");
                }
                Console.WriteLine($"\n监听态总数: {listening}");
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }
}