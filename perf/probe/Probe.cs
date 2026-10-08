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

        private static uint Swap16(uint v) => ((v & 0xFF) << 8) | ((v >> 8) & 0xFF);

        private static void Main()
        {
            foreach (var cls in new[] { 5, 1, 0 })
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, cls, 0);
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    GetExtendedTcpTable(buf, ref size, false, 2, cls, 0);

                    uint first = (uint)Marshal.ReadInt32(buf, 0);
                    int rowSize = Marshal.SizeOf<MIB_TCPROW>();
                    int rowsBySize = size / rowSize;

                    Console.WriteLine($"\n--- AF_INET, class={cls} ---");
                    Console.WriteLine($"  size={size}  行数(按结构体)={rowsBySize}  首uint32={first}");

                    int dataOff = 4;
                    int countA = (size - dataOff) / rowSize;
                    int listenA = 0; ushort lpA = 0;
                    for (int i = 0; i < countA; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW>(IntPtr.Add(buf, dataOff + i * rowSize));
                        if (row.dwState == 2) { listenA++; lpA = (ushort)Swap16(row.dwLocalPort); }
                    }
                    Console.WriteLine($"  A(跳4字节头): 行数={countA} 监听={listenA} 端口={lpA}");

                    int listenB = 0; ushort lpB = 0;
                    for (int i = 0; i < rowsBySize; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW>(IntPtr.Add(buf, i * rowSize));
                        if (row.dwState == 2) { listenB++; lpB = (ushort)Swap16(row.dwLocalPort); }
                    }
                    Console.WriteLine($"  B(不跳头):     行数={rowsBySize} 监听={listenB} 端口={lpB}");
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
    }
}