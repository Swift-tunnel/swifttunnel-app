// Opt-in, out-of-process research sampler. No packet capture or routing APIs.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SwiftTunnel.UsageObservation {
    public sealed class Counts {
        public bool Valid;
        public int Players, Studio, Helpers, StudioDescendantPlayers;
        public int? PlayersWithUdp;
        public uint ProcessError, Udp4Error, Udp6Error;
    }
    public static class WindowsCounts {
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        private struct Entry {
            public uint Size, Usage, Pid;
            public UIntPtr Heap;
            public uint Module, Threads, Parent;
            public int Priority;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string Name;
        }
        [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool Process32FirstW(IntPtr snapshot, ref Entry entry);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool Process32NextW(IntPtr snapshot, ref Entry entry);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("iphlpapi.dll")] private static extern uint GetExtendedUdpTable(IntPtr table, ref uint size, bool sorted, uint family, uint tableClass, uint reserved);
        private static readonly HashSet<string> Players = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "RobloxPlayerBeta.exe", "RobloxPlayer.exe" };
        private static readonly HashSet<string> Studios = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "RobloxStudioBeta.exe", "RobloxStudio.exe" };
        private static readonly HashSet<string> Helpers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "RobloxApp.exe", "RobloxPlayerLauncher.exe", "RobloxPlayerInstaller.exe", "RobloxStudioInstaller.exe",
            "RobloxStudioLauncher.exe", "RobloxStudioLauncherBeta.exe", "Voidstrap.exe", "Voidstrap.Desktop.Windows.exe",
            "Bloxstrap.exe", "Fishstrap.exe", "Froststrap.exe", "Bubblestrap.exe"
        };
        private static uint UdpOwners(uint family, HashSet<uint> owners) {
            uint size=0;
            uint code=GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, 1, 0);
            if(code!=122 && code!=0) return code;
            for(int attempt=0;attempt<3;attempt++) {
                if(size<4 || size>8*1024*1024) return 13;
                IntPtr buffer=Marshal.AllocHGlobal((int)size);
                try {
                    uint allocated=size;
                    code=GetExtendedUdpTable(buffer, ref size, false, family, 1, 0);
                    if(code==122) continue;
                    if(code!=0) return code;
                    int stride=family==2?12:28, pidOffset=family==2?8:24;
                    uint count=unchecked((uint)Marshal.ReadInt32(buffer));
                    if(size>allocated || count>((size-4)/(uint)stride)) return 13;
                    for(uint i=0;i<count;i++) owners.Add(unchecked((uint)Marshal.ReadInt32(buffer, checked(4+(int)i*stride+pidOffset))));
                    return 0;
                } finally { Marshal.FreeHGlobal(buffer); }
            }
            return code;
        }
        public static Counts Capture() {
            var result=new Counts();
            var entries=new Dictionary<uint,Entry>();
            IntPtr snapshot=CreateToolhelp32Snapshot(2,0);
            if(snapshot==new IntPtr(-1)) { result.ProcessError=(uint)Marshal.GetLastWin32Error(); return result; }
            try {
                var entry=new Entry { Size=(uint)Marshal.SizeOf(typeof(Entry)) };
                bool next=Process32FirstW(snapshot,ref entry);
                while(next) {
                    if(entries.Count>=32768) { result.ProcessError=234; return result; }
                    entries[entry.Pid]=entry;
                    next=Process32NextW(snapshot,ref entry);
                }
                uint error=(uint)Marshal.GetLastWin32Error();
                if(error!=18) { result.ProcessError=error; return result; }
            } finally { CloseHandle(snapshot); }
            foreach(var pair in entries) {
                var entry=pair.Value;
                if(Studios.Contains(entry.Name)) result.Studio++;
                if(Helpers.Contains(entry.Name)) result.Helpers++;
                if(!Players.Contains(entry.Name)) continue;
                result.Players++;
                uint parent=entry.Parent;
                for(int depth=0;depth<8;depth++) {
                    Entry ancestor;
                    if(!entries.TryGetValue(parent,out ancestor) || ancestor.Pid==entry.Pid) break;
                    if(Studios.Contains(ancestor.Name)) { result.StudioDescendantPlayers++; break; }
                    if(ancestor.Parent==parent) break;
                    parent=ancestor.Parent;
                }
            }
            // There is no reason to enumerate system UDP bindings while Roblox
            // Player is closed. This is also the usual idle sampling case.
            if(result.Players==0) result.PlayersWithUdp=0;
            else {
                var udp=new HashSet<uint>();
                result.Udp4Error=UdpOwners(2,udp);
                result.Udp6Error=UdpOwners(23,udp);
                int withUdp=0;
                foreach(var pair in entries) if(Players.Contains(pair.Value.Name) && udp.Contains(pair.Key)) withUdp++;
                result.PlayersWithUdp=result.Udp4Error==0 && result.Udp6Error==0?(int?)withUdp:null;
            }
            result.Valid=true;
            return result;
        }
    }
}
