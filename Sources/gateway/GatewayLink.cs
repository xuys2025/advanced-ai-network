using System;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace AdvancedAINetwork.Gateway {
    // The IP packet keeps its destination. Only the Ethernet next hop changes.
    // No global routes, proxy settings, ARP entries, or adapter settings are written.
    public sealed class GatewayLink : IDisposable {
        public static IPAddress ParseGateway(string value) {
            IPAddress ip;
            if (value == null || !IPAddress.TryParse(value, out ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ip.ToString() != value)
                throw new IOException("请输入完整的 IPv4 网关地址，例如 192.168.1.254。");
            var b=ip.GetAddressBytes();
            if(b[0]==0||b[0]==127||b[0]>=224||b[0]==169&&b[1]==254)throw new IOException("网关必须是局域网中的单播地址。");
            return ip;
        }
        public static bool SameSubnet(IPAddress local, IPAddress gateway, IPAddress mask) {
            if(local.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||mask==null)return false;
            var a=local.GetAddressBytes();var b=gateway.GetAddressBytes();var m=mask.GetAddressBytes();bool network=true,broadcast=true;
            for(int i=0;i<4;i++){if((a[i]&m[i])!=(b[i]&m[i]))return false;network&=(b[i]&~m[i])==0;broadcast&=(b[i]|m[i])==255;}
            return !local.Equals(gateway)&&!network&&!broadcast;
        }
        public static string ResolveSource(string adapter,string gateway) {
            var target=ParseGateway(gateway);
            var nic=Array.Find(NetworkInterface.GetAllNetworkInterfaces(),n=>n.Id.Equals(adapter,StringComparison.OrdinalIgnoreCase));
            if(nic==null||nic.OperationalStatus!=OperationalStatus.Up)throw new IOException("当前网卡不可用。");
            foreach(var ip in nic.GetIPProperties().UnicastAddresses)if(ip.Address.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork&&SameSubnet(ip.Address,target,ip.IPv4Mask))return ip.Address.ToString();
            throw new IOException("网关必须与当前网卡在同一子网，且不能是本机、网络或广播地址。");
        }
        readonly byte[] source, destination;
        readonly string interfaceId, sourceAddress, gatewayAddress;
        readonly object sync = new object();
        IntPtr handle;
        public readonly string AdapterName;
        public string GatewayMac { get { lock(sync) return BitConverter.ToString(destination); } }

        public GatewayLink(string interfaceId, string sourceAddress, string gatewayAddress) {
            this.interfaceId=interfaceId;this.sourceAddress=sourceAddress;this.gatewayAddress=gatewayAddress;
            var nic = Array.Find(NetworkInterface.GetAllNetworkInterfaces(),
                item => string.Equals(item.Id, interfaceId, StringComparison.OrdinalIgnoreCase));
            if (nic == null || nic.OperationalStatus != OperationalStatus.Up)
                throw new IOException("The selected Ethernet adapter is unavailable.");
            if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet)
                throw new IOException("This prototype has only been designed for Ethernet adapters.");
            source = nic.GetPhysicalAddress().GetAddressBytes();
            if (source.Length != 6) throw new IOException("An Ethernet MAC address is required.");
            var local = IPAddress.Parse(sourceAddress);
            var gateway = ParseGateway(gatewayAddress);
            if (local.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                gateway.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new IOException("Only IPv4 is supported.");
            bool onLink = false;
            foreach (var address in nic.GetIPProperties().UnicastAddresses) {
                if (!address.Address.Equals(local) || address.IPv4Mask == null) continue;
                onLink |= SameSubnet(local, gateway, address.IPv4Mask);
            }
            if (!onLink || local.Equals(gateway)) throw new IOException("The gateway must be a different host on this adapter's subnet.");
            destination = new byte[6];
            uint length = 6;
            uint result = SendARP(BitConverter.ToUInt32(gateway.GetAddressBytes(), 0),
                BitConverter.ToUInt32(local.GetAddressBytes(), 0), destination, ref length);
            if (result != 0 || length != 6 || (destination[0] & 1) != 0)
                throw new IOException("The local gateway could not be resolved by ARP (" + result + ").");

            // Load the user's separately installed Npcap from the system directory.
            // Npcap binaries are deliberately not bundled with this project.
            string library = Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll");
            if (!File.Exists(library)) throw new IOException("Npcap is not installed. No interception was started.");
            if (LoadLibraryEx(library, IntPtr.Zero, 0x100 | 0x1000) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot load the system Npcap library.");
            AdapterName = "\\Device\\NPF_" + nic.Id;
            var error = new StringBuilder(256);
            handle = pcap_open_live(AdapterName, 65535, 0, 1, error);
            if (handle == IntPtr.Zero) throw new IOException("Npcap adapter open failed: " + error);
            try {
                if (pcap_datalink(handle) != 1) throw new IOException("The adapter does not expose Ethernet frames.");
                // Injection only; do not collect unrelated traffic in a capture buffer.
                var program = new BpfProgram();
                if (pcap_compile(handle, ref program, "len = 0", 1, uint.MaxValue) != 0)
                    throw new IOException("Cannot prepare the injection-only filter.");
                try { if (pcap_setfilter(handle, ref program) != 0) throw new IOException("Cannot set the injection-only filter."); }
                finally { pcap_freecode(ref program); }
            } catch { Dispose(); throw; }
        }

        public void Refresh() {
            var nic=Array.Find(NetworkInterface.GetAllNetworkInterfaces(),item=>string.Equals(item.Id,interfaceId,StringComparison.OrdinalIgnoreCase));
            if(nic==null||nic.OperationalStatus!=OperationalStatus.Up)throw new IOException("Ethernet adapter is offline.");
            bool present=false;foreach(var ip in nic.GetIPProperties().UnicastAddresses)if(ip.Address.ToString()==sourceAddress)present=true;
            if(!present)throw new IOException("Ethernet address changed; gateway service must reconnect.");
            var next=new byte[6];uint length=6;
            uint result=SendARP(BitConverter.ToUInt32(IPAddress.Parse(gatewayAddress).GetAddressBytes(),0),BitConverter.ToUInt32(IPAddress.Parse(sourceAddress).GetAddressBytes(),0),next,ref length);
            if(result!=0||length!=6||(next[0]&1)!=0)throw new IOException("LAN gateway ARP is unavailable.");
            lock(sync)Array.Copy(next,destination,6);
        }

        public void Send(byte[] packet, int length, byte[] metadata) {
            if (length < 20 || length > packet.Length || (packet[0] >> 4) != 4)
                throw new IOException("Invalid IPv4 packet.");
            if (!Divert.WinDivertHelperCalcChecksums(packet, (uint)length, metadata, 0))
                throw new IOException("Cannot finalize packet checksums.");
            var frame = new byte[length + 14];
            Array.Copy(source, 0, frame, 6, 6);
            frame[12] = 8;
            Array.Copy(packet, 0, frame, 14, length);
            lock (sync) {
                Array.Copy(destination, 0, frame, 0, 6);
                if (handle == IntPtr.Zero) throw new ObjectDisposedException("GatewayLink");
                if (pcap_sendpacket(handle, frame, frame.Length) != 0)
                    throw new IOException("Gateway frame injection failed: " + Marshal.PtrToStringAnsi(pcap_geterr(handle)));
            }
        }
        public void Dispose() { lock (sync) { if (handle != IntPtr.Zero) pcap_close(handle); handle = IntPtr.Zero; } }
        [StructLayout(LayoutKind.Sequential)] struct BpfProgram { public uint Length; public IntPtr Instructions; }
        [DllImport("iphlpapi.dll")] static extern uint SendARP(uint destination, uint source, byte[] physical, ref uint length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibraryEx(string name, IntPtr file, uint flags);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int timeout, StringBuilder error);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)] static extern int pcap_datalink(IntPtr handle);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)] static extern int pcap_compile(IntPtr handle, ref BpfProgram program, string filter, int optimize, uint netmask);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)] static extern int pcap_setfilter(IntPtr handle, ref BpfProgram program);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)] static extern void pcap_freecode(ref BpfProgram program);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)] static extern int pcap_sendpacket(IntPtr handle, byte[] packet, int length);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr pcap_geterr(IntPtr handle);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)] static extern void pcap_close(IntPtr handle);
    }

    public static class Divert {
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertRecv(IntPtr handle, byte[] packet, uint size, out uint length, byte[] address);
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertSend(IntPtr handle, byte[] packet, uint size, out uint length, byte[] address);
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        public static extern bool WinDivertHelperCalcChecksums(byte[] packet, uint size, byte[] address, ulong flags);
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)] public static extern bool WinDivertShutdown(IntPtr handle, int how);
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)] public static extern bool WinDivertClose(IntPtr handle);
    }
}
