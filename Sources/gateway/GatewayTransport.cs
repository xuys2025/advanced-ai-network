using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AdvancedAINetwork.Gateway {
    // Register each socket BEFORE Connect/Send. Unrelated packets are reinjected
    // unchanged; a failed process lookup can never block another application's I/O.
    public sealed class GatewayTransport : IDisposable {
        readonly IPAddress local;
        readonly string adapter, stateRoot;
        readonly int interfaceIndex;
        readonly Dictionary<string,Route> tailRoutes = new Dictionary<string,Route>();
        internal const string TailPrefix = "tailscale:";
        internal static bool IsTailscale(string target) { return target!=null && target.StartsWith(TailPrefix,StringComparison.Ordinal); }
        readonly object routeSync = new object();
        Route activeRoute;
        readonly Timer sweeper;
        readonly ConcurrentDictionary<string, Lease> owned = new ConcurrentDictionary<string, Lease>();
        readonly Task worker;
        IntPtr handle;
        int running = 1;
        long forwarded, passed, errors;
        internal Func<ManagedRules> Rules;
        internal volatile bool RuleForwarding;
        long rulePackets,ruleDrops;
        public string LastError = "";
        internal TailscaleLink ActiveTailscale {get{lock(routeSync)return activeRoute.Link as TailscaleLink;}}
        public bool Ready { get { return Volatile.Read(ref running) == 1; } }
        public string GatewayMac { get { lock(routeSync) return activeRoute.Link.GatewayMac; } }
        public void RefreshLink() { using(var route=RetainActiveRoute())route.Link.Refresh(); }
        public Route CreateRoute(string gateway) {
            if(!IsTailscale(gateway)) return new Route(this,new GatewayLink(adapter,local.ToString(),gateway),null);
            lock(routeSync){
                Route route;
                if(tailRoutes.TryGetValue(gateway,out route)){route.Retain();return route;}
                if(stateRoot==null) throw new IOException("Missing Tailscale session directory.");
                var link=new TailscaleLink(stateRoot,gateway.Substring(TailPrefix.Length),local,ReceiveReply);
                route=new Route(this,link,gateway);tailRoutes.Add(gateway,route);return route;
            }
        }
        void ReceiveReply(byte[] packet) {
            if(!Ready || handle==IntPtr.Zero)return;
            var metadata=new byte[80]; // NETWORK layer, inbound, physical adapter, sub-interface zero.
            Buffer.BlockCopy(BitConverter.GetBytes(interfaceIndex),0,metadata,16,4);
            uint sent;
            if(!Divert.WinDivertHelperCalcChecksums(packet,(uint)packet.Length,metadata,0) ||
               !Divert.WinDivertSend(handle,packet,(uint)packet.Length,out sent,metadata)) Interlocked.Increment(ref errors);
        }
        public Route RetainActiveRoute() { lock(routeSync){activeRoute.Retain();return activeRoute;} }
        public void ActivateRoute(Route route) { lock(routeSync){if(route.Owner!=this)throw new IOException("Invalid gateway route.");route.Retain();var old=activeRoute;activeRoute=route;old.Dispose();} }

        public sealed class Route : IDisposable {
            internal readonly GatewayTransport Owner; internal readonly IExitLink Link;
            readonly string key;
            readonly object sync=new object();int refs=1;
            internal Route(GatewayTransport owner,IExitLink link,string key){Owner=owner;Link=link;this.key=key;}
            internal void Retain(){lock(sync){if(refs==0)throw new ObjectDisposedException("Gateway route");refs++;}}
            internal void Send(byte[] packet,int length,byte[] metadata,bool probe=false){
                lock(sync){
                    if(refs==0)throw new ObjectDisposedException("Gateway route");
                    var tail=Link as TailscaleLink;
                    if(tail!=null && !probe && !tail.Verified)throw new IOException("Tailscale 出口等待验证。");
                    Link.Send(packet,length,metadata);
                }
            }
            public void Dispose(){
                lock(Owner.routeSync){lock(sync){if(refs<=0||--refs!=0)return;if(key!=null)Owner.tailRoutes.Remove(key);}}
                Link.Dispose();
            }
        }

        public GatewayTransport(string adapter, string source, string gateway, string stateRoot=null) {
            this.stateRoot=stateRoot;
            var nic=Array.Find(System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces(),n=>n.Id.Equals(adapter,StringComparison.OrdinalIgnoreCase));
            if(nic==null)throw new IOException("当前网卡不可用。");
            interfaceIndex=nic.GetIPProperties().GetIPv4Properties().Index;
            local = IPAddress.Parse(source);
            this.adapter=adapter;
            activeRoute = CreateRoute(gateway);
            string filter = "outbound and not loopback and not impostor and ip and ip.SrcAddr == " + local;
            handle = Divert.WinDivertOpen(filter, 0, 321, 16);
            if (handle == new IntPtr(-1)) {
                int error = Marshal.GetLastWin32Error(); activeRoute.Dispose();
                throw new Win32Exception(error, "Cannot open the gateway transport filter (Win32 "+error+"): "+new Win32Exception(error).Message);
            }
            worker = Task.Factory.StartNew(Receive, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            sweeper=new Timer(_=>Sweep(),null,15000,15000);
        }
        static string Key(int protocol, int port, IPAddress remote, int remotePort) {
            return protocol + "/" + port + "/" + remote + "/" + remotePort;
        }
        static int Port(byte[] packet, int offset) { return packet[offset] * 256 + packet[offset + 1]; }
        static void ValidateTarget(IPAddress target, int port) {
            if (target.AddressFamily != AddressFamily.InterNetwork || port < 1 || port > 65535)
                throw new IOException("Only an IPv4 unicast destination and a valid port are supported.");
            byte[] bytes = target.GetAddressBytes();
            if (bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224 || bytes[0] == 169 && bytes[1] == 254)
                throw new IOException("The gateway transport does not forward local IPC, multicast, or broadcast.");
        }
        Lease Register(int protocol, int port, IPAddress target, int remotePort, Action close, Route route) {
            if (!Ready) throw new IOException("The gateway transport is unavailable.");
            bool probe=route!=null;
            lock(routeSync){route=route??activeRoute;if(route.Owner!=this)throw new IOException("Invalid gateway route.");route.Retain();}
            var lease = new Lease(this, Key(protocol, port, target, remotePort), close, route, probe);
            if(!owned.TryAdd(lease.Key,lease)){lease.ReleaseRoute();throw new IOException("Gateway socket tuple is still reserved.");}
            if (!Ready) { lease.Close(); throw new IOException("The gateway transport stopped during socket registration."); }
            return lease;
        }
        public RoutedTcp OpenTcp(IPAddress target, int port, Route route = null) {
            ValidateTarget(target, port);
            var client = new TcpClient(AddressFamily.InterNetwork);
            Lease lease = null;
            try {
                client.ExclusiveAddressUse = true;
                client.NoDelay = true;
                client.Client.DontFragment = true;
                client.Client.Bind(new IPEndPoint(local, 0));
                lease = Register(6, ((IPEndPoint)client.Client.LocalEndPoint).Port, target, port, client.Close, route);
                var connect = client.ConnectAsync(target, port);
                if (!connect.Wait(5000)) throw new IOException("Gateway TCP connection timed out.");
                connect.GetAwaiter().GetResult();
                if (!Ready) throw new IOException("Gateway transport became unavailable.");
                return new RoutedTcp(client, lease);
            } catch { client.Close(); if (lease != null) lease.Close(); throw; }
        }
        public RoutedUdp OpenUdp(IPAddress target, int port, Route route = null) {
            ValidateTarget(target, port);
            var client = new UdpClient(AddressFamily.InterNetwork);
            Lease lease = null;
            try {
                client.ExclusiveAddressUse = true;
                client.DontFragment = true;
                client.Client.Bind(new IPEndPoint(local, 0));
                lease = Register(17, ((IPEndPoint)client.Client.LocalEndPoint).Port, target, port, client.Close, route);
                client.Connect(target, port);
                return new RoutedUdp(client, lease);
            } catch { client.Close(); if (lease != null) lease.Close(); throw; }
        }
        void Receive() {
            var packet = new byte[65535]; var metadata = new byte[80]; uint length;
            try {
                while (Divert.WinDivertRecv(handle, packet, (uint)packet.Length, out length, metadata)) {
                    Lease lease = null;
                    if (length >= 28 && (packet[0] >> 4) == 4) {
                        int header = (packet[0] & 15) * 4;
                        // Noninitial IP fragments do not carry transport ports.
                        // Registered sockets use the physical MTU; fragmented sends
                        // are not enabled by this transport.
                        if ((packet[9]==6||packet[9]==17) && header >= 20 && header + 4 <= length && (packet[6] & 31) == 0 && packet[7] == 0) {
                            var target = new IPAddress(new byte[] { packet[16], packet[17], packet[18], packet[19] });
                            owned.TryGetValue(Key(packet[9], Port(packet, header), target, Port(packet, header + 2)), out lease);
                        }
                    }
                    if (lease != null) {
                        try { lease.Route.Send(packet, (int)length, metadata, lease.Probe); Interlocked.Increment(ref forwarded); }
                        catch (Exception error) { LastError = error.Message; Interlocked.Increment(ref errors); lease.Close(); }
                    } else if(length>=20 && Rules!=null && Rules().MatchesIp(packet,16)) {
                        if(!RuleForwarding){Interlocked.Increment(ref ruleDrops);continue;}
                        try{using(var selected=RetainActiveRoute())selected.Send(packet,(int)length,metadata);Interlocked.Increment(ref rulePackets);}
                        catch(Exception error){LastError=error.Message;Interlocked.Increment(ref errors);}
                    } else {
                        uint sent;
                        if (!Divert.WinDivertSend(handle, packet, length, out sent, metadata)) {
                            LastError = "Unrelated packet reinjection failed: " + Marshal.GetLastWin32Error();
                            Interlocked.Increment(ref errors);
                        } else Interlocked.Increment(ref passed);
                    }
                }
                if (Ready) LastError = "Gateway capture ended unexpectedly: " + Marshal.GetLastWin32Error();
            } finally {
                Interlocked.Exchange(ref running, 0);
                foreach (var lease in owned.Values) lease.Close();
            }
        }
        void Sweep(){foreach(var item in owned)if(item.Value.Expired&&((ICollection<KeyValuePair<string,Lease>>)owned).Remove(item))item.Value.ReleaseRoute();}
        public object Status() {
            return new { ready = Ready, forwarded_packets = Interlocked.Read(ref forwarded),
                unrelated_packets_passed = Interlocked.Read(ref passed), errors = Interlocked.Read(ref errors),
                last_error = LastError, tracked_sockets = owned.Count, rule_ip_packets=Interlocked.Read(ref rulePackets),rule_ip_dropped=Interlocked.Read(ref ruleDrops) };
        }
        public void Dispose() {
            Interlocked.Exchange(ref running, 0);
            sweeper.Dispose();
            foreach (var lease in owned.Values) lease.Close();
            Divert.WinDivertShutdown(handle, 1);
            worker.Wait(5000);
            Divert.WinDivertClose(handle);
            foreach(var lease in owned.Values)lease.ReleaseRoute();owned.Clear();
            activeRoute.Dispose();
        }
        public sealed class Lease {
            readonly GatewayTransport owner;
            readonly Action close;
            int closed;
            int released;
            internal readonly Route Route;
            internal readonly bool Probe;
            long expiry = long.MaxValue;
            internal readonly string Key;
            internal Lease(GatewayTransport owner, string key, Action close, Route route,bool probe) { Probe=probe;this.owner = owner; Key = key; this.close = close; Route=route; }
            internal void ReleaseRoute(){if(Interlocked.Exchange(ref released,1)==0)Route.Dispose();}
            internal bool Expired { get { return DateTime.UtcNow.Ticks > Interlocked.Read(ref expiry); } }
            public void Close() {
                if (Interlocked.Exchange(ref closed, 1) != 0) return;
                // Keep teardown packets on the same gateway after closing the socket.
                Interlocked.Exchange(ref expiry, DateTime.UtcNow.AddMinutes(2).Ticks);
                try { close(); } catch { }
                GC.KeepAlive(owner);
            }
        }
        public sealed class RoutedTcp : IDisposable {
            public readonly TcpClient Client;
            readonly Lease lease;
            internal RoutedTcp(TcpClient client, Lease lease) { Client = client; this.lease = lease; }
            public void Dispose() { lease.Close(); }
        }
        public sealed class RoutedUdp : IDisposable {
            public readonly UdpClient Client;
            readonly Lease lease;
            internal RoutedUdp(UdpClient client, Lease lease) { Client = client; this.lease = lease; }
            public void Dispose() { lease.Close(); }
        }
    }
}
