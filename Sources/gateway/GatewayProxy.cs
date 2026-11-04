using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AdvancedAINetwork.Gateway {
    // Local mixed HTTP/SOCKS gateway. Only sockets allocated by GatewayTransport
    // can reach the LAN exit; there is no direct-network fallback.
    public sealed class GatewayProxy : IDisposable {
        readonly GatewayTransport transport;
        readonly GatewayDns dns;
        readonly int frontPort;
        readonly ConnectionTimingLog timing;
        readonly TcpListener listener;
        readonly object sync = new object();
        readonly HashSet<TcpClient> clients = new HashSet<TcpClient>();
        bool stopped;
        long connections, errors, uploaded, downloaded;
        public string LastError = "";
        public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
        public GatewayProxy(GatewayTransport transport, int port, int frontPort) : this(transport,port,frontPort,null) {}
        internal GatewayProxy(GatewayTransport transport, int port, int frontPort, ConnectionTimingLog timing) {
            this.timing = timing;
            this.transport = transport; this.frontPort = frontPort; dns = new GatewayDns(transport);
            listener = new TcpListener(IPAddress.Loopback, port);
            listener.Server.ExclusiveAddressUse = true; listener.Start(128);
            Task.Run((Action)Accept);
        }
        void Accept() {
            while (true) {
                TcpClient input;
                try { input = listener.AcceptTcpClient(); } catch { return; }
                lock (sync) {
                    if (stopped || clients.Count >= 256) { input.Close(); continue; }
                    clients.Add(input);
                }
                Task.Run(() => Handle(input));
            }
        }
        async Task Handle(TcpClient input) {
            ConnectionTiming trace = null;
            try {
                if (timing != null && timing.Enabled) {
                    var peer=input.Client.RemoteEndPoint as IPEndPoint;
                    trace=timing.Begin(Port,peer==null?0:peer.Port);
                }
                input.NoDelay = true; input.ReceiveTimeout = input.SendTimeout = 5000;
                await Protocol(input, 0, trace).ConfigureAwait(false);
            } catch (Exception error) { if(trace!=null)trace.Error(trace.Stage,error); LastError = error.Message; Interlocked.Increment(ref errors); }
            finally { if(trace!=null)trace.End(); input.Close(); lock (sync) clients.Remove(input); }
        }
        internal static byte[] Read(Stream stream, int size) {
            var bytes = new byte[size];
            for (int n = 0; n < size;) { int got = stream.Read(bytes, n, size - n); if (got == 0) throw new IOException("Proxy connection closed."); n += got; }
            return bytes;
        }
        static void Write(Stream stream, string value) { byte[] bytes = Encoding.ASCII.GetBytes(value); stream.Write(bytes, 0, bytes.Length); }
        static string Header(Stream stream, int first) {
            var text = new StringBuilder(); text.Append((char)first);
            while (text.Length < 32768) {
                int value = stream.ReadByte(); if (value < 0) throw new IOException("Incomplete proxy header.");
                text.Append((char)value); int n = text.Length;
                if (n >= 4 && text[n-4] == '\r' && text[n-3] == '\n' && text[n-2] == '\r' && text[n-1] == '\n') return text.ToString();
            }
            throw new IOException("Proxy header is too long.");
        }
        static string SocksHost(Stream stream, int type) {
            if (type == 1) return new IPAddress(Read(stream, 4)).ToString();
            if (type == 3) { int size = stream.ReadByte(); if (size <= 0) throw new IOException("Invalid SOCKS hostname."); return Encoding.ASCII.GetString(Read(stream, size)); }
            throw new IOException("IPv6 SOCKS destinations are disabled.");
        }
        static void SocksReply(Stream stream, int code, int port) {
            byte[] bytes = { 5, (byte)code, 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port }; stream.Write(bytes, 0, bytes.Length);
        }
        async Task Protocol(TcpClient input, int depth, ConnectionTiming trace) {
            if (depth > 1 || !transport.Ready) throw new IOException("Gateway unavailable or recursive proxy request.");
            Stream stream = input.GetStream(); int first = stream.ReadByte(); if (first < 0) return;
            bool socks = first == 5, connect = true; string host, forward = null; int port;
            if(trace!=null)trace.Phase(socks?"client_socks_headers":"client_http_headers");
            if (socks) {
                int count = stream.ReadByte(); if (count <= 0 || count > 32 || !Read(stream, count).Contains((byte)0)) throw new IOException("SOCKS authentication is unsupported.");
                stream.Write(new byte[] { 5, 0 }, 0, 2);
                byte[] request = Read(stream, 4); if (request[0] != 5 || request[2] != 0) throw new IOException("Invalid SOCKS request.");
                host = SocksHost(stream, request[3]); byte[] p = Read(stream, 2); port = p[0] * 256 + p[1];
                if (request[1] == 3) { await Udp(input).ConfigureAwait(false); return; }
                if (request[1] != 1) { SocksReply(stream, 7, 0); return; }
            } else {
                string header = Header(stream, first); string[] lines = header.Split(new[] { "\r\n" }, StringSplitOptions.None);
                string[] request = lines[0].Split(' '); if (request.Length != 3 || !request[2].StartsWith("HTTP/1.", StringComparison.Ordinal)) throw new IOException("Invalid HTTP proxy request.");
                connect = request[0] == "CONNECT";
                Uri uri; if (!Uri.TryCreate(connect ? "http://" + request[1] : request[1], UriKind.Absolute, out uri) || uri.Scheme != "http" || uri.UserInfo.Length != 0) throw new IOException("Invalid HTTP proxy target.");
                host = uri.Host; port = uri.Port;
                if (!connect) {
                    var clean = new StringBuilder(request[0] + " " + uri.PathAndQuery + " " + request[2] + "\r\n");
                    foreach (string line in lines.Skip(1)) {
                        if (line.Length == 0) break;
                        if (line.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) || line.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase)) continue;
                        clean.Append(line).Append("\r\n");
                    }
                    forward = clean.Append("Connection: close\r\n\r\n").ToString();
                }
            }
            IPAddress numeric;
            // A selected app's request to the existing Clash port was redirected
            // here. Decode its original proxy protocol, without altering Clash.
            if (socks && IPAddress.TryParse(host, out numeric) && IPAddress.IsLoopback(numeric) && port == frontPort) {
                SocksReply(stream, 0, 0); if(trace!=null)trace.Phase("inner_proxy_greeting"); await Protocol(input, depth + 1,trace).ConfigureAwait(false); return;
            }
            GatewayTransport.RoutedTcp routed = null; TcpClient output = null; bool acknowledged = false;
            try {
                if(trace!=null)trace.Mark("destination",new {api=string.Equals(host,AiCompatibility.S_0e4a7f621b2756,StringComparison.OrdinalIgnoreCase),port});
                if (IPAddress.TryParse(host, out numeric) && Synthetic(numeric)) {
                    if(trace!=null)trace.Phase("guard_mapping");
                    if (port != 80 && port != 443) throw new IOException("Unsupported synthetic-domain port.");
                    output = new TcpClient(); output.ReceiveTimeout = output.SendTimeout = 5000;
                    await output.ConnectAsync(IPAddress.Parse("127.0.0.2"), 17892).ConfigureAwait(false);
                    Stream mapped = output.GetStream(); Write(mapped, "CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
                    if (!Header(mapped, mapped.ReadByte()).StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal)) throw new IOException("Domain guard rejected the mapping.");
                } else {
                    if(trace!=null)trace.Phase("resolve");
                    var address=dns.Resolve(host);
                    if(trace!=null)trace.Phase("upstream_connect");
                    routed=transport.OpenTcp(address,port);output=routed.Client;
                }
                if(trace!=null)trace.Phase("proxy_reply");
                lock (sync) { if (stopped) throw new IOException("Proxy stopped."); clients.Add(output); }
                if (socks) SocksReply(stream, 0, 0); else if (connect) Write(stream, "HTTP/1.1 200 Connection Established\r\n\r\n");
                else Write(output.GetStream(), forward);
                acknowledged = true;
                input.ReceiveTimeout = input.SendTimeout = output.ReceiveTimeout = output.SendTimeout = 0;
                Interlocked.Increment(ref connections);
                await Task.WhenAll(Pump(input, output, true,trace), Pump(output, input, false,trace)).ConfigureAwait(false);
            } catch {
                try { if (!acknowledged) { if (socks) SocksReply(stream, 1, 0); else Write(stream, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); } } catch { }
                throw;
            } finally { if (routed != null) routed.Dispose(); if (output != null) { output.Close(); lock (sync) clients.Remove(output); } }
        }
        static bool Synthetic(IPAddress ip) { byte[] b = ip.GetAddressBytes(); return b.Length == 4 && b[0] == 198 && b[1] == 19 && b[2] >= 64 && b[2] <= 127; }
        async Task Pump(TcpClient source, TcpClient target, bool upload, ConnectionTiming trace) {
            bool writing=false;
            try {
                var buffer = new byte[16384]; int n;
                while ((n = await source.GetStream().ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) != 0) {
                    writing=true;
                    if(trace!=null)trace.Data(upload?0:2,n);
                    await target.GetStream().WriteAsync(buffer, 0, n).ConfigureAwait(false);
                    if(trace!=null)trace.Data(upload?1:3,n);
                    writing=false;
                    if (upload) Interlocked.Add(ref uploaded, n); else Interlocked.Add(ref downloaded, n);
                }
                try { target.Client.Shutdown(SocketShutdown.Send); } catch { }
            } catch(Exception error) {
                if(trace!=null)trace.Error(upload?(writing?"upstream_write":"client_read"):(writing?"client_write":"upstream_read"),error);
                source.Close(); target.Close(); throw;
            }
        }
        async Task Udp(TcpClient control) {
            using (var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) {
                var routes = new Dictionary<string, GatewayTransport.RoutedUdp>();
                var replies = new List<Task>(); IPEndPoint client = null;
                SocksReply(control.GetStream(), 0, ((IPEndPoint)relay.Client.LocalEndPoint).Port);
                control.ReceiveTimeout = 0;
                Task monitor = Task.Run(() => { try { while (control.GetStream().ReadByte() >= 0) { } } catch { } finally { relay.Close(); } });
                Exception failure = null;
                try {
                    while (transport.Ready) {
                        UdpReceiveResult received = await relay.ReceiveAsync().ConfigureAwait(false); byte[] b = received.Buffer;
                        if (!IPAddress.IsLoopback(received.RemoteEndPoint.Address) || b.Length < 7 || b[0] != 0 || b[1] != 0 || b[2] != 0) continue;
                        if (client != null && !client.Equals(received.RemoteEndPoint)) continue;
                        using (var bytes = new MemoryStream(b, 4, b.Length - 4)) {
                            string name = SocksHost(bytes, b[3]); byte[] p = Read(bytes, 2); int port = p[0] * 256 + p[1];
                            IPAddress address = dns.Resolve(name); string key = address + ":" + port; GatewayTransport.RoutedUdp route;
                            if (!routes.TryGetValue(key, out route)) {
                                if (routes.Count >= 64) continue;
                                route = transport.OpenUdp(address, port); routes.Add(key, route);
                                if (client == null) client = received.RemoteEndPoint;
                                replies.Add(UdpReplies(route, relay, client, address, port));
                            }
                            byte[] payload = Read(bytes, (int)(bytes.Length - bytes.Position));
                            await route.Client.SendAsync(payload, payload.Length).ConfigureAwait(false); Interlocked.Add(ref uploaded, payload.Length);
                        }
                    }
                } catch (Exception error) { failure = error; }
                finally {
                    control.Close(); relay.Close(); foreach (var route in routes.Values) route.Dispose();
                }
                try { await Task.WhenAll(replies).ConfigureAwait(false); } catch { }
                await monitor.ConfigureAwait(false);
                if (failure != null && !(failure is ObjectDisposedException) && !(failure is SocketException)) throw failure;
            }
        }
        async Task UdpReplies(GatewayTransport.RoutedUdp route, UdpClient relay, IPEndPoint client, IPAddress address, int port) {
            try {
                while (true) {
                    byte[] payload = (await route.Client.ReceiveAsync().ConfigureAwait(false)).Buffer;
                    byte[] b = new byte[payload.Length + 10]; b[3] = 1; Array.Copy(address.GetAddressBytes(), 0, b, 4, 4); b[8] = (byte)(port >> 8); b[9] = (byte)port; Array.Copy(payload, 0, b, 10, payload.Length);
                    await relay.SendAsync(b, b.Length, client).ConfigureAwait(false); Interlocked.Add(ref downloaded, payload.Length);
                }
            } catch (ObjectDisposedException) { } catch (SocketException) { }
        }
        public object Status() { lock (sync) return new { connections = Interlocked.Read(ref connections), active_sockets = clients.Count, upload = Interlocked.Read(ref uploaded), download = Interlocked.Read(ref downloaded), errors = Interlocked.Read(ref errors), last_error = LastError }; }
        public void Dispose() { TcpClient[] copy; lock (sync) { stopped = true; copy = clients.ToArray(); } listener.Stop(); foreach (var client in copy) client.Close(); }
    }
}
