using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;

public static class ProxyProbe {
    static void Require(bool good, string message) { if (!good) throw new IOException(message); }
    public static TcpClient Socks(int proxy, string host, int port, int command = 1) {
        var c = new TcpClient();
        try {
            c.Connect(IPAddress.Loopback, proxy); c.ReceiveTimeout = c.SendTimeout = 5000;
            var s = c.GetStream(); s.Write(new byte[] { 5, 1, 0 }, 0, 3);
            byte[] hello = GatewayProxy.Read(s, 2); Require(hello[0] == 5 && hello[1] == 0, "SOCKS hello failed.");
            var target = Encoding.ASCII.GetBytes(host); var b = new byte[target.Length + 7];
            b[0] = 5; b[1] = (byte)command; b[3] = 3; b[4] = (byte)target.Length; Array.Copy(target, 0, b, 5, target.Length); b[b.Length-2] = (byte)(port >> 8); b[b.Length-1] = (byte)port;
            s.Write(b, 0, b.Length); if (command == 1) Require(GatewayProxy.Read(s, 10)[1] == 0, "SOCKS connect failed.");
            return c;
        } catch { c.Close(); throw; }
    }
    public static void Udp(int proxy) {
        using (var control = Socks(proxy, "0.0.0.0", 0, 3)) {
            byte[] b = GatewayProxy.Read(control.GetStream(), 10); Require(b[0] == 5 && b[1] == 0 && b[3] == 1, "SOCKS UDP failed.");
            using (var socket = new UdpClient(AddressFamily.InterNetwork)) {
                socket.Connect(IPAddress.Loopback, b[8] * 256 + b[9]); socket.Client.ReceiveTimeout = 5000;
                byte[] query = GatewayDns.Query("example.com"), packet = new byte[query.Length + 10]; packet[3] = 1; packet[4] = packet[5] = packet[6] = packet[7] = 1; packet[9] = 53; Array.Copy(query, 0, packet, 10, query.Length);
                socket.Send(packet, packet.Length); IPEndPoint peer = null; byte[] reply = socket.Receive(ref peer);
                Require(reply.Length > 22 && reply[3] == 1 && reply[9] == 53, "UDP reply envelope mismatch.");
                byte[] answer = new byte[reply.Length - 10]; Array.Copy(reply, 10, answer, 0, answer.Length); int ttl; GatewayDns.Parse(query, answer, out ttl);
            }
        }
    }
    public static int Main(string[] args) {
        var report = new Dictionary<string, object> { {"success",false}, {"real_target_started",false}, {"routes_modified",false}, {"system_proxy_modified",false} };
        try {
            using (var transport = new GatewayTransport(args[0], args[1], args[2]))
            using (var proxy = new GatewayProxy(transport, 0, int.Parse(args[3]))) {
                report["http_connect"] = TransportProbe.Clash(proxy.Port);
                using (var socket = Socks(proxy.Port, "one.one.one.one", 443)) report["socks_domain"] = LinkProbe.HttpsTrace(socket);
                using (var socket = Socks(proxy.Port, "1.1.1.1", 443)) report["socks_numeric"] = LinkProbe.HttpsTrace(socket);
                // SOCKS envelope around a system-proxy request, as used by the process redirector.
                using (var socket = Socks(proxy.Port, "127.0.0.1", int.Parse(args[3]))) {
                    var s = socket.GetStream(); byte[] request = Encoding.ASCII.GetBytes("CONNECT one.one.one.one:443 HTTP/1.1\r\nHost: one.one.one.one:443\r\n\r\n"); s.Write(request,0,request.Length);
                    var header = new StringBuilder(); while (!header.ToString().EndsWith("\r\n\r\n")) { int c = s.ReadByte(); Require(c >= 0 && header.Length < 8192, "Nested proxy closed."); header.Append((char)c); }
                    Require(header.ToString().StartsWith("HTTP/1.1 200 "), "Nested CONNECT failed."); report["nested_clash_request"] = LinkProbe.HttpsTrace(socket);
                }
                Udp(proxy.Port); report["udp_dns"] = true; report["clash_control"] = TransportProbe.Clash(int.Parse(args[3])); report["proxy"] = proxy.Status(); report["transport"] = transport.Status(); report["success"] = true;
            }
        } catch (Exception error) { report["error"] = error.GetBaseException().ToString(); }
        File.WriteAllText(args[4], new JavaScriptSerializer().Serialize(report)); return (bool)report["success"] ? 0 : 1;
    }
}
