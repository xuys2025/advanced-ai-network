using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;

public static class TransportProbe {
    static void Require(bool condition, string message) { if (!condition) throw new IOException(message); }
    public static object Clash(int port) {
        using (var client = new TcpClient()) {
            var connect = client.ConnectAsync(IPAddress.Loopback, port);
            Require(connect.Wait(3000), "Clash connection timed out."); connect.GetAwaiter().GetResult();
            client.ReceiveTimeout = client.SendTimeout = 4000;
            var stream = client.GetStream();
            byte[] request = Encoding.ASCII.GetBytes("CONNECT one.one.one.one:443 HTTP/1.1\r\nHost: one.one.one.one:443\r\n\r\n");
            stream.Write(request, 0, request.Length);
            var headers = new StringBuilder();
            while (headers.Length < 8192) {
                int value = stream.ReadByte(); Require(value >= 0, "Clash closed its control connection.");
                headers.Append((char)value); if (headers.ToString().EndsWith("\r\n\r\n")) break;
            }
            Require(headers.ToString().StartsWith("HTTP/1.1 200 "), "Clash rejected its control request.");
            return LinkProbe.HttpsTrace(client);
        }
    }
    public static int Main(string[] args) {
        if (args.Length != 5) return 2;
        var report = new Dictionary<string, object> { {"success", false}, {"started_utc", DateTime.UtcNow.ToString("o")},
            {"real_target_started",false}, {"routes_modified",false}, {"system_proxy_modified",false} };
        GatewayTransport transport = null;
        try {
            transport = new GatewayTransport(args[0], args[1], args[2]);
            var dns = new GatewayDns(transport);
            report["gateway_dns_answer"] = dns.Resolve("example.com").ToString();
            for (int round = 1; round <= 3; round++) {
                using (var socket = transport.OpenTcp(IPAddress.Parse("1.1.1.1"), 443)) report["gateway_https_" + round] = LinkProbe.HttpsTrace(socket.Client);
                using (var socket = transport.OpenUdp(IPAddress.Parse("1.1.1.1"), 53)) LinkProbe.Dns(socket.Client);
                report["clash_https_" + round] = Clash(int.Parse(args[3]));
            }
            report["gateway_udp_dns_rounds"] = 3;
            Require(transport.Ready && transport.LastError.Length == 0, "Gateway transport error: " + transport.LastError);
            report["success"] = true;
        } catch (Exception error) { report["error"] = error.GetBaseException().Message; }
        finally {
            if (transport != null) { report["transport"] = transport.Status(); transport.Dispose(); }
            report["finished_utc"] = DateTime.UtcNow.ToString("o");
            File.WriteAllText(args[4], new JavaScriptSerializer().Serialize(report), new UTF8Encoding(false));
        }
        return (bool)report["success"] ? 0 : 1;
    }
}
