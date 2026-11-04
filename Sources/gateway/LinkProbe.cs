using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;

// Only two pre-bound probe sockets are captured. No 高级 AI application is started.
public static class LinkProbe {
    static long packets;
    static string forwardingError = "";
    static void Wait(Task task, int timeout, string label) {
        if (!task.Wait(timeout)) throw new IOException(label + " timed out.");
        task.GetAwaiter().GetResult();
    }
    static string ReadHeader(Stream stream) {
        var text = new StringBuilder();
        while (text.Length < 8192) {
            int value = stream.ReadByte();
            if (value < 0) throw new IOException("Connection closed before HTTP headers.");
            text.Append((char)value);
            if (text.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) return text.ToString();
        }
        throw new IOException("Oversized HTTP header.");
    }
    public static object HttpsTrace(TcpClient client) {
        client.ReceiveTimeout = client.SendTimeout = 4000;
        using (var tls = new SslStream(client.GetStream(), false)) {
            tls.ReadTimeout = tls.WriteTimeout = 4000;
            Wait(tls.AuthenticateAsClientAsync("one.one.one.one", null, SslProtocols.Tls12, false), 5000, "TLS authentication");
            var request = Encoding.ASCII.GetBytes("GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n");
            tls.Write(request, 0, request.Length);
            string headers = ReadHeader(tls);
            if (!headers.StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal)) throw new IOException("HTTP probe did not return 200.");
            var data = new byte[4096];
            var body = new StringBuilder();
            DateTime end = DateTime.UtcNow.AddSeconds(5);
            while (body.Length < 16384 && DateTime.UtcNow < end) {
                int count = tls.Read(data, 0, data.Length);
                if (count == 0) break;
                body.Append(Encoding.ASCII.GetString(data, 0, count));
            }
            var result = new Dictionary<string, object>();
            foreach (string line in body.ToString().Split('\n')) {
                string value = line.Trim();
                if (value.StartsWith("ip=") || value.StartsWith("loc=") || value.StartsWith("colo=")) {
                    int split = value.IndexOf('='); result[value.Substring(0, split)] = value.Substring(split + 1);
                }
            }
            if (!result.ContainsKey("ip")) throw new IOException("HTTPS response had no exit address.");
            return result;
        }
    }
    public static void Dns(UdpClient client) {
        byte[] query = { 0x41,0x92,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1 };
        client.Client.ReceiveTimeout = 4000;
        client.Connect(IPAddress.Parse("1.1.1.1"), 53);
        client.Send(query, query.Length);
        IPEndPoint peer = null;
        byte[] reply = client.Receive(ref peer);
        if (reply.Length < 12 || reply[0] != query[0] || reply[1] != query[1] ||
            (reply[2] & 128) == 0 || (reply[3] & 15) != 0 || (reply[6] == 0 && reply[7] == 0))
            throw new IOException("UDP DNS probe did not return a matching answer.");
    }
    public static int Main(string[] args) {
        if (args.Length != 5) { Console.Error.WriteLine("Usage: LinkProbe <adapter-guid> <local-ip> <gateway-ip> <clash-port> <report>"); return 2; }
        var report = new Dictionary<string, object> { {"success",false}, {"real_target_started",false},
            {"scope","two pre-bound probe sockets only"}, {"gateway",args[2]}, {"started_utc",DateTime.UtcNow.ToString("o")} };
        IntPtr handle = new IntPtr(-1);
        Task worker = null;
        GatewayLink link = null;
        try {
            var local = IPAddress.Parse(args[1]);
            using (var tcp = new TcpClient(new IPEndPoint(local, 0)))
            using (var udp = new UdpClient(new IPEndPoint(local, 0))) {
                int tcpPort = ((IPEndPoint)tcp.Client.LocalEndPoint).Port;
                int udpPort = ((IPEndPoint)udp.Client.LocalEndPoint).Port;
                link = new GatewayLink(args[0], args[1], args[2]);
                report["gateway_mac"] = link.GatewayMac;
                string filter = "outbound and not loopback and not impostor and ip and ip.SrcAddr == " + local +
                    " and ip.DstAddr == 1.1.1.1 and ((tcp and tcp.SrcPort == " + tcpPort +
                    " and tcp.DstPort == 443) or (udp and udp.SrcPort == " + udpPort + " and udp.DstPort == 53))";
                // NO_INSTALL: reuse the already installed signed WinDivert driver.
                handle = Divert.WinDivertOpen(filter, 0, 321, 16);
                if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open the scoped probe filter.");
                IntPtr capture = handle;
                worker = Task.Factory.StartNew(() => {
                    var data = new byte[65535]; var metadata = new byte[80]; uint length;
                    while (Divert.WinDivertRecv(capture, data, (uint)data.Length, out length, metadata)) {
                        try { link.Send(data, (int)length, metadata); Interlocked.Increment(ref packets); }
                        catch (Exception error) { forwardingError = error.Message; }
                    }
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                Wait(tcp.ConnectAsync(IPAddress.Parse("1.1.1.1"), 443), 5000, "Gateway TCP connect");
                report["gateway_https"] = HttpsTrace(tcp);
                Dns(udp); report["gateway_udp_dns"] = true;
                // While capture is active, a separate socket must still use Clash.
                using (var control = new TcpClient()) {
                    Wait(control.ConnectAsync(IPAddress.Loopback, int.Parse(args[3])), 3000, "Clash control connect");
                    control.ReceiveTimeout = control.SendTimeout = 4000;
                    byte[] request = Encoding.ASCII.GetBytes("CONNECT one.one.one.one:443 HTTP/1.1\r\nHost: one.one.one.one:443\r\n\r\n");
                    var stream = control.GetStream(); stream.Write(request, 0, request.Length);
                    if (!ReadHeader(stream).StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal)) throw new IOException("Clash rejected its control request.");
                    report["clash_control_https"] = HttpsTrace(control);
                }
                if (Interlocked.Read(ref packets) == 0 || forwardingError.Length != 0) throw new IOException("No successful gateway forwarding, or a forwarding error occurred: " + forwardingError);
                report["success"] = true;
            }
        } catch (Exception error) { report["error"] = error.GetBaseException().Message; }
        finally {
            if (handle != new IntPtr(-1)) {
                Divert.WinDivertShutdown(handle, 1);
                bool drained = worker == null || worker.Wait(3000);
                Divert.WinDivertClose(handle);
                if (!drained) { report["success"] = false; report["cleanup_error"] = "Capture worker did not terminate in time."; }
            }
            if (link != null) link.Dispose();
            report["forwarded_packets"] = Interlocked.Read(ref packets);
            report["forwarding_error"] = forwardingError;
            report["finished_utc"] = DateTime.UtcNow.ToString("o");
            File.WriteAllText(args[4], new JavaScriptSerializer().Serialize(report), new UTF8Encoding(false));
        }
        return (bool)report["success"] ? 0 : 1;
    }
}
