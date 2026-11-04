using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;

// Exercises the unrestricted production capture filter with only one disposable
// child PID selected. Never selects, starts, or injects code into 高级 AI.
public static class ProcessProbe {
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static string executable { get { return System.Reflection.Assembly.GetExecutingAssembly().Location; } }
    static void Save(string path, object value) { File.WriteAllText(path, Json.Serialize(value), new UTF8Encoding(false)); }
    static void Require(bool good, string message) { if (!good) throw new IOException(message); }
    static int Child(string[] args) {
        string root = args[1], role = args[2];
        var report = new Dictionary<string, object> { {"success",false}, {"pid",Process.GetCurrentProcess().Id}, {"role",role} };
        try {
            DateTime end = DateTime.UtcNow.AddSeconds(30);
            while (!File.Exists(Path.Combine(root, "go")) && DateTime.UtcNow < end) Thread.Sleep(50);
            Require(File.Exists(Path.Combine(root, "go")), "Fixture was not released.");
            for (int round = 1; round <= 3; round++) {
                if (role == "selected") {
                    using (var tcp = new TcpClient()) {
                        var connect = tcp.ConnectAsync(IPAddress.Parse("1.1.1.1"),443); Require(connect.Wait(5000),"Selected TCP connection timed out."); connect.GetAwaiter().GetResult();
                        report["direct_https_" + round] = LinkProbe.HttpsTrace(tcp);
                    }
                    using (var udp = new UdpClient(AddressFamily.InterNetwork)) LinkProbe.Dns(udp);
                    report["udp_dns_" + round] = true;
                }
                report["system_proxy_https_" + round] = TransportProbe.Clash(int.Parse(args[3]));
            }
            // Both roles send from sockets that close immediately. Their rows
            // can vanish before packet capture; FLOW ownership must survive.
            for(int n=0;n<20;n++)using(var burst=new UdpClient(AddressFamily.InterNetwork)){byte[] query=GatewayDns.Query("example.com");burst.Send(query,query.Length,new IPEndPoint(IPAddress.Parse("1.1.1.1"),53));}
            Thread.Sleep(600);report["short_lived_udp_sockets"]=20;
            report["success"] = true;
        } catch (Exception error) { report["error"] = error.GetBaseException().ToString(); }
        Save(Path.Combine(root, role + ".json"), report); return (bool)report["success"] ? 0 : 1;
    }
    public static int Main(string[] args) {
        if (args.Length > 0 && args[0] == "child") return Child(args);
        if (args.Length != 5) return 2;
        bool single;var instance=new Mutex(true,"Global\\AdvancedAINetwork-LanProbe",out single);if(!single){instance.Dispose();return 3;}
        ThreadPool.SetMinThreads(64,64);
        string root = Path.GetFullPath(args[4]); Directory.CreateDirectory(root);
        var report = new Dictionary<string, object> { {"success",false}, {"real_target_started",false}, {"routes_modified",false}, {"system_proxy_modified",false}, {"capture","production IPv4 filter; one fixture PID selected"} };
        GatewayTransport transport = null; GatewayProxy proxy = null; UdpForwarder udp = null;
        NativeBridge.OwnerSelector selector = null; NativeBridge.LogCallback logger = null;
        Process selected = null, control = null; bool started = false; dynamic firewall = null;
        string ruleName = "AdvancedAINetwork-LanProbe-" + Guid.NewGuid().ToString("N"); object logLock = new object();
        try {
            Require(!File.Exists(Path.Combine(root,"go")),"Each probe run requires a fresh report directory.");
            Require(!Array.Exists(IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners(),p=>p.Port==34010),"Another process relay already owns the test port.");
            report["clash_before"] = TransportProbe.Clash(int.Parse(args[3]));
            transport = new GatewayTransport(args[0],args[1],args[2]); proxy = new GatewayProxy(transport,0,int.Parse(args[3]));
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()) {
                foreach (var ip in nic.GetIPProperties().UnicastAddresses) if (ip.Address.ToString() == "172.31.254.1") {
                    Require(NativeBridge.SetRelayEndpoint(BitConverter.ToUInt32(ip.Address.GetAddressBytes(),0),(uint)nic.GetIPProperties().GetIPv4Properties().Index),"TUN relay endpoint failed.");
                    report["tun"] = nic.Name;
                }
            }
            Require(report.ContainsKey("tun"),"Existing domain TUN is missing.");
            firewall = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = ruleName; rule.ApplicationName = executable; rule.Grouping = "AdvancedAINetwork-LanProbe"; rule.Protocol = 6; rule.LocalPorts = "34010"; rule.LocalAddresses = "172.31.254.1"; rule.Interfaces = new object[]{"AdvancedAINetwork-TUN"}; rule.Direction = 1; rule.Action = 1; rule.Profiles = 7; rule.Enabled = true; firewall.Rules.Add(rule); Marshal.ReleaseComObject(rule);
            var info = new ProcessStartInfo(executable,"child \"" + root + "\" selected " + args[3]) { UseShellExecute = false, CreateNoWindow = true };
            selected = Process.Start(info); info.Arguments = "child \"" + root + "\" control " + args[3]; control = Process.Start(info);
            uint selectedPid = (uint)selected.Id;
            selector = pid => pid == selectedPid ? 1 : 0;
            logger = value => { lock (logLock) File.AppendAllText(Path.Combine(root,"native.log"),Marshal.PtrToStringAnsi(value) + Environment.NewLine); };
            NativeBridge.SetLogCallback(logger);
            uint config = NativeBridge.AddProxy(1,"127.0.0.1",(ushort)proxy.Port,null,null,false);
            Require(config != 0 && NativeBridge.SetOwnerSelector(selector,config,(ushort)int.Parse(args[3])),"Owner selection failed.");
            udp = new UdpForwarder(null,proxy.Port) { SelectOwner = pid => selector(pid), IsReady = () => transport.Ready };
            Require(NativeBridge.Start(),"Production process capture could not start."); started = true;
            Require(NativeBridge.Alive(),"Process capture worker did not stay alive.");
            File.WriteAllText(Path.Combine(root,"go"),"start");
            Require(selected.WaitForExit(40000),"Selected fixture timed out."); Require(control.WaitForExit(5000),"Control fixture timed out.");
            report["selected"] = Json.DeserializeObject(File.ReadAllText(Path.Combine(root,"selected.json")));
            report["control"] = Json.DeserializeObject(File.ReadAllText(Path.Combine(root,"control.json")));
            Require(selected.ExitCode == 0 && control.ExitCode == 0,"Selected/control fixture failed.");
            Thread.Sleep(1000);
            var udpState=Json.Deserialize<Dictionary<string,object>>(Json.Serialize(udp.Status()));
            Require(Convert.ToInt64(udpState["unknown_owner_dropped"])==0,"A UDP packet remained unclassified.");
            Require(Convert.ToInt64(udpState["closed_endpoint_resolved"])>0,"Short-lived UDP ownership fallback was not exercised.");
            Require(Convert.ToInt64(udpState["associations"])>=23,"Selected short-lived UDP datagrams did not all use the gateway.");
            report["success"] = true;
        } catch (Exception error) { report["error"] = error.GetBaseException().ToString(); }
        finally {
            foreach (var process in new[]{selected,control}) if (process != null) { try { if (!process.HasExited) process.Kill(); } catch { } process.Dispose(); }
            if (udp != null) { report["udp"] = udp.Status(); udp.Dispose(); }
            if (started) report["capture_stopped"] = NativeBridge.Stop();
            if (proxy != null) { report["proxy"] = proxy.Status(); proxy.Dispose(); }
            if (transport != null) { report["transport"] = transport.Status(); transport.Dispose(); }
            if (firewall != null) { try { firewall.Rules.Remove(ruleName); report["firewall_rule_removed"] = true; } catch (Exception error) { report["cleanup_error"] = error.Message; report["success"] = false; } Marshal.ReleaseComObject(firewall); }
            try { report["clash_after"] = TransportProbe.Clash(int.Parse(args[3])); } catch (Exception error) { report["control_after_error"] = error.Message; report["success"] = false; }
            Save(Path.Combine(root,"report.json"),report); GC.KeepAlive(selector); GC.KeepAlive(logger);
            instance.ReleaseMutex();instance.Dispose();
        }
        return (bool)report["success"] ? 0 : 1;
    }
}
