using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;

public sealed partial class GatewayService : ServiceBase {
    public const string Name = "AdvancedAINetworkLanGateway", Version = "0.6.9-lan.1", PipeName = "AdvancedAINetworkLanGateway.Control";
    RuleFeed rules;
    ConnectionTimingLog connectionTiming;
    static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),Name);
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    readonly ManualResetEvent stopping = new ManualResetEvent(false);
    Task worker, pipeWorker; NamedPipeServerStream pipe; readonly object sync = new object();
    volatile bool enabled = true, ready, requestCheck;
    bool capturing, guardReady; string message = "Starting", lastExit = "", nativeError = "", ownerSid, gateway, local, adapter, lastCheck = "";
    int front; ProcessIdentity identity; GatewayTransport transport; GatewayProxy domainProxy, clashProxy; UdpForwarder udp;
    NativeBridge.OwnerSelector selector; NativeBridge.LogCallback logger;
    object guardStatus; DateTime firewallChecked; string adapterName="";
    public GatewayService() { ServiceName = Name; CanShutdown = true; CanStop = true; }
    static Dictionary<string,object> ReadJson(string path) { using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var reader=new StreamReader(file))return Json.Deserialize<Dictionary<string,object>>(reader.ReadToEnd()); }
    static string Str(Dictionary<string,object> d,string key) { object value;return d.TryGetValue(key,out value)?Convert.ToString(value):""; }
    static bool Flag(Dictionary<string,object> d,string key) { object value;return d.TryGetValue(key,out value)&&value is bool&&(bool)value; }
    static void Atomic(string path,object data) { string temp=path+".tmp";File.WriteAllText(temp,Json.Serialize(data),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path); }
    protected override void OnStart(string[] args) { ThreadPool.SetMinThreads(64,64);worker=Task.Run((Action)Run); }
    protected override void OnStop() { RequestAdditionalTime(20000);ready=false;stopping.Set();lock(sync){if(pipe!=null)pipe.Dispose();}if(worker!=null&&!worker.Wait(15000))Environment.Exit(1); }
    protected override void OnShutdown() { OnStop(); }
    bool Guard() {
        try { var state=ReadJson(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AdvancedAINetworkGuard","guard-status.json"));DateTime time;
            bool fresh=DateTime.TryParse(Str(state,"updated_utc"),out time)&&Math.Abs((DateTime.UtcNow-time.ToUniversalTime()).TotalSeconds)<15;
            guardStatus=new{fresh=fresh,tun_ready=fresh&&Flag(state,"tun_ready"),dns_64_65_blocked=fresh&&Flag(state,"dns_64_65_blocked"),network_safety_ready=fresh&&Flag(state,"network_safety_ready"),updated_utc=Str(state,"updated_utc")};
            return fresh&&Flag(state,"tun_ready")&&Flag(state,"dns_64_65_blocked")&&Flag(state,"network_safety_ready");
        }catch{guardStatus=new{fresh=false};return false;}
    }
    static int Tun() { foreach(var nic in NetworkInterface.GetAllNetworkInterfaces())if(nic.Name=="AdvancedAINetwork-TUN")foreach(var ip in nic.GetIPProperties().UnicastAddresses)if(ip.Address.ToString()=="172.31.254.1")return nic.GetIPProperties().GetIPv4Properties().Index;throw new IOException("Domain protection TUN is unavailable."); }
    void Firewall() {
        identity.RefreshInstalled();
        dynamic policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        try {
            foreach(int profile in new[]{1,2,4})if(!(bool)policy.FirewallEnabled(profile))throw new IOException("Windows Firewall is disabled.");
            string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;
            var rules=new List<Tuple<string,string,string,int,int>>{Tuple.Create(Name+"-TUN",exe,"172.31.254.1",1,1)};
            foreach(string path in identity.Paths) { string hash;using(var sha=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(path.ToLowerInvariant()))).Replace("-","").Substring(0,16);rules.Add(Tuple.Create(Name+"-IPv6-"+hash,path,"",2,0)); }
            foreach(var spec in rules) {
                dynamic rule=null;try{rule=policy.Rules.Item(spec.Item1);}catch(Exception e){if(!(e is FileNotFoundException)&&(!(e is COMException)||((COMException)e).ErrorCode!=unchecked((int)0x80070002)))throw;}
                bool add=rule==null;
                if(add){rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));rule.Name=spec.Item1;rule.Grouping=Name;rule.ApplicationName=spec.Item2;}
                else if((string)rule.Grouping!=Name||(string)rule.ApplicationName!=spec.Item2)throw new IOException("Firewall rule ownership mismatch.");
                rule.Protocol=spec.Item4==1?6:256;
                if(spec.Item4==1){rule.LocalPorts="34010";rule.LocalAddresses=spec.Item3;rule.Interfaces=new object[]{"AdvancedAINetwork-TUN"};}
                else rule.RemoteAddresses="::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
                rule.Direction=spec.Item4;rule.Action=spec.Item5;rule.Profiles=7;rule.Enabled=true;if(add)policy.Rules.Add(rule);Marshal.ReleaseComObject(rule);
            }
            firewallChecked=DateTime.UtcNow;
        }finally{Marshal.ReleaseComObject(policy);}
    }
    object Snapshot() {
        return new {version=Version,service_pid=Process.GetCurrentProcess().Id,updated_utc=DateTime.UtcNow.ToString("o"),mode="lan-gateway",enabled=enabled,ready=ready,capturing=capturing,gateway=gateway,local_ip=local,adapter=adapter,adapter_name=adapterName,gateway_mac=transport==null?"":transport.GatewayMac,front_port=front,guard_protected=guardReady,tun_ready=guardReady,dns64_65_blocked=guardReady,guard=guardStatus,ipv6_firewall_ready=(DateTime.UtcNow-firewallChecked).TotalSeconds<45,last_exit=lastExit,exit_location=lastLocation,exit_colo=lastColo,exit_verified_utc=lastCheck,gateway_operation=operation,rule_sync=rules==null?null:rules.Status(),message=message,native_error=nativeError,exit_protection="domain-list",real_target_started=false,identities=identity==null?new object[0]:identity.Status(),transport=transport==null?null:transport.Status(),domain_proxy=domainProxy==null?null:domainProxy.Status(),clash_proxy=clashProxy==null?null:clashProxy.Status(),udp=udp==null?null:udp.Status()};
    }
    void Save() { Atomic(Path.Combine(Root,"status.json"),Snapshot()); }
    void CloseProxies() { ready=false;if(udp!=null)udp.Pause();if(domainProxy!=null)domainProxy.Dispose();if(clashProxy!=null)clashProxy.Dispose();domainProxy=clashProxy=null; }
    void OpenProxies() { if(domainProxy!=null)return;try{domainProxy=new GatewayProxy(transport,17893,front,connectionTiming);clashProxy=new GatewayProxy(transport,17891,front,connectionTiming);}catch{CloseProxies();throw;} }
    void CheckExit() { using(var route=transport.RetainActiveRoute())SetExit(ProbeRoute(route)); }
    void Pipe() {
        while(!stopping.WaitOne(0)) {
            try {
                var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(ownerSid),PipeAccessRights.ReadWrite,AccessControlType.Allow));
                foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid),PipeAccessRights.FullControl,AccessControlType.Allow));
                using(var current=new NamedPipeServerStream(PipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,1024,65536,security)) {
                    lock(sync){if(stopping.WaitOne(0))return;pipe=current;}
                    current.WaitForConnection();
                    object reply;
                    try{string command=ReadCommand(current);HandleCommand(command);reply=Snapshot();}
                    catch(Exception error){reply=new{error=error.GetBaseException().Message};}
                    byte[] response=Encoding.UTF8.GetBytes(Json.Serialize(reply)+"\n");current.Write(response,0,response.Length);
                }
            }catch{if(!stopping.WaitOne(0))stopping.WaitOne(100);}
            finally{lock(sync)pipe=null;}
        }
    }
    void Run() {
        bool fatal=false;
        try {
            var config=ReadJson(Path.Combine(Root,"config.json"));ownerSid=Str(config,"owner_sid");gateway=Str(config,"gateway");adapter=Str(config,"adapter");front=Convert.ToInt32(config["front_port"]);
            if(front<1||front>65535||front>=17891&&front<=17896)throw new IOException("Invalid system proxy port.");
            var nic=NetworkInterface.GetAllNetworkInterfaces().Single(n=>n.Id.Equals(adapter,StringComparison.OrdinalIgnoreCase));
            local=GatewayLink.ResolveSource(adapter,gateway);adapterName=nic.Name;
            if(File.Exists(Path.Combine(Root,"intent.json")))enabled=Flag(ReadJson(Path.Combine(Root,"intent.json")),"enabled");
            identity=new ProcessIdentity(Str(config,"desktop_image"),Str(config,"code_image"),ProcessIdentity.ProfileForOwner(ownerSid));guardReady=Guard();if(!guardReady)throw new IOException("Domain protection is not ready.");
            transport=new GatewayTransport(adapter,local,gateway);rules=new RuleFeed(Root,transport,front);identity.RuleName=name=>rules.Active.MatchesProcess(name);transport.RuleForwarding=enabled&&guardReady;transport.Rules=()=>rules.Active;CheckExit();Firewall();
            selector=identity.Select;logger=p=>{string value=Marshal.PtrToStringAnsi(p);if(value!=null&&(value.IndexOf("failed",StringComparison.OrdinalIgnoreCase)>=0||value.IndexOf("error",StringComparison.OrdinalIgnoreCase)>=0))nativeError=value;};NativeBridge.SetLogCallback(logger);
            if(!NativeBridge.SetRelayEndpoint(BitConverter.ToUInt32(IPAddress.Parse("172.31.254.1").GetAddressBytes(),0),(uint)Tun()))throw new IOException("Relay TUN setup failed.");
            uint proxy=NativeBridge.AddProxy(1,"127.0.0.1",17893,null,null,false);if(proxy==0||!NativeBridge.SetOwnerSelector(selector,proxy,(ushort)front))throw new IOException("Signed process routing setup failed.");
            udp=new UdpForwarder(null,17893){SelectOwner=identity.Select,IsReady=()=>ready};
            connectionTiming=new ConnectionTimingLog(Root);
            if(enabled)OpenProxies();
            if(!NativeBridge.Start())throw new IOException("Process forwarding could not start: "+nativeError);capturing=true;
            pipeWorker=Task.Run((Action)Pipe);DateTime nextLink=DateTime.MinValue,nextFirewall=DateTime.UtcNow.AddSeconds(15);
            while(!stopping.WaitOne(0)) {
                if(!NativeBridge.Alive()||!transport.Ready)throw new IOException("Network worker stopped.");
                guardReady=Guard();
                if(DateTime.UtcNow>=nextLink){transport.RefreshLink();nextLink=DateTime.UtcNow.AddSeconds(10);NativeBridge.SetRelayEndpoint(BitConverter.ToUInt32(IPAddress.Parse("172.31.254.1").GetAddressBytes(),0),(uint)Tun());}
                if(DateTime.UtcNow>=nextFirewall){Firewall();nextFirewall=DateTime.UtcNow.AddSeconds(15);}
                if(!enabled||!guardReady){CloseProxies();message=enabled?"等待域名保护恢复，目标流量暂停。":"专用连接已暂停，域名保护保留。";}
                else{OpenProxies();ready=true;message="命中域名、IPv4 网段、ASN 或程序名的连接经 "+gateway+"；其他程序保留原路径。";}
                if(applyRequested)ApplyCandidate();
                lock(sync){if(requestCheck&&!operationBusy){requestCheck=false;BeginValidation(gateway,true);}}
                ExpireCandidate();
                transport.RuleForwarding=ready;rules.Tick(ready);Save();stopping.WaitOne(500);
            }
        }catch(Exception error){message=error.GetBaseException().Message;fatal=!stopping.WaitOne(0);}
        finally {
            stopping.Set();CloseProxies();if(udp!=null)udp.Dispose();if(capturing)NativeBridge.Stop();capturing=false;if(operationTask!=null)operationTask.Wait(15000);lock(sync){ClearCandidate();if(pipe!=null)pipe.Dispose();}if(rules!=null)rules.Dispose();if(transport!=null)transport.Dispose();if(pipeWorker!=null)pipeWorker.Wait(4000);try{Save();}catch{}GC.KeepAlive(selector);GC.KeepAlive(logger);
        }
        if(connectionTiming!=null)connectionTiming.Dispose();
        if(fatal)Environment.Exit(1);
    }
    public static int Main(string[] args) { ServiceBase.Run(new GatewayService());return 0; }
}
