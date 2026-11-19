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
    public const string Name = "AdvancedAINetworkLanGateway", Version = "0.6.9-lan.7", PipeName = "AdvancedAINetworkLanGateway.Control";
    RuleFeed rules;
    readonly GatewayFailClosed networkGuard = new GatewayFailClosed();
    ConnectionTimingLog connectionTiming;
    GatewayProgress progress;
    long firewallChecks,firewallWrites,firewallAdds;
    static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),Name);
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    readonly ManualResetEvent stopping = new ManualResetEvent(false);
    Task worker, pipeWorker; NamedPipeServerStream pipe; readonly object sync = new object();
    volatile bool enabled = true, ready, requestCheck;
    bool capturing, guardReady; string message = "Starting", lastExit = "", nativeError = "", ownerSid, gateway, local, adapter, lastCheck = "";
    int front; ProcessIdentity identity; GatewayTransport transport; GatewayProxy domainProxy, clashProxy; UdpForwarder udp;
    NativeBridge.OwnerSelector selector; NativeBridge.LogCallback logger;
    object guardStatus; DateTime firewallChecked; string adapterName="",lanGateway="";
    public GatewayService() { ServiceName = Name; CanShutdown = true; CanStop = true; }
    static Dictionary<string,object> ReadJson(string path) { using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var reader=new StreamReader(file))return Json.Deserialize<Dictionary<string,object>>(reader.ReadToEnd()); }
    static string Str(Dictionary<string,object> d,string key) { object value;return d.TryGetValue(key,out value)?Convert.ToString(value):""; }
    static bool Flag(Dictionary<string,object> d,string key) { object value;return d.TryGetValue(key,out value)&&value is bool&&(bool)value; }
    static void Atomic(string path,object data) { string temp=path+".tmp";File.WriteAllText(temp,Json.Serialize(data),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path); }
    protected override void OnStart(string[] args) { ThreadPool.SetMinThreads(64,64);worker=Task.Run((Action)Run); }
    protected override void OnStop() { RequestAdditionalTime(20000);lock(sync){stopping.Set();networkGuard.Pause();ready=false;if(pipe!=null)pipe.Dispose();}if(worker!=null&&!worker.Wait(15000))Environment.Exit(1); }
    protected override void OnShutdown() { OnStop(); }
    bool Guard() {
        try {
            string folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AdvancedAINetworkGuard");
            Dictionary<string,object> state;
            using(var proof=GuardHeartbeat.Open(folder,false))
                state=Json.Deserialize<Dictionary<string,object>>(proof.Read(GuardHeartbeat.RunningPid("AdvancedAINetworkDomainGuard")));
            DateTimeOffset stamp;
            bool fresh=DateTimeOffset.TryParse(Str(state,"updated_utc"),out stamp) && stamp<=DateTimeOffset.UtcNow.AddSeconds(2) && stamp>DateTimeOffset.UtcNow.AddSeconds(-15);
            DateTimeOffset expiry;
            bool verified=Flag(state,"network_safety_ready") && Str(state,"maintenance_revision")=="2"
                && DateTimeOffset.TryParse(Str(state,"safety_valid_until_utc"),out expiry) && expiry>DateTimeOffset.UtcNow;
            guardStatus=new{channel="shared-memory",fresh=fresh,tun_ready=fresh&&Flag(state,"tun_ready"),dns_64_65_blocked=fresh&&Flag(state,"dns_64_65_blocked"),network_safety_ready=fresh&&verified,updated_utc=Str(state,"updated_utc"),maintenance_error=Str(state,"maintenance_error")};
            return fresh&&Flag(state,"tun_ready")&&Flag(state,"dns_64_65_blocked")&&verified;
        }catch(Exception ex){guardStatus=new{fresh=false,read_error=ex.GetType().Name,native_error=ex.HResult&0xffff};return false;}
    }
    bool BindRelay(){
        foreach(var nic in NetworkInterface.GetAllNetworkInterfaces())if(nic.Name=="AdvancedAINetwork-TUN")
            foreach(var ip in nic.GetIPProperties().UnicastAddresses)if(ip.Address.ToString()=="172.31.254.1")
                return NativeBridge.SetRelayEndpoint(BitConverter.ToUInt32(ip.Address.GetAddressBytes(),0),(uint)nic.GetIPProperties().GetIPv4Properties().Index);
        return false;
    }
    void Firewall() {
        progress.Enter(GatewayStage.FirewallIdentity);
        identity.RefreshInstalled();
        progress.Enter(GatewayStage.FirewallProfiles);
        dynamic policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        try {
            foreach(int profile in new[]{1,2,4})if(!(bool)policy.FirewallEnabled(profile))throw new IOException("Windows Firewall is disabled.");
            string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;
            var rules=new List<Tuple<string,string,string,int,int>>{Tuple.Create(Name+"-TUN",exe,"172.31.254.1",1,1)};
            foreach(string path in identity.Paths) { string hash;using(var sha=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(path.ToLowerInvariant()))).Replace("-","").Substring(0,16);rules.Add(Tuple.Create(Name+"-IPv6-"+hash,path,"",2,0)); }
            foreach(var spec in rules) {
                progress.Enter(GatewayStage.FirewallLookup);
                dynamic rule=null;try{rule=policy.Rules.Item(spec.Item1);}catch(Exception e){if(!(e is FileNotFoundException)&&(!(e is COMException)||((COMException)e).ErrorCode!=unchecked((int)0x80070002)))throw;}
                bool add=rule==null;
                if(add)rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                try{
                    if(add){rule.Name=spec.Item1;rule.Grouping=Name;rule.ApplicationName=spec.Item2;}
                    else if((string)rule.Grouping!=Name||(string)rule.ApplicationName!=spec.Item2)throw new IOException("Firewall rule ownership mismatch.");
                    progress.Enter(GatewayStage.FirewallCompare);
                    Action writing=()=>progress.Enter(GatewayStage.FirewallRepair);
                    int changes=GatewayFirewallRule.Reconcile((object)rule,add,spec.Item4==1,spec.Item3,"AdvancedAINetwork-TUN",writing);
                    Interlocked.Add(ref firewallWrites,changes);
                    if(add){progress.Enter(GatewayStage.FirewallRepair);policy.Rules.Add(rule);Interlocked.Increment(ref firewallAdds);}
                }finally{Marshal.ReleaseComObject(rule);}
            }
            firewallChecked=DateTime.UtcNow;
            Interlocked.Increment(ref firewallChecks);
        }finally{Marshal.ReleaseComObject(policy);}
    }
    object Snapshot() {
        return new {version=Version,heartbeat_diagnostics_revision=1,previous_status_write_error=statusWriteError,firewall_checks=Interlocked.Read(ref firewallChecks),firewall_property_writes=Interlocked.Read(ref firewallWrites),firewall_rules_added=Interlocked.Read(ref firewallAdds),service_pid=Process.GetCurrentProcess().Id,updated_utc=DateTime.UtcNow.ToString("o"),mode=GatewayTransport.IsTailscale(gateway)?"tailscale":"lan-gateway",tailscale_supported=true,tailscale_login_required=LoginUrl()!="",lan_gateway=lanGateway,enabled=enabled,ready=ready,capturing=capturing,gateway=gateway,local_ip=local,adapter=adapter,adapter_name=adapterName,gateway_mac=transport==null?"":transport.GatewayMac,front_port=front,guard_protected=guardReady,tun_ready=guardReady,dns64_65_blocked=guardReady,guard=guardStatus,ipv6_firewall_ready=(DateTime.UtcNow-firewallChecked).TotalSeconds<45,last_exit=lastExit,exit_location=lastLocation,exit_colo=lastColo,exit_verified_utc=lastCheck,gateway_operation=operation,rule_sync=rules==null?null:rules.Status(),message=message,native_error=nativeError,process_ip_guard_live=networkGuard.Live,exit_protection="persistent-wfp",real_target_started=false,identities=identity==null?new object[0]:identity.Status(),transport=transport==null?null:transport.Status(),domain_proxy=domainProxy==null?null:domainProxy.Status(),clash_proxy=clashProxy==null?null:clashProxy.Status(),udp=udp==null?null:udp.Status()};
    }
    string statusWriteError="";
    void Save() {
        progress.Enter(GatewayStage.BuildSnapshot);
        var snapshot=Snapshot();
        progress.Enter(GatewayStage.PublishSnapshot);
        try{
            GuardHeartbeat.WriteStatus(Path.Combine(Root,"status.json"),Json.Serialize(snapshot));
            progress.Published();statusWriteError="";
        }catch(System.ComponentModel.Win32Exception ex){statusWriteError=ex.Message;}
        catch(IOException ex){statusWriteError=ex.Message;}
        catch(UnauthorizedAccessException ex){statusWriteError=ex.Message;}
    }
    void CloseProxies() { networkGuard.Pause();ready=false;if(udp!=null)udp.Pause();if(domainProxy!=null)domainProxy.Dispose();if(clashProxy!=null)clashProxy.Dispose();domainProxy=clashProxy=null; }
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
                    try{string command=ReadCommand(current);if(command=="tailscale:login")reply=new{url=LoginUrl()};else{HandleCommand(command);reply=Snapshot();}}
                    catch(Exception error){reply=new{error=error.GetBaseException().Message};}
                    byte[] response=Encoding.UTF8.GetBytes(Json.Serialize(reply)+"\n");current.Write(response,0,response.Length);
                }
            }catch{if(!stopping.WaitOne(0))stopping.WaitOne(100);}
            finally{lock(sync)pipe=null;}
        }
    }
    void Run() {
        bool fatal=false;
        progress=new GatewayProgress(Root,Process.GetCurrentProcess().Id);
        try {
            progress.Enter(GatewayStage.LoadConfig);
            var config=ReadJson(Path.Combine(Root,"config.json"));ownerSid=Str(config,"owner_sid");gateway=Str(config,"gateway");adapter=Str(config,"adapter");front=Convert.ToInt32(config["front_port"]);
            if(front<1||front>65535||front>=17891&&front<=17896)throw new IOException("Invalid system proxy port.");
            progress.Enter(GatewayStage.NetworkAdapter);
            var nic=NetworkInterface.GetAllNetworkInterfaces().Single(n=>n.Id.Equals(adapter,StringComparison.OrdinalIgnoreCase));
            lanGateway=GatewayTransport.IsTailscale(gateway)?Str(config,"lan_gateway"):gateway;
            local=GatewayLink.ResolveSource(adapter,lanGateway);adapterName=nic.Name;
            if(File.Exists(Path.Combine(Root,"intent.json")))enabled=Flag(ReadJson(Path.Combine(Root,"intent.json")),"enabled");
            progress.Enter(GatewayStage.ProcessIdentity);
            identity=new ProcessIdentity(Str(config,"desktop_image"),Str(config,"code_image"),ProcessIdentity.ProfileForOwner(ownerSid));
            progress.Enter(GatewayStage.OpenTransport);
            transport=new GatewayTransport(adapter,local,gateway,Root);
            progress.Enter(GatewayStage.LoadRules);
            rules=new RuleFeed(Root,transport,front,networkGuard);identity.RuleName=name=>rules.Active.MatchesProcess(name);transport.RuleForwarding=false;transport.Rules=()=>rules.Active;
            selector=identity.Select;logger=p=>{string value=Marshal.PtrToStringAnsi(p);if(value!=null&&(value.IndexOf("failed",StringComparison.OrdinalIgnoreCase)>=0||value.IndexOf("error",StringComparison.OrdinalIgnoreCase)>=0))nativeError=value;};NativeBridge.SetLogCallback(logger);
            while(true){
                if(stopping.WaitOne(0))return;
                progress.Enter(GatewayStage.ReadGuard);guardReady=Guard();
                if(guardReady){progress.Enter(GatewayStage.BindRelay);try{if(BindRelay())break;}catch(NetworkInformationException){}}
                message="等待保护网卡及策略核验，目标连接已阻断。";Save();
                progress.Enter(GatewayStage.Wait);if(stopping.WaitOne(500))return;
            }
            progress.Enter(GatewayStage.CheckExit);if(!GatewayTransport.IsTailscale(gateway))CheckExit();Firewall();
            progress.Enter(GatewayStage.StartCapture);
            uint proxy=NativeBridge.AddProxy(1,"127.0.0.1",17893,null,null,false);if(proxy==0||!NativeBridge.SetOwnerSelector(selector,proxy,(ushort)front))throw new IOException("Signed process routing setup failed.");
            udp=new UdpForwarder(null,17893){SelectOwner=identity.Select,IsReady=()=>ready};
            connectionTiming=new ConnectionTimingLog(Root);
            if(!NativeBridge.Start())throw new IOException("Process forwarding could not start: "+nativeError);capturing=true;
            pipeWorker=Task.Run((Action)Pipe);DateTime nextLink=DateTime.MinValue,nextFirewall=DateTime.UtcNow.AddSeconds(15);
            bool linkReady=false;
            Task<Dictionary<string,object>> recovery=null;string recoveringGateway="";
            while(!stopping.WaitOne(0)) {
                progress.Enter(GatewayStage.CheckWorkers);
                if(!NativeBridge.Alive()||!transport.Ready)throw new IOException("Network worker stopped.");
                progress.Enter(GatewayStage.ReadGuard);guardReady=Guard();
                // A validated replacement must work even after the old next hop goes offline.
                if(applyRequested){progress.Enter(GatewayStage.ApplyGateway);ApplyCandidate();nextLink=DateTime.MinValue;}
                if(!guardReady){progress.Enter(GatewayStage.CloseRelays);linkReady=false;nextLink=DateTime.MinValue;transport.RuleForwarding=false;CloseProxies();}
                else if(DateTime.UtcNow>=nextLink){
                    var tail=transport.ActiveTailscale;
                    if(tail!=null && tail.Exited)throw new IOException("Tailscale 会话已退出，正在恢复专用后台。");
                    try{progress.Enter(GatewayStage.RefreshGateway);transport.RefreshLink();
                        if(recovery!=null && recovery.IsCompleted){
                            var completed=recovery;recovery=null;
                            var result=completed.GetAwaiter().GetResult();if(recoveringGateway==gateway)SetExit(result);
                        }
                        if(tail!=null && !tail.Verified && recovery==null){
                            var route=transport.RetainActiveRoute();recoveringGateway=gateway;
                            recovery=Task.Run(()=>{using(route)return ProbeRoute(route);});
                        }
                        progress.Enter(GatewayStage.BindRelay);linkReady=(tail==null||tail.Verified)&&BindRelay();}
                    catch(Exception error){nativeError=error.GetBaseException().Message;linkReady=false;}
                    nextLink=DateTime.UtcNow.AddSeconds(tail!=null?1:linkReady?10:2);
                    if(!linkReady){progress.Enter(GatewayStage.CloseRelays);transport.RuleForwarding=false;CloseProxies();}
                }
                if(DateTime.UtcNow>=nextFirewall){Firewall();nextFirewall=DateTime.UtcNow.AddSeconds(15);}
                progress.Enter(GatewayStage.RecheckGuard);guardReady=guardReady&&Guard();
                progress.Enter(!enabled||!guardReady||!linkReady?GatewayStage.CloseRelays:GatewayStage.OpenRelays);
                if(!enabled||!guardReady||!linkReady){CloseProxies();message=enabled?"等待域名保护与网关恢复，目标流量暂停。":"专用连接已暂停，域名保护保留。";}
                else{OpenProxies();ready=true;message="命中域名、IPv4 网段、ASN 或程序名的连接经 "+gateway+"；其他程序保留原路径。";}
                progress.Enter(GatewayStage.ControlCommands);
                lock(sync){if(requestCheck&&!operationBusy){requestCheck=false;BeginValidation(gateway,true);}}
                ExpireCandidate();
                progress.Enter(GatewayStage.WfpLease);
                lock(sync){transport.RuleForwarding=ready&&enabled&&guardReady&&linkReady&&!stopping.WaitOne(0);networkGuard.SetLive(transport.RuleForwarding,rules.Active);}
                progress.Enter(GatewayStage.RuleUpdates);rules.Tick(ready);Save();
                progress.Enter(GatewayStage.Wait);stopping.WaitOne(500);
            }
        }catch(Exception error){message=error.GetBaseException().Message;fatal=!stopping.WaitOne(0);}
        finally {
            progress.Enter(GatewayStage.Shutdown);
            stopping.Set();CloseProxies();if(udp!=null)udp.Dispose();if(capturing)NativeBridge.Stop();capturing=false;if(operationTask!=null)operationTask.Wait(15000);lock(sync){ClearCandidate();if(pipe!=null)pipe.Dispose();}if(rules!=null)rules.Dispose();if(transport!=null)transport.Dispose();if(pipeWorker!=null)pipeWorker.Wait(4000);try{Save();}catch{}GC.KeepAlive(selector);GC.KeepAlive(logger);
            progress.Dispose();
        }
        if(connectionTiming!=null)connectionTiming.Dispose();
        if(fatal)Environment.Exit(1);
    }
    public static int Main(string[] args) { ServiceBase.Run(new GatewayService());return 0; }
}
