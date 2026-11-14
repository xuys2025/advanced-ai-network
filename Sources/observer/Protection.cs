using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class Protection {
    internal const string Service = "AdvancedAINetworkLanGateway";
    internal static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),Service);
    internal static readonly string GuardRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AdvancedAINetworkGuard");
    internal static readonly string Data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AdvancedAINetworkProtection");
    internal static readonly string Bin = AppDomain.CurrentDomain.BaseDirectory;
    internal static readonly Encoding Utf8 = new UTF8Encoding(false);
    internal sealed class View {
        public string state, message, gateway, detail;
        public int pid, front;
        internal bool Ready {get{return state=="ready";}}
    }
    internal sealed class Egress { public string ip, country, gateway; public DateTime measuredUtc; public int servicePid; }
    internal sealed class StatusUnconfirmed : IOException {
        internal StatusUnconfirmed(View sample):base(sample.message+" "+sample.detail){}
        internal StatusUnconfirmed(string message):base(message){}
    }
    internal static Dictionary<string,object> Read(string path) {
        using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){
            if(f.Length>1024*1024)throw new IOException("状态文件过大。");
            using(var r=new StreamReader(f,Encoding.UTF8))return new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(r.ReadToEnd());
        }
    }
    internal static string Str(Dictionary<string,object> d,string key){object v;return d!=null&&d.TryGetValue(key,out v)?Convert.ToString(v,CultureInfo.InvariantCulture):"";}
    internal static bool Flag(Dictionary<string,object> d,string k){object v;return d.TryGetValue(k,out v)&&v is bool&&(bool)v;}
    internal static bool Fresh(Dictionary<string,object> d,double limit){
        DateTimeOffset t;if(!DateTimeOffset.TryParse(Str(d,"updated_utc"),CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out t))return false;
        double age=(DateTimeOffset.UtcNow-t).TotalSeconds;return age>=-2 && age<limit;
    }
    internal static void Save(string path,object value){
        Directory.CreateDirectory(Path.GetDirectoryName(path));string tmp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{File.WriteAllText(tmp,new JavaScriptSerializer().Serialize(value),Utf8);
            if(File.Exists(path))File.Replace(tmp,path,null);else File.Move(tmp,path);}
        finally{if(File.Exists(tmp))File.Delete(tmp);}
    }
    [DllImport("advapi32",SetLastError=true)] static extern bool QueryServiceStatusEx(IntPtr handle,int info,IntPtr buffer,int size,out int required);
    [DllImport("advapi32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32")] static extern bool CloseServiceHandle(IntPtr handle);
    internal static int RunningPid(string name){
        IntPtr manager=OpenSCManager(null,null,1),service=IntPtr.Zero,buffer=IntPtr.Zero;
        try{
            if(manager==IntPtr.Zero||(service=OpenService(manager,name,4))==IntPtr.Zero)throw new IOException("无法查询保护服务。");
            buffer=Marshal.AllocHGlobal(36);int needed;
            if(!QueryServiceStatusEx(service,0,buffer,36,out needed))throw new IOException("无法读取服务状态。");
            return Marshal.ReadInt32(buffer,4)==4?Marshal.ReadInt32(buffer,28):0;
        }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);if(service!=IntPtr.Zero)CloseServiceHandle(service);if(manager!=IntPtr.Zero)CloseServiceHandle(manager);}
    }
    internal static View Inspect(){
        var v=new View{state="unknown",message="正在复核保护状态"};
        string source="网关服务";
        try{
            v.pid=RunningPid(Service);
            if(v.pid==0){v.state="down";v.message="转发后台已停止。请暂停发送，检查网关服务。";return v;}
            source="网关心跳";var s=StatusSnapshotFile.Read(()=>Read(Path.Combine(Root,"status.json")));v.gateway=Str(s,"gateway");int.TryParse(Str(s,"front_port"),out v.front);
            if(Str(s,"service_pid")!=v.pid.ToString() || !Fresh(s,5)){v.state="stale";v.message="转发后台心跳已过期。";return v;}
            if(Str(s,"exit_protection")!="persistent-wfp"){v.state="policy";v.message="当前后台未报告持久阻断功能。";return v;}
            if(!Flag(s,"enabled") && !Flag(s,"process_ip_guard_live")){v.state="paused";v.message="专用联网已暂停。";return v;}
            if(String.IsNullOrEmpty(v.gateway)||v.gateway!=Str(Read(Path.Combine(Root,"config.json")),"gateway")){v.state="gateway";v.message="当前配置的网关是 "+v.gateway+"，请核对出口。";return v;}
            source="域名守护服务";
            if(RunningPid("AdvancedAINetworkDomainGuard")==0){v.state="guard";v.message="域名保护服务已停止。";return v;}
            source="域名守护心跳";var g=StatusSnapshotFile.Read(()=>Read(Path.Combine(GuardRoot,"guard-status.json")));
            if(!Fresh(g,15)||!Flag(g,"tun_ready")||!Flag(g,"network_safety_ready")||!Flag(g,"dns_64_65_blocked")){
                v.state="guard";v.message="独立域名保护尚未就绪。";return v;}
            if(!Flag(s,"ready")||!Flag(s,"capturing")||!Flag(s,"process_ip_guard_live")||!Flag(s,"guard_protected")){
                bool readGap=false;object nested;
                if(s.TryGetValue("guard",out nested)){
                    var embedded=nested as Dictionary<string,object>;
                    readGap=embedded!=null && embedded.ContainsKey("fresh") && !Flag(embedded,"fresh") && !embedded.ContainsKey("tun_ready");
                }
                // The independently read guard is healthy, but the gateway just failed to read it.
                // It really may have revoked its permits. Keep the sampled state visible and log it.
                bool awaitingRead=readGap&&Flag(s,"capturing")&&!Flag(s,"ready")&&!Flag(s,"process_ip_guard_live")&&!Flag(s,"guard_protected");
                v.state=awaitingRead?"unknown":"protection";
                v.message=awaitingRead?"网关正在复核守护心跳，放行已暂停。":"后台报告程序分流或保护未就绪。";
                v.detail="ready="+Flag(s,"ready")+", capture="+Flag(s,"capturing")+", lease="+Flag(s,"process_ip_guard_live")+", guard="+Flag(s,"guard_protected")+", guard_read_gap="+readGap;
                return v;}
            v.state="ready";v.message="网关与保护后台正常";return v;
        }catch(Exception ex){v.detail=source+" "+ex.GetType().Name+" 0x"+ex.HResult.ToString("X8");return v;}
    }
    [DllImport("iphlpapi")] static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool sort,int family,int tableClass,uint reserved);
    static bool OwnsProxy(int pid){
        int size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,3,0);
        for(int attempt=0;attempt<3&&size>0&&size<4194304;attempt++){
            IntPtr memory=Marshal.AllocHGlobal(size);
            try{int capacity=size;uint rc=GetExtendedTcpTable(memory,ref size,false,2,3,0);
                if(rc==122)continue;if(rc!=0)return false;
                int count=Marshal.ReadInt32(memory);if(count<0||count>(capacity-4)/24)return false;
                for(int i=0;i<count;i++){
                    IntPtr row=IntPtr.Add(memory,4+24*i);
                    int port=(Marshal.ReadByte(row,8)<<8)|Marshal.ReadByte(row,9);
                    if(port==17891 && Marshal.ReadInt32(row,4)==0x0100007f && Marshal.ReadInt32(row,20)==pid)return true;
                }return false;
            }finally{Marshal.FreeHGlobal(memory);}
        }return false;
    }
    internal sealed class TransientProbeError : IOException {
        internal TransientProbeError(string message):base(message){}
    }
    internal static bool TransientCurlCode(int code){
        switch(code){
            case 5: case 6: case 7: case 18: case 22: case 28: case 52: case 55: case 56:return true;
            default:return false;
        }
    }
    internal static string Run(string image,string args,int timeout,bool requireSuccess,bool egressProbe=false){
        using(var child=new Process()){
            child.StartInfo=new ProcessStartInfo(image,args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};
            child.Start();var output=child.StandardOutput.ReadToEndAsync();var error=child.StandardError.ReadToEndAsync();
            if(!child.WaitForExit(timeout)){
                try{child.Kill();}catch(InvalidOperationException){}
                if(egressProbe)throw new TransientProbeError("HTTPS 出口检查超时。");
                throw new IOException("操作超时。");
            }
            string text=output.GetAwaiter().GetResult().Trim();string detail=error.GetAwaiter().GetResult().Trim();
            if(requireSuccess&&child.ExitCode!=0){
                string message=detail.Length>0?detail.Substring(0,Math.Min(detail.Length,200)):"出口检查未完成。";
                if(egressProbe&&TransientCurlCode(child.ExitCode))throw new TransientProbeError(message);
                throw new IOException(message);
            }
            return text;
        }
    }
    internal static Egress Check(){
        var before=Inspect();if(!before.Ready)throw new StatusUnconfirmed(before);
        if(!OwnsProxy(before.pid))throw new IOException("专用入口与网关服务进程不匹配。");
        string curl=Path.Combine(Environment.SystemDirectory,"curl.exe");
        string trace=Run(curl,"-q --silent --show-error --fail --ipv4 --proto =https --connect-timeout 4 --max-time 8 --max-filesize 4096 --noproxy invalid.example --proxy http://127.0.0.1:17891 https://one.one.one.one/cdn-cgi/trace",10000,true,true);
        string ip="",country="";
        foreach(string raw in trace.Split('\n')){string line=raw.Trim();if(line.StartsWith("ip="))ip=line.Substring(3);if(line.StartsWith("loc="))country=line.Substring(4);}
        IPAddress parsed;if(!IPAddress.TryParse(ip,out parsed)||parsed.AddressFamily!=AddressFamily.InterNetwork||parsed.ToString()!=ip)throw new IOException("出口检测站未返回有效 IPv4。");
        var after=Inspect();if(!after.Ready)throw new StatusUnconfirmed(after);
        if(after.pid!=before.pid || after.gateway!=before.gateway)throw new StatusUnconfirmed("检查期间网关或服务进程已更换。");
        if(!OwnsProxy(after.pid))throw new IOException("检查期间专用入口的进程发生变化。");
        return new Egress{gateway=after.gateway,ip=ip,country=country,measuredUtc=DateTime.UtcNow,servicePid=after.pid};
    }
    internal static string Agent {
        get{return Path.Combine(Bin,"AdvancedAINetworkAgent.exe");}
    }
    static void PersistOfflinePause(){
        // Only a user click can reach this fallback. The command is embedded,
        // runs with UAC and touches only the verified, administrator-owned service.
        const string script=@"$ErrorActionPreference='Stop'
$name='AdvancedAINetworkLanGateway'
$root=Join-Path $env:ProgramData $name
$file=Join-Path $root 'intent.json'
foreach($p in @($root,$file)){
  if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked configuration'}
}
$owner=(Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value
if($owner -notin 'S-1-5-18','S-1-5-32-544'){throw 'Unexpected owner'}
$svc=Get-CimInstance Win32_Service -Filter ""Name='AdvancedAINetworkLanGateway'""
if($svc.PathName.Trim([char]34) -ne (Join-Path $root 'GatewayService.exe')){throw 'Unexpected service'}
$tmp=Join-Path $root ([Guid]::NewGuid().ToString('N')+'.tmp')
try{
  [IO.File]::WriteAllText($tmp,(@{enabled=$false}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
  [IO.File]::Replace($tmp,$file,[System.Management.Automation.Language.NullString]::Value)
}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
if((Get-Service $name).Status -ne 'Stopped'){Stop-Service $name -ErrorAction Stop;Start-Service $name -ErrorAction Stop}";
        string args="-NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        using(var p=Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe"),args){Verb="runas",UseShellExecute=true,WindowStyle=ProcessWindowStyle.Hidden})){
            p.WaitForExit();if(p.ExitCode!=0)throw new IOException("应急暂停未完成。");
        }
    }
    static bool IntentOff(){var intent=Read(Path.Combine(Root,"intent.json"));return intent.ContainsKey("enabled")&&intent["enabled"] is bool&&!((bool)intent["enabled"]);}
    static bool Denied(int front){
        var result=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(Run(Path.Combine(Bin,"probe",AiCompatibility.S_11b496da7187c8),"tcp 127.0.0.1 "+front,4500,false));
        return result.ContainsKey("ok")&&!Flag(result,"ok")&&Str(result,"code")=="10013";
    }
    internal static void Pause(){
        // The user invokes this explicitly. Network or notification failures never invoke it.
        Exception last=null;
        for(int attempt=0;attempt<3;attempt++){
            try{Run(Agent,"--command disable",9000,true);last=null;break;}
            catch(Exception error){last=error;if(RunningPid(Service)==0)break;Thread.Sleep(500);}
        }
        if(last!=null && (!IntentOff() || Inspect().state=="ready"))PersistOfflinePause();
        for(int i=0;i<40;i++){
            var v=Inspect();
            if((v.state=="paused"||v.state=="down") && IntentOff()){
                int front=Convert.ToInt32(Read(Path.Combine(Root,"config.json"))["front_port"]);
                if(Denied(front))return;
            }
            Thread.Sleep(200);
        }
        throw new IOException("暂停状态尚未通过 Windows 阻断验证。请先关闭目标程序。");
    }
}
