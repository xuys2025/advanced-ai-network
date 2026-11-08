using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AdvancedAINetwork {
// Only this supervisor consumes completed checks. A slow helper never owns the
// heartbeat thread or the TUN process and cannot renew an expired verification.
internal sealed class GuardMaintenance {
    readonly Func<CancellationToken,Task<DateTime>> launch;
    readonly Action<string> log;
    Task<DateTime> pending;
    DateTime next=DateTime.MinValue;
    internal DateTime Verified {get;private set;}
    internal DateTime ValidUntil {get{return Verified==DateTime.MinValue?DateTime.MinValue:Verified.AddSeconds(45);}}
    internal bool Busy {get{return pending!=null;}}
    internal int Failures {get;private set;}
    internal string Error {get;private set;}
    internal GuardMaintenance(Func<CancellationToken,Task<DateTime>> launch,Action<string> log){this.launch=launch;this.log=log;Error="";}
    internal bool Safe(DateTime now){return Verified!=DateTime.MinValue && now>=Verified && now<ValidUntil;}
    internal void Tick(DateTime now,CancellationToken token){
        if(pending!=null && pending.IsCompleted){
            try{
                Verified=pending.GetAwaiter().GetResult();
                if(Failures>0)log("Protection policy verified again.");
                Error="";Failures=0;next=Verified.AddSeconds(20);
            }catch(OperationCanceledException){throw;}
            catch(Exception ex){
                Verified=DateTime.MinValue;Failures++;Error=LogText.Clean(ex.GetBaseException().Message);
                log("Protection policy verification failed: "+Error);
                next=now.AddSeconds(Math.Min(15,2*Failures));
            }finally{pending=null;}
        }
        token.ThrowIfCancellationRequested();
        if(pending==null && now>=next)pending=launch(token);
    }
    internal void Join(){if(pending!=null)try{pending.GetAwaiter().GetResult();}catch(Exception){}}
}
internal enum TunWork { Keep, Wait, Start, Stop }
internal sealed class TunLiveness {
    int absent;
    internal TunWork Inspect(bool running,bool? routed,bool verified,bool canRetry){
        if(!running){absent=0;return verified&&canRetry?TunWork.Start:TunWork.Wait;}
        if(routed==true){absent=0;return TunWork.Keep;}
        if(!routed.HasValue){absent=0;return TunWork.Wait;}
        return ++absent>=3?TunWork.Stop:TunWork.Wait;
    }
}
public sealed class GuardTun : IDisposable {
    readonly string folder;readonly DomainGuard guard;readonly object sync=new object(),logSync=new object();
    readonly GuardMaintenance maintenance;
    readonly TunLiveness liveness=new TunLiveness();
    Process process;IntPtr job;CancellationTokenSource cancellation;Task worker;bool ready;int failures;string lastError="",lastCoreError="";
    public GuardTun(string directory,DomainGuard dns){
        folder=directory;guard=dns;
        maintenance=new GuardMaintenance(token=>Task.Run(()=>{
            Data.PowerShell(Path.Combine(folder,"Guard-Setup.ps1"),"Repair",25000,token);
            return DateTime.UtcNow;
        },token),Log);
    }
    public void Start(){cancellation=new CancellationTokenSource();worker=Task.Run(()=>Run(cancellation.Token));}
    public static int RouteInterface(string destination){uint index;int error=GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse(destination).GetAddressBytes(),0),out index);if(error!=0)throw new Exception("Unable to inspect protected route: "+error);return (int)index;}
    static int TunIndex(){var adapter=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x=>x.Name==GuardPolicy.InterfaceName);return adapter==null?0:adapter.GetIPProperties().GetIPv4Properties().Index;}
    bool Running {get{lock(sync){return process!=null&&!process.HasExited;}}}
    bool Routed {get{int index=TunIndex();return index!=0&&RouteInterface(GuardPolicy.Address(1))==index;}}
    void Log(string line){lock(logSync){try{line=LogText.Clean(line);if(String.IsNullOrWhiteSpace(line))return;string path=Path.Combine(folder,"tun-service.log");if(File.Exists(path)&&new FileInfo(path).Length>256*1024){File.Copy(path,path+".previous",true);File.WriteAllText(path,"");}File.AppendAllText(path,DateTime.UtcNow.ToString("o")+" "+line+Environment.NewLine,new UTF8Encoding(false));}catch{}}}
    void Publish(){
        DateTime now=DateTime.UtcNow;
        bool safe=!cancellation.IsCancellationRequested&&maintenance.Safe(now);
        guard.SetForwardUntil(ready&&safe?maintenance.ValidUntil:DateTime.MinValue);
        try{
            var status=Data.Obj("version",GuardPolicy.Version,"maintenance_revision",2,"policy_hash",Data.PolicyHash,
                "protected_roots",Data.Roots,"protected_exact",Data.Exact,"protected_keywords",Data.Keywords,
                "updated_utc",now.ToString("o"),"tun_ready",ready,"network_safety_ready",safe,
                "safety_valid_until_utc",maintenance.ValidUntil.ToString("o"),"safety_verified_utc",maintenance.Verified.ToString("o"),
                "maintenance_busy",maintenance.Busy,"maintenance_failures",maintenance.Failures,"maintenance_error",maintenance.Error,
                "tun_prefix",GuardPolicy.Prefix,"tun_interface",GuardPolicy.InterfaceName,"core_pid",Running?process.Id:0,
                "restart_failures",failures,"last_error",lastError,"dns_64_65_blocked",true,"dns",guard.Statistics());
            string path=Path.Combine(folder,"guard-status.json"),temp=path+".tmp";
            File.WriteAllText(temp,Data.Json(status),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
        }catch(Exception ex){Log("Status write failed: "+ex.Message);}
    }
    void Run(CancellationToken token){
        DateTime nextAttempt=DateTime.MinValue;
        while(!token.IsCancellationRequested){
            try{
                maintenance.Tick(DateTime.UtcNow,token);
                bool running=Running;
                bool? routed=null;
                if(running)try{routed=Routed;}catch(Exception error){if(ready)Log("Route query failed: "+error.Message);}
                var now=DateTime.UtcNow;
                var action=liveness.Inspect(running,routed,maintenance.Safe(now),now>=nextAttempt);
                ready=action==TunWork.Keep;
                if(action==TunWork.Stop){
                    Publish();lastError="Protected route was absent on three checks.";Log(lastError);
                    StopCore(token);nextAttempt=DateTime.UtcNow.AddSeconds(2);
                }else if(action==TunWork.Start){
                    Publish();StartCore(token);ready=true;lastError="";failures=0;Log("Selective TUN ready: "+GuardPolicy.Prefix);
                }
            }catch(OperationCanceledException){break;}
            catch(Exception ex){ready=false;Publish();failures++;lastError=LogText.Clean(ex.GetBaseException().Message);Log("TUN lifecycle error: "+lastError);try{StopCore(token);}catch(Exception stop){Log(stop.Message);}nextAttempt=DateTime.UtcNow.AddSeconds(Math.Min(60,5*failures));}
            Publish();if(token.WaitHandle.WaitOne(1000))break;
        }
        ready=false;Publish();try{StopCore(token);}catch(Exception ex){Log(ex.Message);}maintenance.Join();Publish();
    }
    void StartCore(CancellationToken token){
        StopCore(token);token.ThrowIfCancellationRequested();
        if(TunIndex()!=0)throw new IOException("Waiting for the previous TUN interface to disappear.");
        string core=Path.Combine(folder,"core","sing-box.exe");
        if(!File.Exists(core)||Data.Hash(core)!=BuildFacts.CoreSha256)throw new Exception("Protected TUN core is missing or failed SHA-256 verification.");
        string config=Path.Combine(folder,"tun-core.json");File.WriteAllText(config,Data.Json(GuardPolicy.TunConfig()),new UTF8Encoding(false));
        lastCoreError="";
        lock(sync){
            job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Exception("Unable to create TUN process job.");
            var info=new ExtendedLimits();info.Basic.LimitFlags=0x2000;int size=Marshal.SizeOf(typeof(ExtendedLimits));IntPtr ptr=Marshal.AllocHGlobal(size);
            try{Marshal.StructureToPtr(info,ptr,false);if(!SetInformationJobObject(job,9,ptr,(uint)size))throw new Exception("Unable to protect TUN process lifetime.");}finally{Marshal.FreeHGlobal(ptr);}
            process=new Process{StartInfo=new ProcessStartInfo(core,"run -c \""+config+"\""){WorkingDirectory=folder,UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true,RedirectStandardOutput=true,StandardErrorEncoding=Encoding.UTF8,StandardOutputEncoding=Encoding.UTF8}};
            process.ErrorDataReceived+=(s,e)=>{if(e.Data!=null){lastCoreError=LogText.Clean(e.Data);Log(e.Data);}};process.OutputDataReceived+=(s,e)=>{if(e.Data!=null)Log(e.Data);};
            process.Start();if(!AssignProcessToJobObject(job,process.Handle))throw new Exception("Unable to attach TUN process to service lifetime.");process.BeginErrorReadLine();process.BeginOutputReadLine();
        }
        DateTime deadline=DateTime.UtcNow.AddSeconds(22);
        do{token.ThrowIfCancellationRequested();if(!Running)throw new Exception("TUN core exited: "+lastCoreError);if(Routed)return;Publish();if(token.WaitHandle.WaitOne(250))token.ThrowIfCancellationRequested();}while(DateTime.UtcNow<deadline);
        throw new Exception("TUN route did not become ready. "+lastCoreError);
    }
    void StopCore(CancellationToken token){
        bool hadCore=false;
        lock(sync){
            try{
                if(process!=null){
                    hadCore=true;
                    try{if(!process.HasExited){process.Kill();if(!process.WaitForExit(5000))throw new IOException("TUN core did not terminate.");}}
                    finally{process.Dispose();process=null;}
                }
            }finally{if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}
        }
        if(hadCore){
            var elapsed=Stopwatch.StartNew();
            while(!token.IsCancellationRequested&&TunIndex()!=0&&elapsed.ElapsedMilliseconds<12000)token.WaitHandle.WaitOne(200);
        }
    }
    public void Dispose(){
        if(cancellation==null)return;
        cancellation.Cancel();
        if(worker!=null && !worker.Wait(25000)){
            lock(sync){if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}
            if(!worker.Wait(3000))throw new TimeoutException("TUN supervisor did not stop.");
        }
        cancellation.Dispose();cancellation=null;
    }
    [StructLayout(LayoutKind.Sequential)]struct BasicLimits{public long P1,P2;public uint LimitFlags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
    [StructLayout(LayoutKind.Sequential)]struct IoCounters{public ulong R1,R2,R3,R4,R5,R6;}
    [StructLayout(LayoutKind.Sequential)]struct ExtendedLimits{public BasicLimits Basic;public IoCounters Io;public UIntPtr P1,P2,P3,P4;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr CreateJobObject(IntPtr attributes,string name);
    [DllImport("kernel32.dll")]static extern bool SetInformationJobObject(IntPtr h,int type,IntPtr info,uint length);
    [DllImport("kernel32.dll")]static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
    [DllImport("iphlpapi.dll")]static extern int GetBestInterface(uint destination,out uint index);
}
}
