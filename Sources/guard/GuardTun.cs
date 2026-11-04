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
public sealed class GuardTun : IDisposable {
    readonly string folder;readonly DomainGuard guard;readonly object sync=new object(),logSync=new object();
    Process process;IntPtr job;CancellationTokenSource cancellation;Task worker;bool ready;int failures;string lastError="",lastCoreError="";DateTime safetyChecked=DateTime.MinValue;
    public GuardTun(string directory,DomainGuard dns){folder=directory;guard=dns;}
    public void Start(){cancellation=new CancellationTokenSource();worker=Task.Run(()=>Run(cancellation.Token));}
    public static int RouteInterface(string destination){uint index;int error=GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse(destination).GetAddressBytes(),0),out index);if(error!=0)throw new Exception("Unable to inspect protected route: "+error);return (int)index;}
    static int TunIndex(){try{var adapter=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x=>x.Name==GuardPolicy.InterfaceName);return adapter==null?0:adapter.GetIPProperties().GetIPv4Properties().Index;}catch{return 0;}}
    bool Running {get{lock(sync){return process!=null&&!process.HasExited;}}}
    bool Routed {get{int index=TunIndex();return index!=0&&RouteInterface(GuardPolicy.Address(1))==index;}}
    void Log(string line){lock(logSync){try{line=LogText.Clean(line);if(String.IsNullOrWhiteSpace(line))return;string path=Path.Combine(folder,"tun-service.log");if(File.Exists(path)&&new FileInfo(path).Length>256*1024){File.Copy(path,path+".previous",true);File.WriteAllText(path,"");}File.AppendAllText(path,DateTime.UtcNow.ToString("o")+" "+line+Environment.NewLine,new UTF8Encoding(false));}catch{}}}
    void Publish(){try{var status=Data.Obj("version",GuardPolicy.Version,"policy_hash",Data.PolicyHash,"protected_roots",Data.Roots,"protected_exact",Data.Exact,"protected_keywords",Data.Keywords,"updated_utc",DateTime.UtcNow.ToString("o"),"tun_ready",ready,"network_safety_ready",(DateTime.UtcNow-safetyChecked).TotalSeconds<45,"tun_prefix",GuardPolicy.Prefix,"tun_interface",GuardPolicy.InterfaceName,"core_pid",Running?process.Id:0,"restart_failures",failures,"last_error",lastError,"dns_64_65_blocked",true,"dns",guard.Statistics());string path=Path.Combine(folder,"guard-status.json"),temp=path+".tmp";File.WriteAllText(temp,Data.Json(status),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);}catch(Exception ex){Log("Status write failed: "+ex.Message);}}
    void Run(CancellationToken token){
        DateTime nextAttempt=DateTime.MinValue,nextRepair=DateTime.MinValue;
        while(!token.IsCancellationRequested){
            try{
                if(DateTime.UtcNow>=nextRepair){Data.PowerShell(Path.Combine(folder,"Guard-Setup.ps1"),"Repair");safetyChecked=DateTime.UtcNow;nextRepair=DateTime.UtcNow.AddSeconds(30);}
                if(!Running||!Routed){
                    if(ready){lastError="TUN process or protected route was lost; target traffic remains blocked.";Log(lastError);ready=false;StopCore(token);nextAttempt=DateTime.UtcNow.AddSeconds(2);}
                    if(DateTime.UtcNow>=nextAttempt){StartCore(token);ready=true;lastError="";failures=0;Log("Selective TUN ready: "+GuardPolicy.Prefix);}
                }else ready=true;
            }catch(OperationCanceledException){break;}
            catch(Exception ex){ready=false;safetyChecked=DateTime.MinValue;failures++;lastError=LogText.Clean(ex.GetBaseException().Message);Log("TUN startup/health error: "+lastError);try{StopCore(token);}catch(Exception stop){Log(stop.Message);}nextAttempt=DateTime.UtcNow.AddSeconds(Math.Min(60,5*failures));nextRepair=nextAttempt;}
            Publish();if(token.WaitHandle.WaitOne(1000))break;
        }
        ready=false;safetyChecked=DateTime.MinValue;try{StopCore(CancellationToken.None);}catch(Exception ex){lastError=ex.Message;Log(ex.Message);}Publish();
    }
    void StartCore(CancellationToken token){
        StopCore(token);token.ThrowIfCancellationRequested();
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
        bool hadCore=false;lock(sync){if(process!=null){hadCore=true;try{if(!process.HasExited){process.Kill();if(!process.WaitForExit(5000))throw new Exception("TUN core did not terminate.");}}finally{process.Dispose();process=null;}}if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}
        if(hadCore){DateTime deadline=DateTime.UtcNow.AddSeconds(12);while(TunIndex()!=0&&DateTime.UtcNow<deadline){if(token.WaitHandle.WaitOne(200))break;}if(!token.IsCancellationRequested)token.WaitHandle.WaitOne(750);}
    }
    public void Dispose(){if(cancellation==null)return;cancellation.Cancel();if(worker!=null&&!worker.Wait(20000)){lock(sync){if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}}cancellation.Dispose();cancellation=null;}
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
