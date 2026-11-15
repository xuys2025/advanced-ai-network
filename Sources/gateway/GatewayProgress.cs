using System;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Web.Script.Serialization;

// Diagnostic breadcrumbs only. Only the gateway worker writes this map.
// Neither a reader nor a stage update can refresh the actual safety heartbeat.
internal enum GatewayStage {
    Startup=1, LoadConfig, NetworkAdapter, ProcessIdentity, OpenTransport, LoadRules,
    ReadGuard, BindRelay, CheckExit, StartCapture, CheckWorkers, RefreshGateway,
    FirewallIdentity, FirewallProfiles, FirewallLookup, FirewallCompare, FirewallRepair,
    RecheckGuard, CloseRelays, OpenRelays, ApplyGateway, ControlCommands, WfpLease,
    RuleUpdates, BuildSnapshot, PublishSnapshot, Wait, Shutdown
}

internal sealed class GatewayProgress : IDisposable {
    const string MapName="heartbeat-progress.bin";
    const int Layout=1, Size=16;
    internal const string Journal="heartbeat-stalls.jsonl";
    readonly string root;
    readonly int pid;
    MemoryMappedFile map;
    MemoryMappedViewAccessor view;
    long stageStart, lastBeat, longestMs;
    DateTime lastBeatUtc;
    GatewayStage stage, longestStage;

    static long NowMs(){return (long)(Stopwatch.GetTimestamp()*(1000.0/Stopwatch.Frequency));}
    internal GatewayProgress(string root,int pid){
        this.root=root;this.pid=pid;
        lastBeat=stageStart=NowMs();lastBeatUtc=DateTime.UtcNow;
        stage=longestStage=GatewayStage.Startup;
        try{
            using(var file=new FileStream(Path.Combine(root,MapName),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.ReadWrite|FileShare.Delete)){
                if(file.Length!=Size)file.SetLength(Size);
                map=MemoryMappedFile.CreateFromFile(file,null,Size,MemoryMappedFileAccess.ReadWrite,HandleInheritability.None,true);
            }
            view=map.CreateViewAccessor(0,Size,MemoryMappedFileAccess.ReadWrite);
            view.Write(0,0);view.Write(4,pid);Publish();view.Write(0,Layout);
        }catch(IOException){Dispose();}catch(UnauthorizedAccessException){Dispose();}
    }
    void Publish(){
        // Windows x64. One aligned 64-bit word ties the stage to its monotonic start time.
        if(view!=null)view.Write(8,(stageStart<<8)|(byte)stage);
    }
    void CompleteStage(long now){
        long duration=now-stageStart;
        if(duration>longestMs){longestMs=duration;longestStage=stage;}
    }
    internal void Enter(GatewayStage next){
        long now=NowMs();CompleteStage(now);stage=next;stageStart=now;Publish();
    }
    internal void Published(){
        long now=NowMs();CompleteStage(now);
        long gap=now-lastBeat;
        if(gap>=5000){
            var entry=new {observed_utc=DateTime.UtcNow.ToString("o"),pid=pid,previous_publish_or_start_utc=lastBeatUtc.ToString("o"),
                gap_ms=gap,longest_stage=longestStage.ToString(),longest_stage_ms=longestMs};
            try{
                string path=Path.Combine(root,Journal);
                if(File.Exists(path)&&new FileInfo(path).Length>=512*1024){
                    string old=path+".previous";if(File.Exists(old))File.Delete(old);File.Move(path,old);
                }
                File.AppendAllText(path,new JavaScriptSerializer().Serialize(entry)+Environment.NewLine,new UTF8Encoding(false));
            }catch(IOException){}catch(UnauthorizedAccessException){}
        }
        lastBeat=stageStart=now;lastBeatUtc=DateTime.UtcNow;longestMs=0;longestStage=stage;
    }
    internal static string Describe(string root,int expectedPid){
        try{
            using(var file=new FileStream(Path.Combine(root,MapName),FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)){
                if(file.Length!=Size)return "stage=unavailable";
                using(var m=MemoryMappedFile.CreateFromFile(file,null,0,MemoryMappedFileAccess.Read,HandleInheritability.None,true))
                using(var v=m.CreateViewAccessor(0,Size,MemoryMappedFileAccess.Read)){
                    if(v.ReadInt32(0)!=Layout || v.ReadInt32(4)!=expectedPid)return "stage=unavailable";
                    long word=v.ReadInt64(8),elapsed=NowMs()-(word>>8);
                    var current=(GatewayStage)(word&255);
                    if(!Enum.IsDefined(typeof(GatewayStage),current)||elapsed<0||v.ReadInt32(4)!=expectedPid)return "stage=unavailable";
                    return "stage="+current+" stage_ms="+elapsed;
                }
            }
        }catch(IOException){return "stage=unavailable";}catch(UnauthorizedAccessException){return "stage=unavailable";}
    }
    public void Dispose(){
        if(view!=null){view.Dispose();view=null;}
        if(map!=null){map.Dispose();map=null;}
    }
}
