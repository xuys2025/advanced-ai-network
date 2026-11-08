using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using AdvancedAINetwork;

internal static class Regression {
    static void Expect(bool value,string error){if(!value)throw new Exception(error);}
    public static int Main(){
        var t=new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc);
        var token=CancellationToken.None;
        TaskCompletionSource<DateTime> check=null;int calls=0;
        var maintenance=new GuardMaintenance(c=>{calls++;check=new TaskCompletionSource<DateTime>();return check.Task;},s=>{});
        var core=new TunLiveness();
        maintenance.Tick(t,token);Expect(!maintenance.Safe(t)&&calls==1,"startup was permitted");
        check.SetResult(t);maintenance.Tick(t,token);
        Expect(maintenance.Safe(t)&&core.Inspect(false,false,true,true)==TunWork.Start,"verified startup failed");
        for(int i=1;i<=70;i++){
            var now=t.AddSeconds(i);maintenance.Tick(now,token);
            Expect(maintenance.Safe(now)==(i<45),"safety deadline changed while helper stalled");
            Expect(core.Inspect(true,true,maintenance.Safe(now),true)==TunWork.Keep,"slow check tore down a healthy TUN");
        }
        Expect(calls==2,"overlapping maintenance tasks");
        check.SetException(new TimeoutException("fixture timeout"));maintenance.Tick(t.AddSeconds(71),token);
        Expect(!maintenance.Safe(t.AddSeconds(71))&&maintenance.Failures==1,"timeout granted forwarding");
        maintenance.Tick(t.AddSeconds(73),token);
        var verified=t.AddSeconds(74);check.SetResult(verified);maintenance.Tick(verified,token);
        Expect(maintenance.Safe(verified)&&core.Inspect(true,true,true,true)==TunWork.Keep,"recovery required a new TUN");
        maintenance.Tick(t.AddSeconds(95),token);
        check.SetException(new IOException("invalid effective policy"));maintenance.Tick(t.AddSeconds(96),token);
        Expect(!maintenance.Safe(t.AddSeconds(96)),"explicit policy failure kept a previous success alive");
        Expect(core.Inspect(true,false,false,true)==TunWork.Wait,"one missing route restarted core");
        Expect(core.Inspect(true,null,false,true)==TunWork.Wait,"query failure restarted core");
        for(int i=0;i<2;i++)Expect(core.Inspect(true,false,true,true)==TunWork.Wait,"route grace was skipped");
        Expect(core.Inspect(true,false,true,true)==TunWork.Stop,"persistent route loss ignored");
        Expect(core.Inspect(false,false,false,true)==TunWork.Wait,"unverified core started");
        Expect(core.Inspect(false,false,true,false)==TunWork.Wait,"retry backoff ignored");
        Expect(core.Inspect(false,false,true,true)==TunWork.Start,"dead core was never restarted");
        string script=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"SlowFixture.ps1");
        var elapsed=Stopwatch.StartNew();bool timedOut=false;
        try{Data.PowerShell(script,"Repair",3500,token);}catch(TimeoutException ex){timedOut=ex.Message.Contains("fixture wait");}
        Expect(timedOut&&elapsed.Elapsed.TotalSeconds<9,"missing timeout stage or unbounded process wait");
        Console.WriteLine("PASS single in-flight check, 45-second expiry, 70 heartbeats, timeout, failed policy, same-core recovery, actual route loss and labelled PowerShell timeout.");return 0;
    }
}
