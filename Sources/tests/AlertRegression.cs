using System;
using System.IO;
using System.Threading;

internal static class AlertRegression {
    static void Expect(bool value,string text){if(!value)throw new Exception(text);}
    static int Main(){
        var alerts=new Sentinel.Alerts();
        Expect(alerts.Transition("ready",11,0),"initial state missing");
        Expect(!alerts.Transition("unknown",11,100),"single failed read raised an alarm");
        Expect(!alerts.Transition("unknown",11,2100),"second short read raised an alarm");
        Expect(!alerts.Transition("ready",11,4100),"spurious recovery after an unannounced read failure");
        Expect(!alerts.Transition("unknown",11,5000),"recheck should be pending");
        Expect(alerts.Transition("down",0,5100),"real service stop was delayed");
        Expect(alerts.Transition("ready",12,7100),"real recovery missing");
        Expect(alerts.Transition("protection",12,7150),"explicit forwarding/lease failure was delayed");
        Expect(alerts.Transition("guard",12,7200),"explicit guard failure was delayed");
        Expect(alerts.Transition("ready",12,7300),"real protection recovery missing");
        Expect(!alerts.Transition("unknown",12,8000),"premature uncertainty alarm");
        Expect(!alerts.Transition("unknown",12,12000),"four-second transient was reported");
        Expect(alerts.Transition("unknown",12,14000),"persistent unreadable status was silenced");
        Expect(!alerts.Transition("unknown",12,16000),"repeated uncertain alarm");
        Expect(alerts.Transition("ready",12,18000),"persistent uncertainty recovery missing");
        Expect(alerts.Transition("ready",13,20000),"service PID change missed");
        string file=Path.GetTempFileName();
        try{
            File.WriteAllText(file,"current");
            using(var busy=new FileStream(file,FileMode.Open,FileAccess.ReadWrite,FileShare.None)){
                int calls=0;bool failed=false;
                try{StatusSnapshotFile.Read(()=>{calls++;return File.ReadAllText(file);});}catch(IOException){failed=true;}
                Expect(failed&&calls==4,"exhausted file locks must fail closed");
            }
            int attempts=0;
            string content=StatusSnapshotFile.Read(()=>{
                attempts++;
                if(attempts==1)throw new IOException("sharing violation",unchecked((int)0x80070020));
                File.WriteAllText(file,"new snapshot");return File.ReadAllText(file);
            });
            Expect(attempts==2&&content=="new snapshot","a retry must read the new snapshot");
            int reads=0;
            Expect(!StatusSnapshotFile.Read(()=>{reads++;return false;})&&reads==1,"explicit unsafe status was retried");
        }finally{File.Delete(file);}
        Console.WriteLine("PASS notification transitions, service/PID/guard failures, bounded sharing retries, fresh reads and fail-closed errors.");
        return 0;
    }
}
