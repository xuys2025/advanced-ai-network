using System;
using System.IO;
using System.Threading;

internal static class AlertRegression {
    static void Expect(bool value,string text){if(!value)throw new Exception(text);}
    static void TestCellularRenewal(){
        const string a="203.0.113.1", b="203.0.113.2", c="203.0.113.3";
        var e=new Sentinel.EgressAlerts(a,null);
        Expect(!e.Failure("wan",true,0) && e.FastProbe && e.Rechecking,"first WAN timeout produced a warning");
        Expect(!e.Failure("wan",true,60000),"second timeout produced a warning");
        Expect(e.Verified(b,118000)==null && e.ObservedIp==b && e.ReportedIp==a,"simulated renewal produced an early notification");
        Expect(e.Verified(c,178000)==null && e.Verified(c,239000)==null,"intermediate IP reported");
        Expect(e.Verified(c,254000)=="public-ip-changed" && e.ReportedIp==c && !e.FastProbe,"final verified address was not reported");
        Expect(e.Verified(c,314000)==null,"duplicate address notification");
        e.Failure("wan",true,320000);
        Expect(e.Verified(c,339000)==null,"brief outage with the same IP produced a recovery popup");
        Expect(e.Verified(b,350000)==null && e.Verified(c,410000)==null && !e.FastProbe,"return to original IP produced a popup");
        Expect(!e.Failure("wan",true,420000) && !e.Failure("wan",true,569999),"WAN grace too short");
        Expect(e.Failure("wan",true,570000) && !e.Failure("wan",true,630000),"persistent outage warning missed or repeated");
        Expect(e.Verified(b,640000)=="public-ip-changed" && e.Verified(b,700000)==null,"changed-IP recovery was duplicated");
        e.Failure("wan",true,720000);
        Expect(e.Failure("integrity",false,720001),"invalid proxy ownership or TLS error was hidden");
        Expect(e.Verified(b,720010)=="egress-restored","announced failure never reported recovery");
        var resumed=new Sentinel.EgressAlerts(b,a);
        Expect(resumed.Verified(b,0)==null && resumed.Verified(b,75000)=="public-ip-changed","restart lost pending change");
        var fresh=new Sentinel.EgressAlerts("","");
        Expect(fresh.Verified(a,0)==null && !fresh.FastProbe,"first observed IP produced a popup");
        fresh.Verified(b,1000);fresh.Verified(c,61000);fresh.Verified(b,121000);
        Expect(fresh.Verified(c,181000)=="public-ip-changed","churn suppressed changes indefinitely");
        Expect(Protection.TransientCurlCode(28) && Protection.TransientCurlCode(22) && !Protection.TransientCurlCode(60),"wrong probe failure classification");
        Console.WriteLine("PASS cellular renewal at 118 s, IP churn, unchanged-IP recovery, persistent outages, immediate integrity alerts and observer restart.");
    }
    static int Main(){
        TestCellularRenewal();
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
