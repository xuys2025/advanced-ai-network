using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Dynamic;
using System.IO;
using System.Threading;
using System.Web.Script.Serialization;

internal static class GatewayMaintenanceTests {
    public sealed class Rule : DynamicObject {
        internal readonly Dictionary<string,object> values=new Dictionary<string,object>();
        internal readonly List<string> writes=new List<string>();
        public override bool TryGetMember(GetMemberBinder key,out object value){return values.TryGetValue(key.Name,out value);}
        public override bool TrySetMember(SetMemberBinder key,object value){writes.Add(key.Name);values[key.Name]=value;return true;}
    }
    static void Expect(bool ok,string message){if(!ok)throw new Exception(message);}
    static void TestRule(bool tun){
        var rule=new Rule();Action writing=delegate{};
        const string ip="172.31.254.1",adapter="test-tun";
        int created=GatewayFirewallRule.Reconcile(rule,true,tun,ip,adapter,writing);
        Expect(created==(tun?8:6)&&created==rule.writes.Count,"new rule not initialized");
        if(tun){rule.values["LocalAddresses"]=ip+"/255.255.255.255";rule.values["Interfaces"]=new string[]{adapter.ToUpperInvariant()};}
        else rule.values["RemoteAddresses"]=((string)rule.values["RemoteAddresses"]).ToUpperInvariant();
        rule.writes.Clear();
        Expect(GatewayFirewallRule.Reconcile(rule,false,tun,ip,adapter,writing)==0 && rule.writes.Count==0,"unchanged rule was written");
        var bad=new Dictionary<string,object>{{"Protocol",17},{"Enabled",false},{"Profiles",1},{"Direction",9},{"Action",8}};
        if(tun){bad.Add("LocalAddresses",ip+"/24");bad.Add("LocalPorts","34010,34011");bad.Add("Interfaces",new[]{adapter,"another-adapter"});}
        else bad.Add("RemoteAddresses","*");
        foreach(var field in bad){
            rule.values[field.Key]=field.Value;rule.writes.Clear();
            Expect(GatewayFirewallRule.Reconcile(rule,false,tun,ip,adapter,writing)==1 && rule.writes.Count==1 && rule.writes[0]==field.Key,"unexpected writes repairing "+field.Key);
            Expect(GatewayFirewallRule.Reconcile(rule,false,tun,ip,adapter,writing)==0,"repair did not settle");
        }
    }
    public static int Main(string[] args){
        if(args.Length==2){Console.WriteLine(GatewayProgress.Describe(args[0],int.Parse(args[1])));return 0;}
        TestRule(true);TestRule(false);
        string root=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try{
            using(var me=Process.GetCurrentProcess())
            using(var progress=new GatewayProgress(root,me.Id)){
                progress.Published();progress.Enter(GatewayStage.RefreshGateway);
                Thread.Sleep(5100);
                var start=new ProcessStartInfo(me.MainModule.FileName,"\""+root+"\" "+me.Id){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true};
                using(var reader=Process.Start(start)){
                    Expect(reader.WaitForExit(5000),"reader blocked by stalled worker");
                    string detail=reader.StandardOutput.ReadToEnd().Trim();
                    Expect(detail.StartsWith("stage=RefreshGateway stage_ms=")&&long.Parse(detail.Substring(detail.LastIndexOf('=')+1))>=5000,"wrong live stage: "+detail);
                }
                Expect(GatewayProgress.Describe(root,me.Id+1)=="stage=unavailable","stale PID accepted");
                progress.Enter(GatewayStage.PublishSnapshot);progress.Published();progress.Published();
                string[] lines=File.ReadAllLines(Path.Combine(root,GatewayProgress.Journal));
                var row=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(lines[0]);
                Expect(lines.Length==1 && (string)row["longest_stage"]=="RefreshGateway" && Convert.ToInt64(row["gap_ms"])>=5000 && Convert.ToInt64(row["longest_stage_ms"])>=5000,"missing or duplicate slow heartbeat record");
            }
        }finally{
            foreach(string file in Directory.GetFiles(root))File.Delete(file);
            Directory.Delete(root);
        }
        Console.WriteLine("PASS canonical firewall readback, zero writes, single-field repairs, external live stall attribution, stale PID and recovered gap journal.");
        return 0;
    }
}
