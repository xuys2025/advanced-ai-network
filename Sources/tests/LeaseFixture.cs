using System;
using System.Diagnostics;
using AdvancedAINetwork.Gateway;

internal static class LeaseFixture {
    public static int Main(string[] args) {
        try {
            if(args.Length==1 && args[0]=="remove-fixture"){GatewayFailClosed.Uninstall();return 0;}
            if(args.Length!=0)return 2;
            var policy=new ManagedRules{processes=new[]{"ai-outage-fixture.exe"},ipv4=new[]{"192.0.2.17/32"},announced=new string[0],sha256="fixture"};
            policy.Prepare();
            using(var gate=new GatewayFailClosed()){
                gate.SetPolicy(policy);
                if(GatewayFailClosed.Audit(policy)!=3)throw new Exception("Expected two application blocks and one IPv4 block.");
                gate.SetLive(true,policy);
                Console.WriteLine("ready");Console.Out.Flush();
                if(Console.ReadLine()=="crash")Process.GetCurrentProcess().Kill();
            }
            return 0;
        }catch(Exception error){Console.Error.WriteLine(error);return 1;}
    }
}
