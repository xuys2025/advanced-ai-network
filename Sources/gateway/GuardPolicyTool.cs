using System;
using AdvancedAINetwork.Gateway;
static class GuardPolicyTool {
    static int Main(string[] args) {
        try{
            if(args.Length==2&&(args[0]=="audit" || args[0]=="prepare")){
                var policy=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<ManagedRules>(System.IO.File.ReadAllText(args[1]));
                policy.Prepare();
                if(args[0]=="prepare")using(var guard=new GatewayFailClosed()){guard.SetPolicy(policy);}
                Console.WriteLine(GatewayFailClosed.Audit(policy));return 0;
            }
            if(args.Length!=1 || args[0]!="remove-owned-guard")return 2;
            GatewayFailClosed.Uninstall();return 0;
        }
        catch(Exception error){Console.Error.WriteLine(error.Message);return 1;}
    }
}
