using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;

// Instantiates only the identity selector. No native capture, socket, service,
// firewall, or application start/stop API is called by this probe.
public static class EmbeddedIdentityProbe {
    public static int Main(string[] args) {
        try {
            var json=new JavaScriptSerializer();
            var config=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(args[0]));
            string profile=ProcessIdentity.ProfileForOwner((string)config["owner_sid"]);
            var identity=new ProcessIdentity((string)config["desktop_image"],(string)config["code_image"],profile);
            var oldAssembly=Assembly.LoadFrom(Path.Combine(Path.GetDirectoryName(args[0]),"GatewayService.exe"));
            var oldType=oldAssembly.GetType("AdvancedAINetwork.Gateway.ProcessIdentity",true);
            object old=Activator.CreateInstance(oldType,new[]{config["desktop_image"],config["code_image"]});
            var processes=new List<object>();int embedded=0;
            foreach(var process in Process.GetProcessesByName(AiCompatibility.S_c857d09db23e68))using(process) {
                string path;try{path=process.MainModule.FileName;}catch{continue;}
                uint pid=(uint)process.Id;int before=(int)oldType.GetMethod("Select").Invoke(old,new object[]{pid});int after=identity.Select(pid);
                if(path.IndexOf(AiCompatibility.S_4e4e3199477643,StringComparison.OrdinalIgnoreCase)>=0) {embedded++;if(after!=1)throw new IOException("Embedded CC not verified: "+pid);}
                processes.Add(new{pid=pid,path=path,before=before,after=after});
            }
            if(identity.Select((uint)Process.GetCurrentProcess().Id)!=0)throw new IOException("Unrelated probe was selected.");
            var report=new{success=true,read_only=true,real_target_started=false,network_capture_started=false,live_routing_tested=false,embedded_processes=embedded,identities=identity.Status(),firewall_paths_prepared=identity.Paths,processes=processes,checked_utc=DateTime.UtcNow.ToString("o")};
            string text=json.Serialize(report);File.WriteAllText(args[1],text,new UTF8Encoding(false));Console.WriteLine(text);return 0;
        }catch(Exception error){Console.Error.WriteLine(error.GetBaseException().ToString());return 1;}
    }
}
