using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Web.Script.Serialization;
using AdvancedAINetwork;
using AdvancedAINetwork.Gateway;
public static class SetupInspect {
    public static int Main(string[] args){try{object result;
        if(args.Length==1&&args[0]=="--discover")result=new{desktop=CcIdentity.DesktopPath(),code=CcIdentity.DefaultPath(),adapters=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up&&n.NetworkInterfaceType==NetworkInterfaceType.Ethernet).Select(n=>new{id=n.Id,name=n.Name,addresses=n.GetIPProperties().UnicastAddresses.Where(i=>i.Address.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork).Select(i=>i.Address.ToString()).ToArray()}).ToArray()};
        else if(args.Length==4){string local=GatewayLink.ResolveSource(args[1],args[0]);result=new{gateway=GatewayLink.ParseGateway(args[0]).ToString(),adapter=args[1],local_ip=local,identities=new ProcessIdentity(args[2],args[3]).Status()};}
        else throw new Exception("Usage: SetupInspect --discover | gateway adapter desktop code");
        Console.OutputEncoding=new System.Text.UTF8Encoding(false);Console.WriteLine(new JavaScriptSerializer().Serialize(result));return 0;
    }catch(Exception e){Console.Error.WriteLine(e.GetBaseException().Message);return 1;}}
}
