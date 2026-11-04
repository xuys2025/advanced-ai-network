using System;
using System.IO;
using System.Net;
using AdvancedAINetwork.Gateway;
public static class GatewayValidationTests {
    public static int Main(){
        int checks=0;
        foreach(string text in new[]{"192.168.50.254","10.42.0.1","172.16.2.1"}){if(GatewayLink.ParseGateway(text).ToString()!=text)throw new Exception(text);checks++;}
        foreach(string text in new[]{"","192.168.10","192.168.010.1","0xC0A80AE1","3232238305","256.1.1.1","192.168.50.254:80","127.0.0.1","0.0.0.1","224.0.0.1","255.255.255.255","169.254.1.1","::1"}){bool rejected=false;try{GatewayLink.ParseGateway(text);}catch(IOException){rejected=true;}if(!rejected)throw new Exception("Accepted invalid gateway: "+text);checks++;}
        var local=IPAddress.Parse("192.168.50.77");var mask=IPAddress.Parse("255.255.255.0");
        foreach(string text in new[]{"192.168.50.0","192.168.50.255","192.168.50.77","192.168.51.254"}){if(GatewayLink.SameSubnet(local,IPAddress.Parse(text),mask))throw new Exception(text);checks++;}
        if(!GatewayLink.SameSubnet(local,IPAddress.Parse("192.168.50.254"),mask))throw new Exception("Rejected valid gateway");checks++;
        if(!GatewayLink.SameSubnet(IPAddress.Parse("10.42.3.5"),IPAddress.Parse("10.42.2.1"),IPAddress.Parse("255.255.254.0")))throw new Exception("Non-/24 subnet rejected");checks++;
        Console.WriteLine("PASS "+checks+" gateway address and subnet cases");return 0;
    }
}
