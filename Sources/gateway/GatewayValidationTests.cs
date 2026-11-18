using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using AdvancedAINetwork.Gateway;
public static class GatewayValidationTests {
    static void CheckDownloadTunnel(){
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        int port=((IPEndPoint)listener.LocalEndpoint).Port;
        try {
            var mock=Task.Run(()=>{
                using(var socket=listener.AcceptTcpClient()){
                    socket.ReceiveTimeout=3000;
                    var stream=socket.GetStream();
                    using(var reader=new StreamReader(stream,Encoding.ASCII,false,1024,true)){
                        string authority=ManagedRules.DownloadDomain+":443";
                        if(reader.ReadLine()!="CONNECT "+authority+" HTTP/1.1" || reader.ReadLine()!="Host: "+authority || reader.ReadLine()!="")
                            throw new Exception("Clash did not receive the original download hostname");
                    }
                    byte[] reply=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\nX");
                    stream.Write(reply,0,reply.Length);
                }
            });
            using(var tunnel=GatewayProxy.OpenDownload(17893,port,443).GetAwaiter().GetResult()){
                if(tunnel.GetStream().ReadByte()!='X')throw new Exception("Missing Clash tunnel payload");
            }
            mock.GetAwaiter().GetResult();
            try{GatewayProxy.OpenDownload(17891,port,443).GetAwaiter().GetResult();throw new Exception("Clash loop accepted");}
            catch(IOException){}
        }finally{listener.Stop();}
    }
    public static int Main(){
        CheckDownloadTunnel();
        int checks=0;
        foreach(string address in new[]{"100.64.0.1","100.127.255.254"}){if(TailscaleLink.ParseNode(address)!=address)throw new Exception(address);checks++;}
        foreach(string address in new[]{"100.63.255.255","100.128.0.0","100.064.0.1","127.0.0.1","100.80.1.2:80","::1",""}){try{TailscaleLink.ParseNode(address);throw new Exception(address);}catch(IOException){checks++;}}
        var syn=new byte[44];syn[0]=0x45;syn[9]=6;syn[32]=0x60;syn[33]=2;syn[40]=2;syn[41]=4;syn[42]=5;syn[43]=180;
        TailscaleLink.ClampMss(syn,syn.Length);if(syn[42]!=4||syn[43]!=216)throw new Exception("Tailscale TCP MSS");checks++;
        foreach(string text in new[]{"192.168.50.254","10.42.0.1","172.16.2.1"}){if(GatewayLink.ParseGateway(text).ToString()!=text)throw new Exception(text);checks++;}
        foreach(string text in new[]{"","192.168.10","192.168.010.1","0xC0A80AE1","3232238305","256.1.1.1","192.168.50.254:80","127.0.0.1","0.0.0.1","224.0.0.1","255.255.255.255","169.254.1.1","::1"}){bool rejected=false;try{GatewayLink.ParseGateway(text);}catch(IOException){rejected=true;}if(!rejected)throw new Exception("Accepted invalid gateway: "+text);checks++;}
        var local=IPAddress.Parse("192.168.50.77");var mask=IPAddress.Parse("255.255.255.0");
        foreach(string text in new[]{"192.168.50.0","192.168.50.255","192.168.50.77","192.168.51.254"}){if(GatewayLink.SameSubnet(local,IPAddress.Parse(text),mask))throw new Exception(text);checks++;}
        if(!GatewayLink.SameSubnet(local,IPAddress.Parse("192.168.50.254"),mask))throw new Exception("Rejected valid gateway");checks++;
        if(!GatewayLink.SameSubnet(IPAddress.Parse("10.42.3.5"),IPAddress.Parse("10.42.2.1"),IPAddress.Parse("255.255.254.0")))throw new Exception("Non-/24 subnet rejected");checks++;
        Console.WriteLine("PASS "+checks+" gateway address and subnet cases");return 0;
    }
}
