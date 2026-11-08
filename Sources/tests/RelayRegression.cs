using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using AdvancedAINetwork;

internal static class RelayRegression {
    static int FreePort(IPAddress address){
        var l=new TcpListener(address,0);l.Start();int p=((IPEndPoint)l.LocalEndpoint).Port;l.Stop();return p;
    }
    static byte[] Query(){
        var q=new List<byte>{1,2,1,0,0,1,0,0,0,0,0,0};
        foreach(string part in "api.ipify.org".Split('.')){q.Add((byte)part.Length);q.AddRange(Encoding.ASCII.GetBytes(part));}
        q.AddRange(new byte[]{0,0,1,0,1});return q.ToArray();
    }
    static TcpClient Connect(int port,string ip){
        var c=new TcpClient();c.ReceiveTimeout=3000;c.SendTimeout=3000;c.Connect("127.0.0.2",port);
        var wire=Encoding.ASCII.GetBytes("CONNECT "+ip+":443 HTTP/1.1\r\nHost: "+ip+":443\r\n\r\n");
        c.GetStream().Write(wire,0,wire.Length);return c;
    }
    static void Header(NetworkStream stream){
        int value;var text=new StringBuilder();
        while(text.Length<4096&&(value=stream.ReadByte())>=0){text.Append((char)value);if(text.ToString().EndsWith("\r\n\r\n"))return;}
        throw new IOException("Missing response header.");
    }
    static void Closed(TcpClient client){
        try{if(client.GetStream().ReadByte()!=-1)throw new Exception("Protected relay still passed data.");}
        catch(IOException e){var s=e.GetBaseException() as SocketException;if(s==null || (s.SocketErrorCode!=SocketError.ConnectionReset&&s.SocketErrorCode!=SocketError.ConnectionAborted))throw;}
    }
    public static int Main(){
        var folder=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"relay-fixture-"+Guid.NewGuid().ToString("N"));
        var upstream=new TcpListener(IPAddress.Loopback,0);upstream.Start();
        int port=FreePort(IPAddress.Parse("127.0.0.2"));
        try{using(var guard=new DomainGuard(folder,dns:0,proxy:((IPEndPoint)upstream.LocalEndpoint).Port,selectiveTun:true,gateway:port)){
            guard.Start();var query=Query();var response=guard.Answer(query);
            string ip=new IPAddress(response.Skip(response.Length-4).ToArray()).ToString();
            if(!GuardPolicy.Synthetic(ip))throw new Exception("Expected a protected DNS answer.");
            using(var denied=Connect(port,ip))Closed(denied);
            if(upstream.Pending())throw new Exception("Unverified relay reached upstream.");
            guard.SetForwardUntil(DateTime.UtcNow.AddSeconds(15));
            using(var allowed=Connect(port,ip)){
                var get=upstream.AcceptTcpClientAsync();if(!get.Wait(3000))throw new Exception("Verified relay did not connect.");
                using(var peer=get.Result){peer.ReceiveTimeout=3000;Header(peer.GetStream());
                    var ok=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\n");peer.GetStream().Write(ok,0,ok.Length);Header(allowed.GetStream());
                    guard.SetForwardUntil(DateTime.MinValue);Closed(allowed);
                }
            }
            using(var denied=Connect(port,ip))Closed(denied);
            if(upstream.Pending()||!guard.Answer(query).SequenceEqual(response))throw new Exception("Expired forwarding or protected DNS regression.");
        }}finally{upstream.Stop();}
        Console.WriteLine("PASS live loopback relay rejects before verification, permits after verification, closes established streams on revocation and preserves protected DNS.");return 0;
    }
}
