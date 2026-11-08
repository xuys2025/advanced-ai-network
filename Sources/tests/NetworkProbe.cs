using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Web.Script.Serialization;

internal static class NetworkProbe {
    public static int Main(string[] args) {
        var json = new JavaScriptSerializer();
        try {
            if(args[0]=="tcp" || args[0]=="udp") {
                bool tcp = args[0]=="tcp";
                using(var socket=new Socket(AddressFamily.InterNetwork,tcp?SocketType.Stream:SocketType.Dgram,tcp?ProtocolType.Tcp:ProtocolType.Udp)) {
                    var op=socket.BeginConnect(IPAddress.Parse(args[1]),int.Parse(args[2]),null,null);
                    if(!op.AsyncWaitHandle.WaitOne(2000))throw new TimeoutException("connect timeout");
                    socket.EndConnect(op);
                    if(!tcp)socket.Send(args.Length>3?Convert.FromBase64String(args[3]):new byte[]{0});
                    Console.WriteLine(json.Serialize(new{ok=true}));return 0;
                }
            }
            var request=(HttpWebRequest)WebRequest.Create(args[1]);
            request.Proxy=args[0]=="direct"?null:new WebProxy(args[0],false);
            request.KeepAlive=false;request.AllowAutoRedirect=false;request.Timeout=12000;
            ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
            using(var response=(HttpWebResponse)request.GetResponse())
            using(var reader=new StreamReader(response.GetResponseStream())) {
                var body=reader.ReadToEnd();if(body.Length>4096)throw new IOException("Unexpected response.");
                Console.WriteLine(json.Serialize(new{ok=true,body=body}));return 0;
            }
        }catch(Exception ex) {
            var root=ex.GetBaseException();var socket=root as SocketException;
            Console.WriteLine(json.Serialize(new{ok=false,code=socket==null?0:socket.NativeErrorCode,message=root.Message}));return 2;
        }
    }
}
