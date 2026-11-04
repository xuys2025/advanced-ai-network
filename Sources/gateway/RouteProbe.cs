using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;
public static class RouteProbe {
    static void Dns(GatewayTransport.RoutedUdp socket){var q=GatewayDns.Query("example.com");socket.Client.Client.ReceiveTimeout=3000;socket.Client.Send(q,q.Length);IPEndPoint remote=null;var a=socket.Client.Receive(ref remote);int ttl;GatewayDns.Parse(q,a,out ttl);}
    static object Trace(GatewayTransport transport){using(var route=transport.RetainActiveRoute())using(var socket=transport.OpenTcp(new GatewayDns(transport,route).Resolve("one.one.one.one"),443,route))return LinkProbe.HttpsTrace(socket.Client);}
    public static int Main(string[] args){var report=new Dictionary<string,object>{{"success",false},{"real_target_started",false}};try{
        using(var t=new GatewayTransport(args[0],args[1],args[2])){
            using(var before=t.RetainActiveRoute())using(var existing=t.OpenUdp(IPAddress.Parse("1.1.1.1"),53)){
                Dns(existing);report["before"]=Trace(t);
                using(var candidate=t.CreateRoute(args[2])){
                    using(var dns=t.OpenUdp(IPAddress.Parse("1.1.1.1"),53,candidate))Dns(dns);
                    t.ActivateRoute(candidate);
                }
                Dns(existing);report["old_socket_survived_switch"]=true;report["after"]=Trace(t);
                t.ActivateRoute(before);Dns(existing);report["rollback"]=Trace(t);
            }
            report["clash_control"]=TransportProbe.Clash(int.Parse(args[3]));report["transport"]=t.Status();if(t.LastError.Length!=0)throw new IOException(t.LastError);report["success"]=true;
        }
    }catch(Exception e){report["error"]=e.GetBaseException().ToString();}report["checked_utc"]=DateTime.UtcNow.ToString("o");File.WriteAllText(args[4],new JavaScriptSerializer().Serialize(report),new UTF8Encoding(false));return (bool)report["success"]?0:1;}
}
