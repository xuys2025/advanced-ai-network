using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;
using AdvancedAINetwork.Gateway;

public sealed partial class GatewayService {
    volatile object operation=new {phase="idle"};
    volatile bool operationBusy,applyRequested;
    Task operationTask;
    GatewayTransport.Route candidate;
    string candidateGateway="",candidateToken="",lastLocation="",lastColo="";
    DateTime candidateExpiry;
    Dictionary<string,object> candidateExit;
    static string ReadCommand(NamedPipeServerStream pipe){
        var read=Task.Run(()=>{var bytes=new List<byte>();for(int i=0;i<2048;i++){int b=pipe.ReadByte();if(b<0)throw new EndOfStreamException();if(b==10)return Encoding.UTF8.GetString(bytes.ToArray()).Trim();bytes.Add((byte)b);}throw new IOException("命令过长。");});
        if(!read.Wait(3000))throw new IOException("命令读取超时。");return read.GetAwaiter().GetResult();
    }
    void HandleCommand(string input){
        string command=input;var args=new Dictionary<string,object>();
        if(input.StartsWith("{",StringComparison.Ordinal)){args=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string,object>>(input);command=Str(args,"command");}
        if(command=="status")return;
        if(command=="rules:refresh"||command=="rules:auto-on"||command=="rules:auto-off"){rules.Command(command);return;}
        if(command=="gateway:validate"){BeginValidation(Str(args,"gateway"),false);return;}
        if(command=="gateway:apply"){
            lock(sync){
                if(operationBusy)throw new IOException("正在处理上一次操作，请稍候。");
                if(candidate==null||candidateToken!=Str(args,"token")||candidateExpiry<=DateTime.UtcNow)throw new IOException("验证结果已过期，请重新验证网关。");
                if(!guardReady)throw new IOException("请等待域名保护恢复后再切换。");
                operationBusy=true;applyRequested=true;operation=new{phase="applying",gateway=candidateGateway};
            }return;
        }
        lock(sync){
            if(operationBusy)throw new IOException("正在验证或切换出口，请稍候。");
            if(command=="check"){requestCheck=true;return;}
            if(command!="enable"&&command!="disable")throw new IOException("不支持的网关操作。");
            bool next=command=="enable";if(!next)networkGuard.Pause();Atomic(Path.Combine(Root,"intent.json"),new{enabled=next});enabled=next;if(next)requestCheck=true;
        }
    }
    Dictionary<string,object> ProbeRoute(GatewayTransport.Route route){
        using(var socket=transport.OpenTcp(new GatewayDns(transport,route).Resolve("one.one.one.one"),443,route))
            return (Dictionary<string,object>)LinkProbe.HttpsTrace(socket.Client);
    }
    void SetExit(Dictionary<string,object> result){lastExit=Str(result,"ip");lastLocation=Str(result,"loc");lastColo=Str(result,"colo");lastCheck=DateTime.UtcNow.ToString("o");}
    void ClearCandidate(){if(candidate!=null)candidate.Dispose();candidate=null;candidateToken="";candidateExit=null;}
    void ExpireCandidate(){lock(sync){if(!operationBusy&&candidate!=null&&DateTime.UtcNow>=candidateExpiry){ClearCandidate();operation=new{phase="expired",message="验证已过期，请重新验证。"};}}}
    void BeginValidation(string target,bool checkOnly){
        target=GatewayLink.ParseGateway(target).ToString();
        if(GatewayLink.ResolveSource(adapter,target)!=local)throw new IOException("新网关必须与当前连接使用同一个本机 IPv4 地址。");
        lock(sync){
            if(operationBusy)throw new IOException("正在处理上一次操作，请稍候。");
            ClearCandidate();operationBusy=true;operation=new{phase="validating",gateway=target};
            operationTask=Task.Run(()=>{
                GatewayTransport.Route route=null;
                try{
                    route=checkOnly?transport.RetainActiveRoute():transport.CreateRoute(target);
                    var result=ProbeRoute(route);
                    lock(sync){
                        if(stopping.WaitOne(0))return;
                        if(checkOnly){SetExit(result);operation=new{phase="checked",gateway=target,exit=result,checked_utc=lastCheck};}
                        else{candidate=route;route=null;candidateGateway=target;candidateExit=result;candidateToken=Guid.NewGuid().ToString("N");candidateExpiry=DateTime.UtcNow.AddMinutes(5);operation=new{phase="validated",gateway=target,exit=result,token=candidateToken,expires_utc=candidateExpiry.ToString("o")};}
                    }
                }catch(Exception error){operation=new{phase="failed",gateway=target,message="网关验证失败："+error.GetBaseException().Message};}
                finally{if(route!=null)route.Dispose();operationBusy=false;}
            });
        }
    }
    void ApplyCandidate(){
        lock(sync){
            applyRequested=false;
            using(var previous=transport.RetainActiveRoute()){
                string oldGateway=gateway;bool changed=false;
                try{
                    if(candidate==null||candidateExpiry<=DateTime.UtcNow)throw new IOException("验证已过期。");
                    candidate.Link.Refresh();
                    var config=ReadJson(Path.Combine(Root,"config.json"));config["gateway"]=candidateGateway;
                    if(gateway!=candidateGateway){CloseProxies();transport.ActivateRoute(candidate);changed=true;if(enabled&&guardReady)OpenProxies();}
                    Atomic(Path.Combine(Root,"config.json"),config);
                    gateway=candidateGateway;SetExit(candidateExit);ready=enabled&&guardReady;
                    operation=new{phase="applied",gateway=gateway,exit=candidateExit,checked_utc=lastCheck};
                }catch(Exception error){
                    if(changed){CloseProxies();transport.ActivateRoute(previous);if(enabled&&guardReady)OpenProxies();}
                    gateway=oldGateway;ready=enabled&&guardReady;operation=new{phase="failed",message="切换未完成，已保留原出口："+error.GetBaseException().Message};
                }finally{ClearCandidate();operationBusy=false;}
            }
        }
    }
}
