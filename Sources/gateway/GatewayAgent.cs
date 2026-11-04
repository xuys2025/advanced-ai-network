using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

public static class GatewayAgent {
    static readonly object sync=new object();
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
    static readonly string Root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AdvancedAINetworkLanGateway");
    static volatile bool running=true;
    static DateTime heartbeat=DateTime.UtcNow;
    static void Send(object value){lock(sync){Console.WriteLine(Json.Serialize(value));Console.Out.Flush();}}
    static object State(){try{using(var file=new FileStream(Path.Combine(Root,"status.json"),FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var reader=new StreamReader(file)){var state=Json.Deserialize<Dictionary<string,object>>(reader.ReadToEnd());DateTime at=DateTime.Parse(Convert.ToString(state["updated_utc"])).ToUniversalTime();if(Math.Abs((DateTime.UtcNow-at).TotalSeconds)>5){state["ready"]=false;state["capturing"]=false;state["guard_protected"]=false;state["ipv6_firewall_ready"]=false;state["stale"]=true;state["message"]="后台状态已过期，正在等待服务恢复。";}return state;}}catch(Exception error){return new{ready=false,stale=true,version="0.6.8-lan.1",message="后台尚未就绪："+error.Message};}}
    static object Command(string command){using(var pipe=new NamedPipeClientStream(".","AdvancedAINetworkLanGateway.Control",PipeDirection.InOut,PipeOptions.Asynchronous)){pipe.Connect(3000);byte[] value=Encoding.UTF8.GetBytes(command+"\n");pipe.Write(value,0,value.Length);var read=Task.Run(()=>{var bytes=new List<byte>();for(int i=0;i<131072;i++){int b=pipe.ReadByte();if(b<0)throw new EndOfStreamException();if(b==10)return Encoding.UTF8.GetString(bytes.ToArray());bytes.Add((byte)b);}throw new IOException("后台响应过长。");});if(!read.Wait(5000))throw new IOException("后台命令超时。");var result=Json.Deserialize<Dictionary<string,object>>(read.GetAwaiter().GetResult());object error;if(result.TryGetValue("error",out error))throw new IOException(Convert.ToString(error));return result;}}
    public static int Main(string[] args){Console.InputEncoding=new UTF8Encoding(false);Console.OutputEncoding=new UTF8Encoding(false);
        if(args.Length==2&&args[0]=="--command"){try{Send(Command(args[1]));return 0;}catch(Exception error){Console.Error.WriteLine(error.Message);return 1;}}
        int parent;if(args.Length!=1||!int.TryParse(args[0],out parent))return 2;
        Task.Run(()=>{try{string line;while(running&&(line=Console.ReadLine())!=null){string id="";try{if(line.Length>2048)continue;var request=Json.Deserialize<Dictionary<string,object>>(line);object v;id=request.TryGetValue("id",out v)?Convert.ToString(v):"";string method=Convert.ToString(request["method"]);if(method=="rules:refresh"||method=="rules:auto-on"||method=="rules:auto-off"){Send(new{id,ok=true,result=Command(method)});continue;}if(method=="heartbeat"){heartbeat=DateTime.UtcNow;continue;}object result;if(method=="shutdown"){running=false;result=new{stopping=true};}else if(method=="state")result=State();else if(method=="connect"||method=="check"||method=="disconnect")result=Command(method=="connect"?"enable":method=="disconnect"?"disable":"check");else if(method=="gateway:validate"||method=="gateway:apply"){var parameters=request["params"] as Dictionary<string,object>;string key=method=="gateway:validate"?"gateway":"token";if(parameters==null||!parameters.TryGetValue(key,out v)||!(v is string)||((string)v).Length>64)throw new IOException("无效的出口参数。");result=Command(Json.Serialize(new Dictionary<string,object>{{"command",method},{key,v}}));}else throw new IOException("不支持的操作。");Send(new{id=id,ok=true,result=result});}catch(Exception error){Send(new{id=id,ok=false,error=error.GetBaseException().Message});}}}finally{running=false;}});
        while(running){try{using(var process=Process.GetProcessById(parent))if(process.HasExited)break;}catch{break;}if((DateTime.UtcNow-heartbeat).TotalSeconds>15)break;Send(new{@event="state",state=State()});Thread.Sleep(1000);}return 0;
    }
}
