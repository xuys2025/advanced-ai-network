using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

public static class InstalledProbe {
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
    static Dictionary<string,object> Command(string command){using(var pipe=new NamedPipeClientStream(".","AdvancedAINetworkLanGateway.Control",PipeDirection.InOut,PipeOptions.Asynchronous)){pipe.Connect(3000);byte[] data=Encoding.UTF8.GetBytes(command+"\n");pipe.Write(data,0,data.Length);using(var reader=new StreamReader(pipe)){var read=reader.ReadLineAsync();if(!read.Wait(5000))throw new IOException("Gateway control timed out.");return Json.Deserialize<Dictionary<string,object>>(read.Result);}}}
    static bool Flag(Dictionary<string,object> state,string key){object value;return state.TryGetValue(key,out value)&&value is bool&&(bool)value;}
    static Dictionary<string,object> Wait(bool ready){DateTime end=DateTime.UtcNow.AddSeconds(12);do{var state=Command("status");if(Flag(state,"ready")==ready)return state;Thread.Sleep(250);}while(DateTime.UtcNow<end);throw new IOException("Gateway state change timed out.");}
    static string Domain(int proxy){var request=(HttpWebRequest)WebRequest.Create("https://api.ipify.org/");request.Proxy=proxy==0?null:new WebProxy("http://127.0.0.1:"+proxy);request.Timeout=8000;request.ReadWriteTimeout=8000;request.KeepAlive=false;using(var response=request.GetResponse())using(var reader=new StreamReader(response.GetResponseStream())){string text=reader.ReadToEnd().Trim();IPAddress ip;if(!IPAddress.TryParse(text,out ip))throw new IOException("Protected domain returned no exit address.");return ip.ToString();}}
    public static int Main(string[] args){
        ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;int front=int.Parse(args[0]);bool paused=false;
        var report=new Dictionary<string,object>{{"success",false},{"real_target_started",false},{"started_utc",DateTime.UtcNow.ToString("o")}};
        try{
            var state=Command("status");if(!Flag(state,"ready"))throw new IOException("Gateway is not ready.");report["before"]=state;
            var dns=new Dictionary<string,object>();foreach(string domain in new[]{AiCompatibility.S_d318762d9a7b1e,AiCompatibility.S_c55d5f6562819e,"antspace.dev","clau.de",AiCompatibility.S_743e483ae01f1f,AiCompatibility.S_3c3a75765581d1,AiCompatibility.S_ba35b59b5869e8,AiCompatibility.S_b55da41d0fb07a,AiCompatibility.S_c3b2d321f93f6b,AiCompatibility.S_cceb19833d60dc,AiCompatibility.S_9bf2a517ed3cdf,AiCompatibility.S_4d8d78a2b2b457,AiCompatibility.S_a1101ea07e3e93,AiCompatibility.S_62e4eb09895085,"modelcontextprotocol.com","modelcontextprotocol.io","modelcontextprotocol.net","modelcontextprotocol.org","ant.dev",AiCompatibility.S_e8d2487918725c,AiCompatibility.S_377781691d8cda,AiCompatibility.S_ea80aaae921557,AiCompatibility.S_2d7a1683632e95,"intercom.io","intercomcdn.com","interface.feedback","lcicat.org","lcicollections.org","mcpservertest.online","muthos.com","sentry.io","sillylittleguy.org","statsigapi.net","api.ipify.org","icanhazip.com","ifconfig.me","ip.net.coffee",AiCompatibility.S_783a5375a32dd3,AiCompatibility.S_7361a0b35b1d80,AiCompatibility.S_1e461caa6d3581,"browser-intake-us5-datadoghq.com","cdn.growthbook.io","cdn.usefathom.com",AiCompatibility.S_10aec8d3389d2c,"storage.googleapis.com"}){var answers=Dns.GetHostAddresses(domain);bool synthetic=false;foreach(var ip in answers){byte[] b=ip.GetAddressBytes();if(b.Length==4&&b[0]==198&&b[1]==19&&b[2]>=64&&b[2]<128)synthetic=true;}if(!synthetic)throw new IOException("Protected DNS mapping was not returned for "+domain);dns[domain]=true;}report["domain_dns"]=dns;
            report["domain_direct_exit"]=Domain(0);report["domain_clash_exit"]=Domain(front);report["unrelated_clash_before"]=TransportProbe.Clash(front);
            Command("disable");paused=true;report["paused"]=Wait(false);
            bool blocked=false;try{Domain(0);}catch(WebException){blocked=true;}if(!blocked)throw new IOException("Protected direct access succeeded while gateway was paused.");report["domain_direct_blocked_while_paused"]=true;
            blocked=false;try{Domain(front);}catch(WebException){blocked=true;}if(!blocked)throw new IOException("Protected Clash access succeeded while gateway was paused.");report["domain_clash_blocked_while_paused"]=true;
            report["unrelated_clash_while_paused"]=TransportProbe.Clash(front);
            Command("enable");paused=false;Wait(true);report["domain_resumed_exit"]=Domain(0);report["after"]=Command("status");report["success"]=true;
        }catch(Exception error){report["error"]=error.GetBaseException().ToString();}
        finally{if(paused){try{Command("enable");report["restored_ready"]=Flag(Wait(true),"ready");}catch(Exception error){report["restore_error"]=error.Message;}}report["finished_utc"]=DateTime.UtcNow.ToString("o");File.WriteAllText(args[1],Json.Serialize(report),new UTF8Encoding(false));}
        return (bool)report["success"]?0:1;
    }
}
