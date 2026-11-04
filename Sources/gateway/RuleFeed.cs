using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace AdvancedAINetwork.Gateway {
    internal sealed class RuleFeed : IDisposable {
        readonly string root;readonly GatewayTransport transport;readonly int front;
        readonly object sync=new object();readonly TcpListener listener;
        volatile ManagedRules active;volatile bool closed;
        bool busy,requested,automatic=true;string message="",lastCheck="",lastSuccess="",lastChange="";
        DateTime next;HttpWebRequest pending;
        const int Hours=6;
        internal ManagedRules Active {get{return active;}}
        internal const int Port=17894;
        static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
        static void Write(string file,string content){
            string temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";
            try{File.WriteAllText(temp,content,Utf8);if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);}
            finally{if(File.Exists(temp))File.Delete(temp);}
        }
        string FileAt(string name){return Path.Combine(root,name);}
        internal RuleFeed(string root,GatewayTransport transport,int front){
            this.root=root;this.transport=transport;this.front=front;
            string master=FileAt("managed-rules.json");
            if(!File.Exists(master))Write(master,Encoding.UTF8.GetString(Convert.FromBase64String("eyJyb290cyI6WyJhbnQuZGV2IiwiYW50aHJvcGljLmNvbSIsImFudGhyb3BpYy5jb20uY24iLCJhbnRocm9waWMudGVhbSIsImFudHNwYWNlLmRldiIsImNoYXRib3RjbGF1ZGUuY29tIiwiY2xhdS5kZSIsImNsYXVkZS5haSIsImNsYXVkZS5hcHAiLCJjbGF1ZGUuY29tIiwiY2xhdWRlLmRldiIsImNsYXVkZS5uZXciLCJjbGF1ZGUuc2l0ZSIsImNsYXVkZWFjYWRlbXkuY29tIiwiY2xhdWRlbWNwY2xpZW50LmNvbSIsImNsYXVkZW1jcGNvbnRlbnQuY29tIiwiY2xhdWRlcGFnZXMuZGV2IiwiY2xhdWRlc3R1ZGlvLmNvbSIsImNsYXVkZXVzZXJjb250ZW50LmNvbSIsImludGVyY29tLmlvIiwiaW50ZXJjb21jZG4uY29tIiwiaW50ZXJmYWNlLmZlZWRiYWNrIiwibGNpY2F0Lm9yZyIsImxjaWNvbGxlY3Rpb25zLm9yZyIsIm1jcHNlcnZlcnRlc3Qub25saW5lIiwibW9kZWxjb250ZXh0cHJvdG9jb2wuY29tIiwibW9kZWxjb250ZXh0cHJvdG9jb2wuaW8iLCJtb2RlbGNvbnRleHRwcm90b2NvbC5uZXQiLCJtb2RlbGNvbnRleHRwcm90b2NvbC5vcmciLCJtdXRob3MuY29tIiwic2VudHJ5LmlvIiwic2lsbHlsaXR0bGVndXkub3JnIiwic3RhdHNpZ2FwaS5uZXQiXSwiZXhhY3QiOlsiYW50aHJvcGljLWNvbS5naG9zdC5pbyIsImFudGhyb3BpYy5hdXRoMC5jb20iLCJhbnRocm9waWMuY29tLmNkbi5jbG91ZGZsYXJlLm5ldCIsImFwaS5pcGlmeS5vcmciLCJicm93c2VyLWludGFrZS11czUtZGF0YWRvZ2hxLmNvbSIsImNkbi5ncm93dGhib29rLmlvIiwiY2RuLnVzZWZhdGhvbS5jb20iLCJpY2FuaGF6aXAuY29tIiwiaWZjb25maWcubWUiLCJpcC5uZXQuY29mZmVlIiwic2VydmQtYW50aHJvcGljLXdlYnNpdGUuYi1jZG4ubmV0Iiwic3RvcmFnZS5nb29nbGVhcGlzLmNvbSJdLCJrZXl3b3JkcyI6WyJkYXRhZG9nIiwic2VudHJ5Iiwic2lmdCJdLCJwcm9jZXNzZXMiOlsiQ2xhdWRlIiwiQ2xhdWRlLmV4ZSIsImNsYXVkZSIsImNsYXVkZS5leGUiLCJjb3dvcmstc3ZjLmV4ZSJdLCJpcHY0IjpbIjE2MC43OS4xMDQuMC8yMSJdLCJhbm5vdW5jZWQiOlsiMTYwLjc5LjEwNC4wLzIzIl0sImFzbnMiOlszOTkzNThdLCJzaGEyNTYiOiIxNzhmZDc3NGU2NWUyMjNjNmE5YTJkMjgyMDk0YzViNzkyMmNiY2MyZjVlNjcwZmIyN2Y2MmRiOGFjOGM0NTYwIiwicmV2aXNpb24iOiIyY2UzNTA1MWQ5ZDA2ODk2OGQwMTU1ODA4MWRjMzg3NDFiMTkyZWFkNTQ3OGM3MmUzYTNiODAxNTRmZmI5NjU3In0=")));
            active=new JavaScriptSerializer().Deserialize<ManagedRules>(File.ReadAllText(master));active.Prepare();
            string dns=FileAt("managed-domains.json");if(!File.Exists(dns)||File.ReadAllText(dns)!=active.DnsSource())Write(dns,active.DnsSource());
            string prefs=FileAt("rule-auto.txt");automatic=!File.Exists(prefs)||File.ReadAllText(prefs).Trim()!="off";
            string history=FileAt("rule-history.json");
            if(File.Exists(history))try{var h=new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(File.ReadAllText(history));lastSuccess=h["last_success"];lastCheck=h["last_check"];lastChange=h["last_change"];}catch(IOException){}catch(ArgumentException){}catch(KeyNotFoundException){}
            DateTime t;next=DateTime.TryParse(lastSuccess,out t)?t.ToUniversalTime().AddHours(Hours):DateTime.MinValue;
            listener=new TcpListener(IPAddress.Loopback,Port);listener.Server.ExclusiveAddressUse=true;listener.Start(8);
            Task.Factory.StartNew(Serve,TaskCreationOptions.LongRunning);
        }
        internal void Command(string cmd){
            lock(sync){
                if(cmd=="rules:refresh"){if(!busy)requested=true;return;}
                bool on=cmd=="rules:auto-on";Write(FileAt("rule-auto.txt"),on?"on":"off");automatic=on;
            }
        }
        internal object Status(){lock(sync){return new{source=ManagedRules.Url,automatic,busy,requested,interval_hours=Hours,last_check=lastCheck,last_success=lastSuccess,last_change=lastChange,
            next_check=next==DateTime.MinValue?"":next.ToString("o"),message,policy=active};}}
        internal void Tick(bool ready){
            lock(sync){
                if(closed||busy||!ready||(!requested&&(!automatic||DateTime.UtcNow<next)))return;
                busy=true;requested=false;lastCheck=DateTime.UtcNow.ToString("o");message="正在通过专用网关检查规则";Task.Run((Action)Update);
            }
        }
        string Fetch(string url,int port,int cap){
            var request=(HttpWebRequest)WebRequest.Create(url);
            request.Proxy=new WebProxy("http://127.0.0.1:"+port,false);
            request.AllowAutoRedirect=false;request.UseDefaultCredentials=false;request.KeepAlive=false;
            request.Timeout=15000;request.ReadWriteTimeout=10000;request.UserAgent="AdvancedAINetwork-rule-update/1";
            lock(sync){if(closed)throw new OperationCanceledException();pending=request;}
            try{using(var response=(HttpWebResponse)request.GetResponse()){
                if(response.StatusCode!=HttpStatusCode.OK||response.ContentLength>cap)throw new IOException("Unexpected HTTPS response");
                using(var input=response.GetResponseStream())using(var output=new MemoryStream()){
                    var buf=new byte[8192];int n;while((n=input.Read(buf,0,buf.Length))!=0){if(output.Length+n>cap)throw new IOException("Rule source exceeded size limit");output.Write(buf,0,n);}if(response.ContentLength>=0&&output.Length!=response.ContentLength)throw new IOException("Truncated rule download");return Utf8.GetString(output.ToArray());}
            }}finally{lock(sync){pending=null;}}
        }
        void Update(){
            try{
                // The downloader owns this private, ephemeral proxy for the entire TLS request.
                // Its resolver and upstream sockets are opened by the active gateway transport.
                ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
                ManagedRules candidate;
                using(var dedicated=new GatewayProxy(transport,0,front)){
                    candidate=ManagedRules.Parse(Fetch(ManagedRules.Url,dedicated.Port,256*1024));
                    var prefixes=new List<string>();
                    foreach(uint asn in candidate.asns)prefixes.AddRange(ManagedRules.ActiveV4(asn,Fetch("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"+asn+"&min_peers_seeing=1",dedicated.Port,1024*1024)));
                    candidate.announced=prefixes.Distinct().OrderBy(x=>x,StringComparer.Ordinal).ToArray();candidate.Prepare();
                }
                lock(sync){
                    if(closed) return;
                    bool changed=candidate.revision!=active.revision;
                    if(changed){
                        var old=active;var json=new JavaScriptSerializer();
                        Write(FileAt("managed-rules.previous.json"),json.Serialize(old));
                        Write(FileAt("managed-domains.json"),candidate.DnsSource());
                        try{Write(FileAt("managed-rules.json"),json.Serialize(candidate));}
                        catch{Write(FileAt("managed-domains.json"),old.DnsSource());throw;}
                        active=candidate;lastChange=DateTime.UtcNow.ToString("o");
                    }
                    lastSuccess=DateTime.UtcNow.ToString("o");next=DateTime.UtcNow.AddHours(Hours);message=changed?"新规则已载入":"已核对，当前为最新规则";
                    Write(FileAt("rule-history.json"),new JavaScriptSerializer().Serialize(new{last_success=lastSuccess,last_check=lastCheck,last_change=lastChange}));
                }
            }catch(Exception ex){lock(sync){message="更新失败，继续使用现有规则："+ex.GetBaseException().Message;next=DateTime.UtcNow.AddMinutes(15);}}
            finally{lock(sync){busy=false;}}
        }
        void Serve(){
            while(!closed)try{using(var client=listener.AcceptTcpClient()){
                client.ReceiveTimeout=client.SendTimeout=2000;var stream=client.GetStream();var bytes=new List<byte>();int b;
                while(bytes.Count<4096&&(b=stream.ReadByte())>=0){bytes.Add((byte)b);int n=bytes.Count;if(n>=4&&bytes[n-4]==13&&bytes[n-3]==10&&bytes[n-2]==13&&bytes[n-1]==10)break;}
                string first=Encoding.ASCII.GetString(bytes.ToArray()).Split('\r')[0];
                bool domains=first=="GET /domains.yaml HTTP/1.1"||first=="GET /domains.yaml HTTP/1.0";
                bool routing=first=="GET /routing.yaml HTTP/1.1"||first=="GET /routing.yaml HTTP/1.0";
                var data=Utf8.GetBytes(domains||routing?active.Provider(domains):"");
                var header=Encoding.ASCII.GetBytes("HTTP/1.1 "+(domains||routing?"200 OK":"404 Not Found")+"\r\nContent-Type: text/yaml\r\nCache-Control: no-cache\r\nContent-Length: "+data.Length+"\r\nConnection: close\r\n\r\n");
                stream.Write(header,0,header.Length);stream.Write(data,0,data.Length);
            }}catch(SocketException){if(closed)return;}catch(IOException){}catch(ObjectDisposedException){return;}
        }
        public void Dispose(){lock(sync){closed=true;if(pending!=null)pending.Abort();}listener.Stop();}
    }
}
