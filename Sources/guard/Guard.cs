using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AdvancedAINetwork {
public sealed class DomainGuard : IDisposable {
    readonly string state;readonly int dnsPort,proxyPort,gatewayPort;readonly int[] relayPorts;readonly bool tunMode;
    readonly object sync=new object();readonly Dictionary<string,string> mapping=new Dictionary<string,string>();
    readonly Dictionary<string,string> tunMapping=new Dictionary<string,string>(),reverse=new Dictionary<string,string>();long answers,blocked64,blocked65;
    readonly List<TcpListener> listeners=new List<TcpListener>();readonly HashSet<TcpClient> clients=new HashSet<TcpClient>();
    readonly HashSet<TcpClient> relays=new HashSet<TcpClient>();
    DateTime forwardUntilUtc=DateTime.MinValue;
    internal void SetForwardUntil(DateTime validUntilUtc) {
        lock(sync){
            forwardUntilUtc=validUntilUtc;
            if(tunMode && DateTime.UtcNow>=validUntilUtc)
                foreach(var relay in relays)relay.Close();
        }
    }
    UdpClient udp;volatile bool stopped;int inflight;
    public DomainGuard(string directory,int dns=53,int proxy=17891,int[] ports=null,bool selectiveTun=false,int gateway=GuardPolicy.GatewayPort){state=directory;dnsPort=dns;proxyPort=proxy;relayPorts=ports??new[]{80,443};tunMode=selectiveTun;gatewayPort=gateway;}
    public void Start() {
        Directory.CreateDirectory(state);
        string path=Path.Combine(state,"domain-mappings.json");
        if(File.Exists(path))foreach(var pair in Data.Parse(File.ReadAllText(path))) {string ip=Convert.ToString(pair.Value);IPAddress parsed;if(ValidName(pair.Key)&&IPAddress.TryParse(ip,out parsed)&&ip.StartsWith("127.66.")&&!mapping.Values.Contains(ip))mapping[pair.Key]=ip;else throw new Exception("本机域名映射损坏，请通过安装程序修复，不能自动清空历史映射。");}
        string tunPath=Path.Combine(state,"domain-tun-mappings.json");
        if(File.Exists(tunPath))foreach(var pair in Data.Parse(File.ReadAllText(tunPath))){string ip=Convert.ToString(pair.Value);if(!ValidName(pair.Key)||!GuardPolicy.Synthetic(ip)||reverse.ContainsKey(ip))throw new Exception("TUN 域名映射损坏，保持拒绝；不会自动重置已缓存地址。");tunMapping[pair.Key]=ip;reverse[ip]=pair.Key;}
        try{
            foreach(var pair in mapping)ListenDomain(pair.Key,pair.Value);
            if(tunMode){var gateway=new TcpListener(IPAddress.Parse("127.0.0.2"),gatewayPort);gateway.Server.ExclusiveAddressUse=true;gateway.Start(64);listeners.Add(gateway);Task.Run(()=>Accept(gateway,HandleGateway));}
            udp=new UdpClient(new IPEndPoint(IPAddress.Parse("127.0.0.2"),dnsPort));
            var dns=new TcpListener(IPAddress.Parse("127.0.0.2"),dnsPort);dns.Server.ExclusiveAddressUse=true;dns.Start(32);listeners.Add(dns);
            Task.Run((Action)ReceiveUdp);Task.Run(()=>Accept(dns,HandleDns));
        }catch{Dispose();throw;}
    }
    static bool ValidName(string name){return name.Length>0&&name.Length<=253&&name.Split('.').All(x=>x.Length>0&&x.Length<=63&&x.All(c=>c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-'||c=='_'));}
    string GetMapping(string domain) {
        if(tunMode)return GetTunMapping(domain);
        lock(sync){string ip;if(mapping.TryGetValue(domain,out ip))return ip;if(mapping.Count>=2048)throw new Exception("映射上限，保持拒绝。");
            int index=1;do{ip="127.66."+(index/256)+"."+(index%256);index++;}while(mapping.Values.Contains(ip));
            string path=Path.Combine(state,"domain-mappings.json"),temp=path+".tmp";
            var next=new Dictionary<string,string>(mapping);next[domain]=ip;
            File.WriteAllText(temp,Data.Json(next),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
            mapping[domain]=ip;ListenDomain(domain,ip);
            return ip;
        }
    }
    string GetTunMapping(string domain){lock(sync){string ip;if(tunMapping.TryGetValue(domain,out ip))return ip;if(tunMapping.Count>=8192)throw new Exception("TUN 映射容量已满，保持拒绝。");int index=1;do{ip=GuardPolicy.Address(index++);}while(reverse.ContainsKey(ip));var next=new Dictionary<string,string>(tunMapping);next[domain]=ip;string path=Path.Combine(state,"domain-tun-mappings.json"),temp=path+".tmp";File.WriteAllText(temp,Data.Json(next),new UTF8Encoding(false));if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);tunMapping[domain]=ip;reverse[ip]=domain;return ip;}}
    public object Statistics(){lock(sync)return Data.Obj("a_answers",Interlocked.Read(ref answers),"qtype64_blocked",Interlocked.Read(ref blocked64),"qtype65_blocked",Interlocked.Read(ref blocked65),"tun_mapped_domains",tunMapping.Count,"legacy_mapped_domains",mapping.Count,"selective_tun",tunMode);}
    void ListenDomain(string domain,string ip) {
        var added=new List<TcpListener>();
        try{foreach(int port in relayPorts){var listener=new TcpListener(IPAddress.Parse(ip),port);listener.Server.ExclusiveAddressUse=true;listener.Start(16);added.Add(listener);int destination=port;Task.Run(()=>Accept(listener,client=>Relay(client,domain,destination)));}listeners.AddRange(added);}
        catch{foreach(var listener in added)listener.Stop();throw;}
    }
    public byte[] Answer(byte[] query) {
        if(query.Length<12||query.Length>4096)return null;
        int offset=12;var labels=new List<string>();
        try{
            if((query[2]&0x80)!=0||query[4]!=0||query[5]!=1)return Failure(query,12,1);
            while(true){int length=query[offset++];if(length==0)break;if(length>63||offset+length>query.Length)throw new Exception();labels.Add(Encoding.ASCII.GetString(query,offset,length));offset+=length;}
            if(offset+4>query.Length)throw new Exception();int type=query[offset]*256+query[offset+1],cls=query[offset+2]*256+query[offset+3];offset+=4;
            string name=String.Join(".",labels).ToLowerInvariant();
            if(cls!=1||!ValidName(name)||!Data.Target(name))return Failure(query,offset,5);
            // NOERROR with no records: suppress SVCB/HTTPS aliases, ECH and address hints locally.
            if(type==64){Interlocked.Increment(ref blocked64);return Failure(query,offset,0);}
            if(type==65){Interlocked.Increment(ref blocked65);return Failure(query,offset,0);}
            if(type!=1)return Failure(query,offset,0);
            byte[] address=IPAddress.Parse(GetMapping(name)).GetAddressBytes();byte[] response=new byte[offset+16];Array.Copy(query,response,offset);
            response[2]=(byte)(0x80|0x04|(query[2]&1));response[3]=0x80;response[6]=0;response[7]=1;for(int i=8;i<12;i++)response[i]=0;
            int p=offset;response[p++]=0xc0;response[p++]=0x0c;response[p++]=0;response[p++]=1;response[p++]=0;response[p++]=1;response[p++]=0;response[p++]=0;response[p++]=0;response[p++]=60;response[p++]=0;response[p++]=4;Array.Copy(address,0,response,p,4);Interlocked.Increment(ref answers);return response;
        }catch{return Failure(query,Math.Min(offset,query.Length),2);}
    }
    static byte[] Failure(byte[] query,int length,int code){length=Math.Max(12,Math.Min(length,query.Length));var answer=new byte[length];Array.Copy(query,answer,length);answer[2]=(byte)(0x80|(query[2]&1));answer[3]=(byte)(0x80|code);for(int i=6;i<12;i++)answer[i]=0;return answer;}
    void ReceiveUdp() {
        while(!stopped){try{var endpoint=new IPEndPoint(IPAddress.Any,0);byte[] q=udp.Receive(ref endpoint);if(!IPAddress.IsLoopback(endpoint.Address))continue;byte[] a=Answer(q);if(a!=null)udp.Send(a,a.Length,endpoint);}catch(SocketException){if(stopped)return;}catch(ObjectDisposedException){return;}catch{}}
    }
    async Task Accept(TcpListener listener,Action<TcpClient> handler) {
        while(!stopped){TcpClient client=null;try{client=await listener.AcceptTcpClientAsync().ConfigureAwait(false);if(stopped){client.Close();return;}if(Interlocked.Increment(ref inflight)>128){Interlocked.Decrement(ref inflight);client.Close();continue;}lock(sync)clients.Add(client);Dispatch(client,handler);}catch(SocketException){return;}catch(ObjectDisposedException){return;}catch{if(client!=null)client.Close();}}
    }
    void Dispatch(TcpClient accepted,Action<TcpClient> handler){Task.Run(()=>{try{handler(accepted);}catch{}finally{accepted.Close();lock(sync)clients.Remove(accepted);Interlocked.Decrement(ref inflight);}});}
    static byte[] ReadExact(Stream stream,int length){var buffer=new byte[length];int n=0;while(n<length){int read=stream.Read(buffer,n,length-n);if(read==0)throw new EndOfStreamException();n+=read;}return buffer;}
    void HandleDns(TcpClient client){client.ReceiveTimeout=2500;client.SendTimeout=2500;using(var stream=client.GetStream()){byte[] size=ReadExact(stream,2);int length=size[0]*256+size[1];if(length<12||length>4096)return;byte[] answer=Answer(ReadExact(stream,length));if(answer==null)return;stream.WriteByte((byte)(answer.Length>>8));stream.WriteByte((byte)answer.Length);stream.Write(answer,0,answer.Length);}}
    void HandleGateway(TcpClient client){
        client.ReceiveTimeout=5000;client.SendTimeout=5000;var stream=client.GetStream();var bytes=new List<byte>();
        while(bytes.Count<8192){int value=stream.ReadByte();if(value<0)return;bytes.Add((byte)value);int n=bytes.Count;if(n>=4&&bytes[n-4]==13&&bytes[n-3]==10&&bytes[n-2]==13&&bytes[n-1]==10)break;}
        string text=Encoding.ASCII.GetString(bytes.ToArray());string[] first=text.Split(new[]{"\r\n"},StringSplitOptions.None)[0].Split(' ');string domain=null;int port=0;
        if(text.EndsWith("\r\n\r\n",StringComparison.Ordinal)&&first.Length==3&&first[0]=="CONNECT"&&first[2]=="HTTP/1.1"){
            string[] target=first[1].Split(':');if(target.Length==2&&GuardPolicy.Synthetic(target[0])&&Int32.TryParse(target[1],out port)&&(port==80||port==443))lock(sync)reverse.TryGetValue(target[0],out domain);
        }
        if(domain==null||!Data.Target(domain)){byte[] denied=Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");stream.Write(denied,0,denied.Length);return;}
        Relay(client,domain,port,true);
    }
    void Relay(TcpClient incoming,string domain,int port,bool gateway=false) {
        if(!Data.Target(domain))return;
        using(var outgoing=new TcpClient()) {
            lock(sync){
                if(stopped || (tunMode && DateTime.UtcNow>=forwardUntilUtc))return;
                clients.Add(outgoing);relays.Add(outgoing);
            }
            try{
                var pending=outgoing.BeginConnect("127.0.0.1",proxyPort,null,null);if(!pending.AsyncWaitHandle.WaitOne(2000))return;outgoing.EndConnect(pending);
                outgoing.ReceiveTimeout=5000;outgoing.SendTimeout=5000;var remote=outgoing.GetStream();byte[] connect=Encoding.ASCII.GetBytes("CONNECT "+domain+":"+port+" HTTP/1.1\r\nHost: "+domain+":"+port+"\r\n\r\n");remote.Write(connect,0,connect.Length);
                var header=new List<byte>();while(header.Count<4096){int b=remote.ReadByte();if(b<0)return;header.Add((byte)b);int n=header.Count;if(n>=4&&header[n-4]==13&&header[n-3]==10&&header[n-2]==13&&header[n-1]==10)break;}
                string status=Encoding.ASCII.GetString(header.ToArray()).Split('\n')[0];if(!status.StartsWith("HTTP/1.1 200 ")&&!status.StartsWith("HTTP/1.0 200 "))return;
                outgoing.ReceiveTimeout=0;outgoing.SendTimeout=0;incoming.ReceiveTimeout=0;incoming.SendTimeout=0;var local=incoming.GetStream();if(gateway){byte[] ok=Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n");local.Write(ok,0,ok.Length);}Task a=local.CopyToAsync(remote),btask=remote.CopyToAsync(local);Task.WaitAny(a,btask);
            }finally{lock(sync){clients.Remove(outgoing);relays.Remove(outgoing);}}
        }
    }
    public void Dispose(){stopped=true;if(udp!=null)udp.Close();lock(sync){foreach(var listener in listeners)listener.Stop();foreach(var client in clients)client.Close();listeners.Clear();}}
}
public sealed class GuardService : ServiceBase {
    DomainGuard guard;GuardTun tun;
    public GuardService(){ServiceName="AdvancedAINetworkDomainGuard";CanStop=true;AutoLog=true;}
    protected override void OnStart(string[] args){ThreadPool.SetMinThreads(64,64);string directory=GuardPolicy.DirectoryPath;guard=new DomainGuard(directory,proxy:GuardPolicy.VerifiedPort,selectiveTun:true);guard.Start();tun=new GuardTun(directory,guard);tun.Start();}
    protected override void OnStop(){RequestAdditionalTime(25000);if(tun!=null)tun.Dispose();if(guard!=null)guard.Dispose();}
    public static void Main(){ServiceBase.Run(new GuardService());}
}
}
