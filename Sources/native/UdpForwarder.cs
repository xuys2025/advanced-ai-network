using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

// Full IPv4 5-tuple -> independent SOCKS5 UDP association. No shared reply guessing.
public sealed class UdpForwarder:IDisposable {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate bool PacketCallback(IntPtr packet,uint length,IntPtr address,bool outbound);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl)] static extern bool AdvancedAINetwork_SetUdpCallback(PacketCallback callback);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl)] static extern uint AdvancedAINetwork_QueryUdpOwner(uint address,ushort port);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl)] static extern int AdvancedAINetwork_QueryUdpFlowDecision(uint local,ushort port,uint remote,ushort remotePort,out uint pid);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl)] static extern bool AdvancedAINetwork_InjectUdp(byte[] packet,uint length,byte[] address);
    readonly string image;readonly int proxyPort;readonly PacketCallback callback;
    readonly ConcurrentDictionary<string,Flow> flows=new ConcurrentDictionary<string,Flow>();
    readonly Timer sweep;volatile bool stopped;long upload,download,errors,dropped,unknown,associations,flowResolved;
    public Func<uint,int> SelectOwner;
    public Func<bool> IsReady;
    public UdpForwarder(string image,int proxyPort){this.image=image;this.proxyPort=proxyPort;callback=Capture;if(!AdvancedAINetwork_SetUdpCallback(callback))throw new IOException("UDP capture callback could not be registered.");sweep=new Timer(_=>Sweep(),null,1000,1000);}
    static ushort U16(byte[] b,int n){return (ushort)((b[n]<<8)|b[n+1]);}
    static void Put(byte[] b,int n,int v){b[n]=(byte)(v>>8);b[n+1]=(byte)v;}
    bool Owner(uint pid){try{using(var p=Process.GetProcessById((int)pid))return string.Equals(p.MainModule.FileName,image,StringComparison.OrdinalIgnoreCase);}catch{return false;}}
    bool Capture(IntPtr memory,uint length,IntPtr address,bool outbound){try{
        if(!outbound)return false;
        if(length<28||length>65535)return true;
        var b=new byte[length];Marshal.Copy(memory,b,0,b.Length);int h=(b[0]&15)*4;
        if((b[0]>>4)!=4||h<20||h+8>b.Length||b[9]!=17)return true;
        // Local IPC is outside outbound gateway selection and can have no UDP
        // owner-table row by the time a short-lived sender is inspected.
        if(b[16]==127)return false;
        uint pid=AdvancedAINetwork_QueryUdpOwner(BitConverter.ToUInt32(b,12),U16(b,h));
        int cached=-1;
        if(pid==0){cached=AdvancedAINetwork_QueryUdpFlowDecision(BitConverter.ToUInt32(b,12),U16(b,h),BitConverter.ToUInt32(b,16),U16(b,h+2),out pid);if(cached<0){Interlocked.Increment(ref unknown);return true;}Interlocked.Increment(ref flowResolved);}
        if(pid==(uint)Process.GetCurrentProcess().Id)return false;
        int selected=cached>=0?cached:SelectOwner==null?(Owner(pid)?1:0):SelectOwner(pid);
        if(selected==0)return false;
        if(selected==2||stopped||IsReady!=null&&!IsReady()){Interlocked.Increment(ref dropped);return true;}
        // Local application IPC is not a dedicated-exit destination. Broadcast and
        // multicast cannot be represented by a remote SOCKS exit and are dropped.
        if(b[16]==127)return false;
        if((b[6]&0x3f)!=0||b[7]!=0||b[16]>=224||b[16]==0||b[16]==169&&b[17]==254){Interlocked.Increment(ref dropped);return true;}
        int udpLength=U16(b,h+4);if(udpLength<8||h+udpLength>b.Length){Interlocked.Increment(ref dropped);return true;}
        var local=new IPEndPoint(new IPAddress(new byte[]{b[12],b[13],b[14],b[15]}),U16(b,h));
        var remote=new IPEndPoint(new IPAddress(new byte[]{b[16],b[17],b[18],b[19]}),U16(b,h+2));
        string key=pid+"/"+local+"/"+remote;Flow flow;
        if(!flows.TryGetValue(key,out flow)){lock(flows){if(!flows.TryGetValue(key,out flow)){if(flows.Count>=64){Interlocked.Increment(ref dropped);return true;}var metadata=new byte[80];Marshal.Copy(address,metadata,0,80);flow=new Flow(this,key,local,remote,metadata);if(!flows.TryAdd(key,flow)){flow.Dispose();return true;}flow.Start();}}}
        var data=new byte[udpLength-8];Array.Copy(b,h+8,data,0,data.Length);flow.Send(data);return true;
    }catch{Interlocked.Increment(ref errors);return true;}}
    void Sweep(){try{foreach(var f in flows.Values)if((DateTime.UtcNow-f.LastUsed).TotalSeconds>90)f.Dispose();}catch{}}
    static byte[] Read(Stream s,int length){var b=new byte[length];for(int n=0;n<length;){int r=s.Read(b,n,length-n);if(r==0)throw new IOException("SOCKS control closed.");n+=r;}return b;}
    public object Status(){return new{flows=flows.Count,associations=Interlocked.Read(ref associations),upload=Interlocked.Read(ref upload),download=Interlocked.Read(ref download),errors=Interlocked.Read(ref errors),dropped=Interlocked.Read(ref dropped),unknown_owner_dropped=Interlocked.Read(ref unknown),closed_endpoint_resolved=Interlocked.Read(ref flowResolved)};}
    public void Pause(){foreach(var f in flows.Values)f.Dispose();}
    public void Dispose(){stopped=true;sweep.Dispose();foreach(var f in flows.Values)f.Dispose();GC.KeepAlive(callback);}
    sealed class Flow:IDisposable {
        readonly UdpForwarder owner;readonly string key;readonly IPEndPoint local,remote;readonly byte[] metadata;
        readonly BlockingCollection<byte[]> queue=new BlockingCollection<byte[]>(32);readonly object resources=new object();
        TcpClient control;UdpClient socket;int closed;long touched=DateTime.UtcNow.Ticks;
        public DateTime LastUsed{get{return new DateTime(Interlocked.Read(ref touched),DateTimeKind.Utc);}}
        public Flow(UdpForwarder owner,string key,IPEndPoint local,IPEndPoint remote,byte[] metadata){this.owner=owner;this.key=key;this.local=local;this.remote=remote;this.metadata=metadata;}
        public void Start(){Task.Factory.StartNew(Run,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);}
        public void Send(byte[] data){Interlocked.Exchange(ref touched,DateTime.UtcNow.Ticks);try{if(closed!=0||!queue.TryAdd(data))Interlocked.Increment(ref owner.dropped);}catch{Interlocked.Increment(ref owner.dropped);}}
        void Run(){try{
            var c=new TcpClient();lock(resources){if(closed!=0){c.Close();return;}control=c;}
            c.NoDelay=true;c.ReceiveTimeout=c.SendTimeout=3000;var pending=c.ConnectAsync(IPAddress.Loopback,owner.proxyPort);if(!pending.Wait(3000))throw new IOException("Local UDP gateway unavailable.");pending.GetAwaiter().GetResult();
            var s=c.GetStream();s.Write(new byte[]{5,1,0},0,3);var hello=Read(s,2);if(hello[0]!=5||hello[1]!=0)throw new IOException("UDP gateway authentication rejected.");
            s.Write(new byte[]{5,3,0,1,0,0,0,0,0,0},0,10);var h=Read(s,4);if(h[0]!=5||h[1]!=0||h[2]!=0||h[3]!=1)throw new IOException("UDP gateway association rejected.");
            var bound=Read(s,6);var address=new IPAddress(new byte[]{bound[0],bound[1],bound[2],bound[3]});if(address.Equals(IPAddress.Any))address=IPAddress.Loopback;if(!IPAddress.IsLoopback(address))throw new IOException("UDP gateway must be loopback.");
            var u=new UdpClient(AddressFamily.InterNetwork);lock(resources){if(closed!=0){u.Close();return;}socket=u;}u.Client.ReceiveTimeout=1000;u.Connect(address,U16(bound,4));Interlocked.Increment(ref owner.associations);
            var sender=Task.Factory.StartNew(()=>{try{foreach(var data in queue.GetConsumingEnumerable()){if(closed!=0)return;var request=new byte[data.Length+10];request[3]=1;Array.Copy(remote.Address.GetAddressBytes(),0,request,4,4);Put(request,8,remote.Port);Array.Copy(data,0,request,10,data.Length);u.Send(request,request.Length);Interlocked.Add(ref owner.upload,data.Length);}}catch{if(closed==0)Interlocked.Increment(ref owner.errors);Dispose();}},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
            while(closed==0){try{IPEndPoint peer=null;var b=u.Receive(ref peer);if(b.Length<10||b[0]!=0||b[1]!=0||b[2]!=0||b[3]!=1)continue;var from=new IPAddress(new byte[]{b[4],b[5],b[6],b[7]});if(!from.Equals(remote.Address)||U16(b,8)!=remote.Port)continue;Reply(b,10);}
                catch(SocketException error){if(error.SocketErrorCode!=SocketError.TimedOut)throw;if(c.Client.Poll(0,SelectMode.SelectRead)&&c.Client.Available==0)throw new IOException("UDP control disconnected.");}}
            GC.KeepAlive(sender);
        }catch{if(closed==0)Interlocked.Increment(ref owner.errors);}finally{Dispose();}}
        void Reply(byte[] b,int offset){if(owner.IsReady!=null&&!owner.IsReady())return;int payload=b.Length-offset;if(payload>65507)return;var packet=new byte[28+payload];packet[0]=0x45;Put(packet,2,packet.Length);packet[8]=64;packet[9]=17;Array.Copy(remote.Address.GetAddressBytes(),0,packet,12,4);Array.Copy(local.Address.GetAddressBytes(),0,packet,16,4);Put(packet,20,remote.Port);Put(packet,22,local.Port);Put(packet,24,payload+8);Array.Copy(b,offset,packet,28,payload);var meta=(byte[])metadata.Clone();if(!AdvancedAINetwork_InjectUdp(packet,(uint)packet.Length,meta)){Interlocked.Increment(ref owner.errors);return;}Interlocked.Add(ref owner.download,payload);Interlocked.Exchange(ref touched,DateTime.UtcNow.Ticks);}
        public void Dispose(){if(Interlocked.Exchange(ref closed,1)!=0)return;queue.CompleteAdding();lock(resources){if(control!=null)control.Close();if(socket!=null)socket.Close();}Flow ignored;owner.flows.TryRemove(key,out ignored);}
    }
}
